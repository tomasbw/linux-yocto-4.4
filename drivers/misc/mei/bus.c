/*
 * Intel Management Engine Interface (Intel MEI) Linux driver
 * Copyright (c) 2012, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/mei_bus.h>

#include "mei_dev.h"
#include "hw-me.h"
#include "client.h"
#include "bus.h"

static int mei_device_match(struct device *dev, struct device_driver *drv)
{
	struct mei_bus_client *client = to_mei_client(dev);
	struct mei_bus_driver *driver;

	if (!client)
		return 0;

	driver = to_mei_driver(drv);

	return !uuid_le_cmp(client->uuid, driver->id.uuid) &&
		!strcmp(client->name, driver->id.name);
}

static int mei_device_probe(struct device *dev)
{
	struct mei_bus_client *client = to_mei_client(dev);
	struct mei_bus_driver *driver;
	int status;

	if (!client)
		return 0;

	driver = to_mei_driver(dev->driver);
	if (!driver->probe)
		return -ENODEV;

	client->driver = driver;
	dev_dbg(dev, "probe\n");

	status = driver->probe(client);
	if (status)
		client->driver = NULL;

	return status;
}

static int mei_device_remove(struct device *dev)
{
	struct mei_bus_client *client = to_mei_client(dev);
	struct mei_bus_driver *driver;
	int status;

	if (!client || !dev->driver)
		return 0;

	if (client->event_cb) {
		client->event_cb = NULL;
		cancel_work_sync(&client->event_work);
	}

	driver = to_mei_driver(dev->driver);
	if (!driver->remove) {
		dev->driver = NULL;
		client->driver = NULL;

		return 0;
	}

	status = driver->remove(client);
	if (!status)
		client->driver = NULL;

	return status;
}

static void mei_device_shutdown(struct device *dev)
{
	return;
}

struct bus_type mei_bus_type = {
	.name		= "mei",
	.match		= mei_device_match,
	.probe		= mei_device_probe,
	.remove		= mei_device_remove,
	.shutdown	= mei_device_shutdown,
};
EXPORT_SYMBOL(mei_bus_type);

static void mei_client_dev_release(struct device *dev)
{
	kfree(to_mei_client(dev));
}

static struct device_type mei_client_type = {
	.release	= mei_client_dev_release,
};

static struct mei_cl *mei_bus_find_mei_cl_by_uuid(struct mei_device *mei_dev,
						uuid_le uuid)
{
	struct mei_cl *cl, *next;

	list_for_each_entry_safe(cl, next,
				 &mei_dev->bus_client_list, bus_client_link) {
		if (!uuid_le_cmp(uuid, cl->bus_client_uuid))
			return cl;
	}

	return NULL;
}

struct mei_bus_client *mei_add_device(struct mei_device *mei_dev,
				      uuid_le uuid, char *name)
{
	struct mei_bus_client *client;
	struct mei_cl *cl;
	int status;

	cl = mei_bus_find_mei_cl_by_uuid(mei_dev, uuid);
	if (cl == NULL)
		return NULL;

	client = kzalloc(sizeof(struct mei_bus_client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->cl = cl;

	client->mei_dev = mei_dev;
	client->uuid = uuid;
	strlcpy(client->name, name, sizeof(client->name));

	client->dev.parent = &client->mei_dev->pdev->dev;
	client->dev.bus = &mei_bus_type;
	client->dev.type = &mei_client_type;

	dev_set_name(&client->dev, "%s", client->name);

	status = device_register(&client->dev);
	if (status) {
		kfree(client);
		dev_err(client->dev.parent, "Failed to register MEI client\n");
		return NULL;
	}

	cl->client = client;

	dev_dbg(&client->dev, "client %s registered\n", client->name);

	return client;
}
EXPORT_SYMBOL(mei_add_device);

void mei_remove_device(struct mei_bus_client *client)
{
	device_unregister(&client->dev);
}
EXPORT_SYMBOL(mei_remove_device);

int mei_add_driver(struct mei_bus_driver *driver)
{
	int err;

	/* Can't register until after driver model init */
	if (unlikely(WARN_ON(!mei_bus_type.p)))
		return -EAGAIN;

	driver->driver.owner = THIS_MODULE;
	driver->driver.bus = &mei_bus_type;

	err = driver_register(&driver->driver);
	if (err)
		return err;

	pr_debug("mei: driver [%s] registered\n", driver->driver.name);

	return 0;
}
EXPORT_SYMBOL(mei_add_driver);

void mei_del_driver(struct mei_bus_driver *driver)
{
	driver_unregister(&driver->driver);

	pr_debug("mei: driver [%s] unregistered\n", driver->driver.name);
}
EXPORT_SYMBOL(mei_del_driver);

int mei_send(struct mei_cl *cl, u8 *buf, size_t length)
{
	struct mei_device *dev;
	struct mei_msg_hdr mei_hdr;
	struct mei_cl_cb *cb;
	int me_cl_id, err;

	if (WARN_ON(!cl || !cl->dev))
		return -ENODEV;

	if (cl->state != MEI_FILE_CONNECTED)
		return -ENODEV;

	cb = mei_io_cb_init(cl, NULL);
	if (!cb)
		return -ENOMEM;

	err = mei_io_cb_alloc_req_buf(cb, length);
	if (err < 0) {
		mei_io_cb_free(cb);
		return err;
	}

	memcpy(cb->request_buffer.data, buf, length);
	cb->fop_type = MEI_FOP_WRITE;

	dev = cl->dev;

	mutex_lock(&dev->device_lock);

	/* Check if we have an ME client device */
	me_cl_id = mei_me_cl_by_id(dev, cl->me_client_id);
	if (me_cl_id == dev->me_clients_num) {
		err = -ENODEV;
		goto out_err;
	}

	if (length > dev->me_clients[me_cl_id].props.max_msg_length) {
		err = -EINVAL;
		goto out_err;
	}

	err = mei_cl_flow_ctrl_creds(cl);
	if (err < 0)
		goto out_err;

	/* Host buffer is not ready, we queue the request */
	if (err == 0 || !dev->hbuf_is_ready) {
		cb->buf_idx = 0;
		mei_hdr.msg_complete = 0;
		cl->writing_state = MEI_WRITING;
		list_add_tail(&cb->list, &dev->write_list.list);

		mutex_unlock(&dev->device_lock);

		return length;
	}

	dev->hbuf_is_ready = false;

	/* Check for a maximum length */
	if (length > mei_hbuf_max_len(dev)) {
		mei_hdr.length = mei_hbuf_max_len(dev);
		mei_hdr.msg_complete = 0;
	} else {
		mei_hdr.length = length;
		mei_hdr.msg_complete = 1;
	}

	mei_hdr.host_addr = cl->host_client_id;
	mei_hdr.me_addr = cl->me_client_id;
	mei_hdr.reserved = 0;

	if (mei_write_message(dev, &mei_hdr, buf)) {
		err = -EIO;
		goto out_err;
	}

	cl->writing_state = MEI_WRITING;
	cb->buf_idx = mei_hdr.length;

	if (!mei_hdr.msg_complete) {
		list_add_tail(&cb->list, &dev->write_list.list);
	} else {
		if (mei_cl_flow_ctrl_reduce(cl)) {
			err = -EIO;
			goto out_err;
		}

		list_add_tail(&cb->list, &dev->write_waiting_list.list);
	}

	mutex_unlock(&dev->device_lock);

	return mei_hdr.length;

out_err:
	mutex_unlock(&dev->device_lock);
	mei_io_cb_free(cb);

	return err;
}

int mei_recv(struct mei_cl *cl, u8 *buf, size_t length)
{
	struct mei_device *dev;
	struct mei_cl_cb *cb;
	size_t r_length;
	int err;

	if (WARN_ON(!cl || !cl->dev))
		return -ENODEV;

	dev = cl->dev;

	mutex_lock(&dev->device_lock);

	if (!cl->read_cb) {
		err = mei_cl_read_start(cl);
		if (err < 0) {
			mutex_unlock(&dev->device_lock);
			return err;
		}
	}

	if (cl->reading_state != MEI_READ_COMPLETE &&
	    !waitqueue_active(&cl->rx_wait)) {
		mutex_unlock(&dev->device_lock);

		if (wait_event_interruptible(cl->rx_wait,
				(MEI_READ_COMPLETE == cl->reading_state))) {
			if (signal_pending(current))
				return -EINTR;
			return -ERESTARTSYS;
		}

		mutex_lock(&dev->device_lock);
	}

	cb = cl->read_cb;

	if (cl->reading_state != MEI_READ_COMPLETE) {
		r_length = 0;
		goto out;
	}

	r_length = min_t(size_t, length, cb->buf_idx);

	memcpy(buf, cb->response_buffer.data, r_length);

	mei_io_cb_free(cb);
	cl->reading_state = MEI_IDLE;
	cl->read_cb = NULL;

out:
	mutex_unlock(&dev->device_lock);

	return r_length;
}

int mei_bus_send(struct mei_bus_client *client, u8 *buf, size_t length)
{
	struct mei_cl *cl = client->cl;

	if (cl == NULL)
		return -ENODEV;

	if (client->ops && client->ops->send)
		return client->ops->send(client, buf, length);

	return mei_send(cl, buf, length);
}
EXPORT_SYMBOL(mei_bus_send);

int mei_bus_recv(struct mei_bus_client *client, u8 *buf, size_t length)
{
	struct mei_cl *cl =  client->cl;

	if (cl == NULL)
		return -ENODEV;

	if (client->ops && client->ops->recv)
		return client->ops->recv(client, buf, length);

	return mei_recv(cl, buf, length);
}
EXPORT_SYMBOL(mei_bus_recv);

static void mei_bus_event_work(struct work_struct *work)
{
	struct mei_bus_client *client;

	client = container_of(work, struct mei_bus_client, event_work);

	if (client->event_cb)
		client->event_cb(client, client->events, client->event_context);

	client->events = 0;

	/* Prepare for the next read */
	mei_cl_read_start(client->cl);
}

int mei_bus_register_event_cb(struct mei_bus_client *client,
			      mei_bus_event_cb_t event_cb, void *context)
{
	if (client->event_cb)
		return -EALREADY;

	client->events = 0;
	client->event_cb = event_cb;
	client->event_context = context;
	INIT_WORK(&client->event_work, mei_bus_event_work);

	mei_cl_read_start(client->cl);

	return 0;
}
EXPORT_SYMBOL(mei_bus_register_event_cb);

void mei_bus_rx_event(struct mei_cl *cl)
{
	struct mei_bus_client *client = cl->client;

	if (!client || !client->event_cb)
		return;

	set_bit(MEI_BUS_EVENT_RX, &client->events);

	schedule_work(&client->event_work);
}

int mei_bus_init(struct pci_dev *pdev)
{
	return bus_register(&mei_bus_type);
}

void mei_bus_exit(void)
{
	bus_unregister(&mei_bus_type);
}
