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
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/mei_bus.h>

#include "mei_dev.h"
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

struct mei_bus_client *mei_add_device(struct mei_device *mei_dev,
				      uuid_le uuid, char *name)
{
	struct mei_bus_client *client;
	int status;

	client = kzalloc(sizeof(struct mei_bus_client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->mei_dev = mei_dev;
	client->uuid = uuid;
	strlcpy(client->name, name, sizeof(client->name));

	client->dev.parent = &client->mei_dev->pdev->dev;
	client->dev.bus = &mei_bus_type;
	client->dev.type = &mei_client_type;

	dev_set_name(&client->dev, "%s", client->name);

	status = device_register(&client->dev);
	if (status)
		goto out_err;

	dev_dbg(&client->dev, "client %s registered\n", client->name);

	return client;

out_err:
	dev_err(client->dev.parent, "Failed to register MEI client\n");

	kfree(client);

	return NULL;
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
