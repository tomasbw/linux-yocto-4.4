/*
 *
 * Intel Management Engine Interface (Intel MEI) Linux driver
 * Copyright (c) 2003-2012, Intel Corporation.
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

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/mei.h>
#include <linux/mei_bus.h>

#include "mei_dev.h"
#include "client.h"
#include "bus.h"
#include "nfc.h"

/** mei_nfc_bdev - nfc mei bus device
 *
 * @cl: nfc info host client
 * @cl_info: nfc info host client
 * @init_work: perform connection to the info client
 * @fw_ivn: NFC Intervace Version Number
 * @vendor_id: NFC manufacturer ID
 * @radio_type: NFC radio type
 */
struct mei_bus_dev_nfc {
	struct mei_cl *cl;
	struct mei_cl *cl_info;
	struct work_struct init_work;
	wait_queue_head_t send_wq;
	u8 fw_ivn;
	u8 vendor_id;
	u8 radio_type;

	char *bus_name;

	u16 req_id;
	u16 recv_req_id;
};

struct mei_bus_dev_nfc nfc_bdev;

/* UUIDs for NFC F/W clients */
const uuid_le mei_nfc_guid = UUID_LE(0x0bb17a78, 0x2a8e, 0x4c50,
				     0x94, 0xd4, 0x50, 0x26,
				     0x67, 0x23, 0x77, 0x5c);

const uuid_le mei_nfc_info_guid = UUID_LE(0xd2de1625, 0x382d, 0x417d,
					0x48, 0xa4, 0xef, 0xab,
					0xba, 0x8a, 0x12, 0x06);

static void mei_nfc_free(struct mei_bus_dev_nfc *bdev)
{
	if (bdev->cl) {
		list_del(&bdev->cl->bus_client_link);
		mei_cl_unlink(bdev->cl);
		kfree(bdev->cl);
	}

	if (bdev->cl_info) {
		list_del(&bdev->cl_info->bus_client_link);
		mei_cl_unlink(bdev->cl_info);
		kfree(bdev->cl_info);
	}
}

static int mei_nfc_build_bus_name(struct mei_bus_dev_nfc *bdev)
{
	struct mei_device *dev;

	if (!bdev->cl)
		return -ENODEV;

	dev = bdev->cl->dev;

	switch (bdev->vendor_id) {
	case MEI_NFC_VENDOR_INSIDE:
		switch (bdev->radio_type) {
		case MEI_NFC_VENDOR_INSIDE_UREAD:
			bdev->bus_name = "microread";
			return 0;

		default:
			dev_err(&dev->pdev->dev, "Unknow radio type 0x%x\n",
				bdev->radio_type);

			return -EINVAL;
		}

	default:
		dev_err(&dev->pdev->dev, "Unknow vendor ID 0x%x\n",
			bdev->vendor_id);

		return -EINVAL;
	}

	return 0;
}

static int mei_nfc_connect(struct mei_bus_dev_nfc *bdev)
{
	struct mei_device *dev;
	struct mei_cl *cl;
	struct mei_nfc_cmd *cmd, *reply;
	struct mei_nfc_connect *connect;
	struct mei_nfc_connect_resp *connect_resp;
	size_t connect_length, connect_resp_length;
	int bytes_recv, ret;

	cl = bdev->cl;
	dev = cl->dev;

	connect_length = sizeof(struct mei_nfc_cmd) +
			sizeof(struct mei_nfc_connect);

	connect_resp_length = sizeof(struct mei_nfc_cmd) +
			sizeof(struct mei_nfc_connect_resp);

	cmd = kzalloc(connect_length, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;
	connect = (struct mei_nfc_connect *)cmd->data;

	reply = kzalloc(connect_resp_length, GFP_KERNEL);
	if (!reply) {
		kfree(cmd);
		return -ENOMEM;
	}

	connect_resp = (struct mei_nfc_connect_resp *)reply->data;

	cmd->command = MEI_NFC_CMD_MAINTENANCE;
	cmd->data_size = 3;
	cmd->sub_command = MEI_NFC_SUBCMD_CONNECT;
	connect->fw_ivn = bdev->fw_ivn;
	connect->vendor_id = bdev->vendor_id;

	ret = mei_send(cl, (u8 *)cmd, connect_length);
	if (ret < 0) {
		dev_err(&dev->pdev->dev, "Could not send connect cmd\n");
		goto err;
	}

	bytes_recv = mei_recv(cl, (u8 *)reply, connect_resp_length);
	if (bytes_recv < 0) {
		dev_err(&dev->pdev->dev, "Could not read connect response\n");
		ret = bytes_recv;
		goto err;
	}

	dev_info(&dev->pdev->dev, "IVN 0x%x Vendor ID 0x%x\n",
		connect_resp->fw_ivn, connect_resp->vendor_id);

	dev_info(&dev->pdev->dev, "ME FW %d.%d.%d.%d\n",
		connect_resp->me_major, connect_resp->me_minor,
		connect_resp->me_hotfix, connect_resp->me_build);

	ret = 0;

err:
	kfree(reply);
	kfree(cmd);

	return ret;
}

static int mei_nfc_if_version(struct mei_bus_dev_nfc *bdev)
{
	struct mei_device *dev;
	struct mei_cl *cl;

	struct mei_nfc_cmd cmd;
	struct mei_nfc_reply *reply = NULL;
	struct mei_nfc_if_version *version;
	size_t if_version_length;
	int bytes_recv, ret;

	cl = bdev->cl_info;
	dev = cl->dev;

	memset(&cmd, 0, sizeof(struct mei_nfc_cmd));
	cmd.command = MEI_NFC_CMD_MAINTENANCE;
	cmd.data_size = 1;
	cmd.sub_command = MEI_NFC_SUBCMD_IF_VERSION;

	ret = mei_send(cl, (u8 *)&cmd, sizeof(struct mei_nfc_cmd));
	if (ret < 0) {
		dev_err(&dev->pdev->dev, "Could not send IF version cmd\n");
		return ret;
	}

	/* to be sure on the stack we alloc memory */
	if_version_length = sizeof(struct mei_nfc_reply) +
		sizeof(struct mei_nfc_if_version);

	reply = kzalloc(if_version_length, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	bytes_recv = mei_recv(cl, (u8 *)reply, if_version_length);
	if (bytes_recv < 0 || bytes_recv < sizeof(struct mei_nfc_reply)) {
		dev_err(&dev->pdev->dev, "Could not read IF version\n");
		ret = -EIO;
		goto err;
	}

	version = (struct mei_nfc_if_version *)reply->data;

	bdev->fw_ivn = version->fw_ivn;
	bdev->vendor_id = version->vendor_id;
	bdev->radio_type = version->radio_type;

err:
	kfree(reply);
	return ret;
}

static int mei_nfc_send(struct mei_bus_client *client, u8 *buf, size_t length)
{
	struct mei_device *dev;
	struct mei_bus_dev_nfc *bdev;
	struct mei_nfc_hci_hdr *hdr;
	u8 *mei_buf;
	int err;

	bdev = (struct mei_bus_dev_nfc *) client->priv_data;
	dev = bdev->cl->dev;

	mei_buf = kzalloc(length + MEI_NFC_HEADER_SIZE, GFP_KERNEL);
	if (!mei_buf)
		return -ENOMEM;

	hdr = (struct mei_nfc_hci_hdr *) mei_buf;
	hdr->cmd = MEI_NFC_CMD_HCI_SEND;
	hdr->status = 0;
	hdr->req_id = bdev->req_id;
	hdr->reserved = 0;
	hdr->data_size = length;

	memcpy(mei_buf + MEI_NFC_HEADER_SIZE, buf, length);

	err = mei_send(bdev->cl, mei_buf, length + MEI_NFC_HEADER_SIZE);

	kfree(mei_buf);

	if (!wait_event_interruptible_timeout(bdev->send_wq,
				bdev->recv_req_id == bdev->req_id, HZ)) {
		dev_err(&dev->pdev->dev, "NFC MEI command timeout\n");
		err = -ETIMEDOUT;
	} else {
		bdev->req_id++;
	}

	return err;
}

static int mei_nfc_recv(struct mei_bus_client *client, u8 *buf, size_t length)
{
	struct mei_bus_dev_nfc *bdev;
	struct mei_nfc_hci_hdr *hci_hdr;
	int received_length;

	bdev = (struct mei_bus_dev_nfc *) client->priv_data;

	received_length = mei_recv(bdev->cl, buf, length);
	if (received_length < 0)
		return received_length;

	hci_hdr = (struct mei_nfc_hci_hdr *) buf;

	if (hci_hdr->cmd == MEI_NFC_CMD_HCI_SEND) {
		bdev->recv_req_id = hci_hdr->req_id;
		wake_up(&bdev->send_wq);

		return 0;
	}

	return received_length;
}

static struct mei_bus_ops nfc_ops = {
	.send = mei_nfc_send,
	.recv = mei_nfc_recv,
};

static void mei_nfc_init(struct work_struct *work)
{
	struct mei_device *dev;
	struct mei_bus_client *bus_client;
	struct mei_bus_dev_nfc *bdev;
	struct mei_cl *cl_info, *cl;
	int ret;

	bdev = container_of(work, struct mei_bus_dev_nfc, init_work);

	cl_info = bdev->cl_info;
	cl = bdev->cl;
	dev = cl_info->dev;

	mutex_lock(&dev->device_lock);

	if (mei_cl_connect(cl_info, NULL) < 0) {
		mutex_unlock(&dev->device_lock);
		dev_err(&dev->pdev->dev,
			"Could not connect to the NFC INFO ME client");

		goto err;
	}

	mutex_unlock(&dev->device_lock);

	ret = mei_nfc_if_version(bdev);
	if (ret < 0) {
		dev_err(&dev->pdev->dev, "Could not get the NFC interfave version");

		goto err;
	}

	dev_info(&dev->pdev->dev,
		"NFC MEI VERSION: IVN 0x%x Vendor ID 0x%x Type 0x%x\n",
		bdev->fw_ivn, bdev->vendor_id, bdev->radio_type);

	mutex_lock(&dev->device_lock);

	if (mei_cl_connect(cl, NULL) < 0) {
		mutex_unlock(&dev->device_lock);
		dev_err(&dev->pdev->dev,
			"Could not connect to the NFC ME client");

		goto err;
	}

	mutex_unlock(&dev->device_lock);

	ret = mei_nfc_connect(bdev);
	if (ret < 0) {
		dev_err(&dev->pdev->dev, "Could not connect to NFC");
		return;
	}

	if (mei_nfc_build_bus_name(bdev) < 0) {
		dev_err(&dev->pdev->dev,
			"Could not build the bus ID name\n");
		return;
	}

	bus_client = mei_add_device(dev, mei_nfc_guid,
				    bdev->bus_name);
	if (!bus_client) {
		dev_err(&dev->pdev->dev,
			"Could not add the NFC device to the MEI bus\n");

		goto err;
	}

	bus_client->priv_data = bdev;
	bus_client->ops = &nfc_ops;

	return;

err:
	mei_nfc_free(bdev);

	return;
}


int mei_nfc_host_init(struct mei_device *dev)
{
	struct mei_bus_dev_nfc *bdev = &nfc_bdev;
	struct mei_cl *cl_info, *cl  = NULL;
	int i, ret;

	/* already initialzed */
	if (bdev->cl_info)
		return 0;

	cl_info = mei_cl_allocate(dev);
	cl = mei_cl_allocate(dev);

	if (!cl || !cl_info) {
		ret = -ENOMEM;
		goto err;
	}

	/* check for valid client id */
	i = mei_me_cl_by_uuid(dev, &mei_nfc_info_guid);
	if (i < 0) {
		dev_info(&dev->pdev->dev, "nfc: failed to find the client\n");
		ret = -ENOENT;
		goto err;
	}

	cl_info->me_client_id = dev->me_clients[i].client_id;

	ret = mei_cl_link(cl_info, MEI_HOST_CLIENT_ID_ANY);
	if (ret)
		goto err;

	cl_info->bus_client_uuid = mei_nfc_info_guid;

	list_add_tail(&cl_info->bus_client_link, &dev->bus_client_list);

	/* check for valid client id */
	i = mei_me_cl_by_uuid(dev, &mei_nfc_guid);
	if (i < 0) {
		dev_info(&dev->pdev->dev, "nfc: failed to find the client\n");
		ret = -ENOENT;
		goto err;
	}

	cl->me_client_id = dev->me_clients[i].client_id;

	ret = mei_cl_link(cl, MEI_HOST_CLIENT_ID_ANY);
	if (ret)
		goto err;

	cl->bus_client_uuid = mei_nfc_guid;

	list_add_tail(&cl->bus_client_link, &dev->bus_client_list);

	bdev->cl_info = cl_info;
	bdev->cl = cl;
	bdev->req_id = 1;

	INIT_WORK(&bdev->init_work, mei_nfc_init);
	init_waitqueue_head(&bdev->send_wq);
	schedule_work(&bdev->init_work);

	return 0;

err:
	mei_nfc_free(bdev);

	return ret;
}

void mei_nfc_host_exit(void)
{
	struct mei_bus_dev_nfc *bdev = &nfc_bdev;

	if (bdev->cl && bdev->cl->client)
		mei_remove_device(bdev->cl->client);

	mei_nfc_free(bdev);
}
