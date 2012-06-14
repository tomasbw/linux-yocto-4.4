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

#ifndef _MEI_BUS_H_
#define _MEI_BUS_H_

#define to_mei_driver(d) container_of(d, struct mei_bus_driver, driver)
#define to_mei_client(d) container_of(d, struct mei_bus_client, dev)

struct mei_bus_client *mei_add_device(struct mei_device *mei_dev,
					uuid_le uuid, char *name);
void mei_remove_device(struct mei_bus_client *client);

#endif /* _MEI_BUS_H_ */
