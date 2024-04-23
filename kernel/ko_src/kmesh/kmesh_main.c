/*
 * Copyright 2023 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 * Author: liuxin
 * Create: 2022-08-24
 */

#define pr_fmt(fmt) "Kmesh_main: " fmt

#include <linux/types.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>

#include "defer_connect.h"
#include "kmesh_parse_protocol_data.h"
#include "kmesh_parse_http_1_1.h"

static int __init kmesh_init(void)
{
    int ret;

    ret = defer_conn_init();
    if (ret)
        return ret;

    ret = proto_common_init();
    if (ret)
        return ret;

    ret = kmesh_register_http_1_1_init();
    return ret;
}

static void __exit kmesh_exit(void)
{
    defer_conn_exit();
    proto_common_exit();
}

module_init(kmesh_init);
module_exit(kmesh_exit);

MODULE_LICENSE("GPL");
