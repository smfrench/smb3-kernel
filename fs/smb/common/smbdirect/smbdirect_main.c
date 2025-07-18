// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (c) 2025, Stefan Metzmacher
 */

#include "smbdirect_internal.h"
#include <linux/module.h>

static __init int smbdirect_init_module(void)
{
	pr_notice("subsystem loaded\n");
	return 0;
}

static __exit void smbdirect_exit_module(void)
{
	pr_notice("subsystem unloaded\n");
}

module_init(smbdirect_init_module);
module_exit(smbdirect_exit_module);

MODULE_DESCRIPTION("smbdirect subsystem");
MODULE_LICENSE("GPL");
