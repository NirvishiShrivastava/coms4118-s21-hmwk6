/*
 * linux/fs/ppagefs/inode.c
 * This is a psuedo file system that exports kernel information
 * about the process physical page usage of currently 
 * running process.
 */

#include<linux/fs.h>
#include<linux/module.h>
#include<linux/init.h>
#include<linux/slab.h>
#include<linux/magic.h>

/* TODO: create ppage_mount and ppage_fill_super functions */

static struct file_system_type ppage_fs_type = {
	.owner = 	THIS_MODULE,
	.name = 	"ppagefs",
	.mount = 	ppage_mount,
	.kill_sb = 	kill_litter_super,
};

static int __init ppagefs_init(void)
{
	return register_filesystem(&ppage_fs_type);
}

/* To initialize PpageFS at kernel boot time */
module_init(ppagefs_init);
