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

/* TODO: create ppage_create_dir and inode functions */
static int ppage_fill_super(struct super_block *sb, void *data, int silent)
{
	static const struct tree_descr ppage_files[] = {{""}};
	int err;
	char dir_name[] = "ppagefs";
	err = simple_fill_super(sb, PPAGEFS_MAGIC, ppage_files);
	if(err)
		goto fail;
	ppage_create_dir(sb, sb->s_root, dir_name);
fail:
	return err;
}

static struct dentry *ppage_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name, 
			void *data)
{
	return mount_single(fs_type, flags, data, ppage_fill_super);
}

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
