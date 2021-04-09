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
#include<linux/pagemap.h>

static struct inode *ppage_make_inode(struct super_block *sb,
			       int mode)
{
	struct inode *inode;

	inode = new_inode(sb);

	if (!inode)
		return NULL;

	inode->i_ino = get_next_ino();
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_mode = mode;
	inode->i_blkbits = PAGE_SHIFT;
	inode->i_blocks = 0;

	return inode;
};

struct dentry *ppage_create_dir(struct super_block *sb,
				struct dentry *dir, const char *name)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;

	qname.name = name;
	qname.len = strlen(name);
	qname.hash = full_name_hash(dir, name, qname.len);

	dentry = d_alloc(dir, &qname);
	if (!dentry)
		return NULL;

	inode = ppage_make_inode(sb, S_IFDIR | 0755);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;

	d_add(dentry, inode);
	return dentry;

};

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
