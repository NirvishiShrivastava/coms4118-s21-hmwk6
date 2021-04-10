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
#include<linux/sched.h>
#include<linux/string.h>
#include<linux/sched/task.h>
#include<linux/sched/signal.h>

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

void parse(char *name)
{
	while(*name != '\0')
	{
		if(*name == '/')
			*name = '-';
		name++;
	}
}

static int ppage_create_subdir(struct super_block *sb, struct dentry *dir)
{
        char task_name[16];
        struct task_struct *p;
        long pid;
        char s_pid[6];
	char subdir_name[30] = "";

        read_lock(&tasklist_lock);

	for_each_process(p) {

		strcpy(subdir_name, "");
		pid = (long)task_pid_vnr(p);
		sprintf(s_pid,"%ld",pid);

		get_task_comm(task_name, p);
		parse(task_name);
		pr_info("Process name is %s\n", task_name);

		strcat(subdir_name, s_pid);
		strcat(subdir_name, ".");
		strcat(subdir_name, task_name);

		ppage_create_dir(sb, dir, subdir_name);
	}
	read_unlock(&tasklist_lock);
        return 0;

}

static int ppage_fill_super(struct super_block *sb, void *data, int silent)
{
	static const struct tree_descr ppage_files[] = {{""}};
	int err;
	struct dentry *root_dentry;
	char root_dir_name[] = "ppagefs";

	err = simple_fill_super(sb, PPAGEFS_MAGIC, ppage_files);
	if(err)
		goto fail;
	root_dentry = ppage_create_dir(sb, sb->s_root, root_dir_name);
	ppage_create_subdir(sb, root_dentry);
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
