/*
 * linux/fs/ppagefs/inode.c
 * This is a pseudo file system that exports kernel information
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
#include<linux/sched/mm.h>
#include<linux/fs_context.h>
#include<linux/fs_parser.h>
#include<linux/refcount.h>
#include<linux/fsnotify.h>
#include "ppagewalk.h"
#include<linux/list.h>

#define PPAGEFS_DEFAULT_MODE    0755
#define PPAGEFS_DEFAULT_DIR_MODE 0555
#define PPAGEFS_DEFAULT_FILE_MODE 0444
#define PPAGEFS_FSDATA_IS_REAL_FOPS_BIT BIT(0)

static struct vfsmount *ppagefs_mount;
static int ppagefs_mount_count;

struct ppagefs_fsdata {
	const struct file_operations *real_fops;
	refcount_t active_users;
	struct completion active_users_drained;
};

static struct inode *ppagefs_make_inode(struct super_block *sb, int mode)
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

static long calculate_pages(struct task_struct *task, int toggle)
{
	struct mm_struct *task_mm;
	struct vm_area_struct *vma;
	unsigned long begin, end;
	long count;
	int ret;

	LIST_HEAD(pfn_list);

	count = 0;

	task_mm = get_task_mm(task);

	if (!task_mm)
		return 0;

	for (vma = task_mm->mmap; vma; vma = vma->vm_next) {
		begin = vma->vm_start;
		end = vma->vm_end;
		ret = expose_vm_region(task_mm, begin, end, toggle,
				&count, &pfn_list);
		if (ret < 0)
			return ret;
	}
	return count;
}

static ssize_t ppagefs_read_file(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int ret, i, toggle, len;
	long num_pages = 0, pid;
	struct task_struct *p;
	struct dentry *dentry;
	char parent_dir[30] = "", pid_str[6] = "";
	char filename[6] = "", count_pages[25];

	if (*ppos > 0)
		return 0;
	i = 0;
	dentry = file_dentry(file);
	strcpy(filename, dentry->d_name.name);
	strcpy(parent_dir, dentry->d_parent->d_name.name);

	/* Toggle = 1 for total pages and toggle = 0 for zero pages*/
	if (strcmp(filename, "total") == 0)
		toggle = 1;
	else
		toggle = 0;

	while (parent_dir[i] != '.') {
		pid_str[i] = parent_dir[i];
		i++;
	}

	ret = kstrtol(pid_str, 10, &pid);
	if (ret)
		return -EINVAL;

	read_lock(&tasklist_lock);
	p = find_task_by_vpid(pid);
	read_unlock(&tasklist_lock);

	if (p)
		num_pages = calculate_pages(p, toggle);

	if (num_pages < 0)
		return -1;

	sprintf(count_pages, "%ld\n", num_pages);
	len = strlen(count_pages);

	ret = copy_to_user(buf, count_pages, len);
	if (ret)
		return -EFAULT;
	*ppos += len;

	return len;
}

static ssize_t default_write_file(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	return count;
}


const struct inode_operations ppagefs_file_inode_operations = {
	.setattr	= simple_setattr,
	.getattr	= simple_getattr,
};

const struct file_operations ppagefs_file_operations = {
	.read		= ppagefs_read_file,
	.write		= default_write_file,
	.open		= simple_open,
	.llseek		= noop_llseek,
};

struct dentry *ppagefs_create_file(struct super_block *sb,
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

	inode = ppagefs_make_inode(sb, S_IFREG | PPAGEFS_DEFAULT_FILE_MODE);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_op = &ppagefs_file_inode_operations;
	inode->i_fop = &ppagefs_file_operations;

	d_add(dentry, inode);
	return dentry;

};


static void __ppagefs_file_removed(struct dentry *dentry)
{
	struct ppagefs_fsdata *fsd;

	/*
	 * Paired with the closing smp_mb() implied by a successful
	 * cmpxchg() in debugfs_file_get(): either
	 * debugfs_file_get() must see a dead dentry or we must see a
	 * debugfs_fsdata instance at ->d_fsdata here (or both).
	 */
	smp_mb();

	fsd = READ_ONCE(dentry->d_fsdata);
	if ((unsigned long)fsd & PPAGEFS_FSDATA_IS_REAL_FOPS_BIT)
		return;
	if (!refcount_dec_and_test(&fsd->active_users))
		wait_for_completion(&fsd->active_users_drained);
}

static int __ppagefs_remove(struct dentry *dentry, struct dentry *parent)
{
	int ret = 0;

	if (simple_positive(dentry)) {
		dget(dentry);
		if (d_is_dir(dentry)) {
			ret = simple_rmdir(d_inode(parent), dentry);
			if (!ret)
				fsnotify_rmdir(d_inode(parent), dentry);
		} else {
			simple_unlink(d_inode(parent), dentry);
			fsnotify_unlink(d_inode(parent), dentry);
		}
		if (!ret)
			d_delete(dentry);

		if (d_is_reg(dentry))
			__ppagefs_file_removed(dentry);

		dput(dentry);
	}
	return ret;
}

void ppagefs_remove_recursive(struct dentry *dentry)
{

	struct dentry *child, *parent;

	if (IS_ERR_OR_NULL(dentry))
		return;

	parent = dentry;
 down:
	inode_lock(d_inode(parent));
 loop:
	spin_lock(&parent->d_lock);
	list_for_each_entry(child, &parent->d_subdirs, d_child) {
		if (!simple_positive(child))
			continue;

		if (!list_empty(&child->d_subdirs)) {
			spin_unlock(&parent->d_lock);
			inode_unlock(d_inode(parent));
			parent = child;
			goto down;
		}

		spin_unlock(&parent->d_lock);

		if (!__ppagefs_remove(child, parent))
			simple_release_fs(&ppagefs_mount, &ppagefs_mount_count);

		goto loop;
	}
	spin_unlock(&parent->d_lock);

	inode_unlock(d_inode(parent));
	child = parent;
	parent = parent->d_parent;
	inode_lock(d_inode(parent));

	if (child != dentry)
		/* go up */
		goto loop;

	if (!__ppagefs_remove(child, parent))
		simple_release_fs(&ppagefs_mount, &ppagefs_mount_count);

	inode_unlock(d_inode(parent));
}

struct dentry *ppagefs_simple_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	pr_info("inside %s", __func__);
	pr_info("DENTRY PASSED IS : %s",dentry->d_name.name);
	char total_file_name[] = "total";
        char zero_file_name[] = "zero";
	struct inode *inode;
	if(d_inode(dentry) != NULL){
		pr_info("INODE IS NOT EQUAL to NULL");
		return dentry;
	}

	pr_info("Making new inode");
	inode = ppagefs_make_inode(dentry->d_sb, S_IFDIR | PPAGEFS_DEFAULT_DIR_MODE);

	if (!inode) {
		pr_info("INODE could not be created");
                dput(dentry);
                return NULL;
    	}
	pr_info("Setting inode OPS");
    	inode->i_op = &simple_dir_inode_operations;
    	inode->i_fop = &simple_dir_operations;
	pr_info("Updating DCache");
    	d_add(dentry, inode);

    	if (ppagefs_create_file(dentry->d_sb, dentry, total_file_name) < 0)
            return ERR_PTR(-ENOMEM);

    	if (ppagefs_create_file(dentry->d_sb, dentry, zero_file_name) < 0)
            return ERR_PTR(-ENOMEM);

	pr_info("RETURNING from LOOKUP");
	return NULL;
}

static const struct inode_operations ppagefs_dir_inode_operations = {
	.lookup		= ppagefs_simple_lookup,
};

struct dentry *ppagefs_create_dir(struct super_block *sb,
		struct dentry *dir, const char *name)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;
	char total_file_name[] = "total";
	char zero_file_name[] = "zero";

	qname.name = name;
	qname.len = strlen(name);
	qname.hash = full_name_hash(dir, name, qname.len);

	dentry = d_alloc(dir, &qname);
	if (!dentry)
		return NULL;

	inode = ppagefs_make_inode(sb, S_IFDIR | PPAGEFS_DEFAULT_DIR_MODE);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;

	d_add(dentry, inode);

	if (ppagefs_create_file(sb, dentry, total_file_name) < 0)
		return ERR_PTR(-ENOMEM);

	if (ppagefs_create_file(sb, dentry, zero_file_name) < 0)
		return ERR_PTR(-ENOMEM);

	return dentry;

};

void parse(char *name)
{
	while (*name != '\0') {
		if (*name == '/')
			*name = '-';
		name++;
	}
}

static int ppagefs_create_subdir(struct super_block *sb, struct dentry *dir)
{

	struct task_struct *p;
	long pid;
	char s_pid[6], task_name[16], subdir_name[30] = "";

	read_lock(&tasklist_lock);

	for_each_process(p) {
		strcpy(subdir_name, "");
		pid = (long)task_pid_vnr(p);
		sprintf(s_pid, "%ld", pid);

		get_task_comm(task_name, p);
		parse(task_name);

		strcat(subdir_name, s_pid);
		strcat(subdir_name, ".");
		strcat(subdir_name, task_name);

		ppagefs_create_dir(sb, dir, subdir_name);
	}
	read_unlock(&tasklist_lock);
	return 0;
}

struct ppagefs_mount_opts {
	umode_t mode;
};

struct ppagefs_fs_info {
	struct ppagefs_mount_opts mount_opts;
};

static void ppagefs_free_fc(struct fs_context *fc)
{
	kfree(fc->s_fs_info);
}

enum ppagefs_param {
	Opt_mode,
};

static const struct fs_parameter_spec ppagefs_param_specs[] = {
	fsparam_u32oct("mode",    Opt_mode),
	{}
};

const struct fs_parameter_description ppagefs_fs_parameters = {
	.name =		"ppagefs",
	.specs =	ppagefs_param_specs,
};

static int ppagefs_parse_param(struct fs_context *fc,
		struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct ppagefs_fs_info *fsi = fc->s_fs_info;
	int opt;

	opt = fs_parse(fc, &ppagefs_fs_parameters, param, &result);

	if (opt < 0) {
		if (opt == -ENOPARAM)
			opt = 0;
		return opt;
	}

	switch (opt) {
	case Opt_mode:
		fsi->mount_opts.mode = result.uint_32 & S_IALLUGO;
		break;
	}
	return 0;
}


static int ppagefs_root_dir_open(struct inode *inode, struct file *file)
{
	struct super_block *sb = inode->i_sb;
	struct dentry *dentry, *child;

	dentry = file_dentry(file);

	if (!list_empty(&dentry->d_subdirs)) {
		list_for_each_entry(child, &dentry->d_subdirs, d_child)
			ppagefs_remove_recursive(child);
	}
	if (ppagefs_create_subdir(sb, sb->s_root) < 0)
		return -ENOMEM;

	return dcache_dir_open(inode, file);
}

const struct file_operations ppagefs_root_dir_operations = {
	.open =		ppagefs_root_dir_open,
	.release =	dcache_dir_close,
	.llseek =	dcache_dir_lseek,
	.read =		generic_read_dir,
	.iterate =	dcache_readdir,
	.fsync =	noop_fsync,
};

static int ppagefs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	static const struct tree_descr ppagefs_files[] = { {""} };
	struct inode *inode;
	int err;

	err = simple_fill_super(sb, PPAGEFS_MAGIC, ppagefs_files);
	if (err)
		goto fail;
	inode = d_inode(sb->s_root);
	inode->i_op = &ppagefs_dir_inode_operations;
	inode->i_fop = &ppagefs_root_dir_operations;

fail:
	return err;
}


static int ppagefs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, ppagefs_fill_super);
}

static const struct fs_context_operations ppagefs_context_ops = {
	.free =		ppagefs_free_fc,
	.parse_param =	ppagefs_parse_param,
	.get_tree =	ppagefs_get_tree,
};

int ppagefs_init_fs_context(struct fs_context *fc)
{
	struct ppagefs_fs_info *fsi;

	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);

	if (!fsi)
		return -ENOMEM;

	fsi->mount_opts.mode = PPAGEFS_DEFAULT_MODE;
	fc->s_fs_info = fsi;
	fc->ops = &ppagefs_context_ops;
	return 0;
}

static void ppagefs_kill_sb(struct super_block *sb)
{
	kfree(sb->s_fs_info);
	kill_litter_super(sb);
}

static struct file_system_type ppagefs_type = {
	.owner =		THIS_MODULE,
	.name =			"ppagefs",
	.init_fs_context =	ppagefs_init_fs_context,
	.parameters =		&ppagefs_fs_parameters,
	.kill_sb =		ppagefs_kill_sb,
	.fs_flags =		FS_USERNS_MOUNT,
};

static int __init ppagefs_init(void)
{
	return register_filesystem(&ppagefs_type);
}

/* To initialize PpageFS at kernel boot time */
module_init(ppagefs_init);
