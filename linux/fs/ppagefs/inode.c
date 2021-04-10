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
#include <linux/sched/mm.h>

static int check_pte_for_addr(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		goto out;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;
	pmd = pmd_offset(pud, addr);
	if (!(pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))) {
		pte = pte_offset_map(pmd, addr);
		if (!pte_none(*pte))
			return 1;
	}
out:
	return 0;
}

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

static long calculate_total(struct task_struct *task)
{
	struct mm_struct *task_mm;
	struct vm_area_struct *vma;
	unsigned long begin, end, curr;
	long total;

	task_mm = get_task_mm(task);
	if (!task_mm) {
		pr_info("Couldn't get mm for this process");
		//return -EINVAL;
		return 0;
	}

	total = 0;
	for (vma = task_mm->mmap; vma; vma = vma->vm_next) {
	    begin = vma->vm_start;
	    end = vma->vm_end;
	    for (curr = begin; curr < end; curr += PAGE_SIZE)
		    total += check_pte_for_addr(task_mm, curr);
	}
	return total;
}

static int ppage_create_subdir(struct super_block *sb, struct dentry *dir)
{
        char task_name[16];
        struct task_struct *p;
        long pid;
        long total_pages, zero_pages;
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

		/* Get total physical pages of process p */
		total_pages = calculate_total(p);
		pr_info("# of Total Pages: %ld", total_pages);
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
