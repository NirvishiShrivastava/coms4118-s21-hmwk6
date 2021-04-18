#include <asm/pgtable.h>
#include "ppagewalk.h"
#include <linux/slab.h>
#include <asm/pgtable_64_types.h>
#include <asm/page.h>
#include <linux/mm.h>

#define pfn_to_virt(pfn)	__va((pfn) << PAGE_SHIFT)
#define PGD_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))

bool traverse(struct list_head *head, unsigned long pfn)
{
	struct page_iter_list *temp;

	list_for_each_entry(temp, head, page_list) {
		if (temp->pfn == pfn)
			return 1;
	}
	return 0;
}

static int expose_page_range(struct mm_struct *target_mm,
			    pmd_t *pmd,
			    unsigned long va_curr,
			    unsigned long va_end, int toggle, long *count,
			    struct list_head *list)
{
	int ret = 0;
	pte_t *pte;
	unsigned long pfn;
	struct page_iter_list *node;
	unsigned long *virt_addr;
	void *zero_buf;

	down_read(&target_mm->mmap_sem);
	pte = pte_offset_map(pmd, va_curr);
	if (pte_none(*pte))
		goto out_sem;
	up_read(&target_mm->mmap_sem);

	pfn = pte_pfn(*pte);
	if (pfn) {
		if (!traverse(list, pfn)) {
			if (toggle == 1) {
				*count += 1;
			} else {
				virt_addr = pfn_to_virt(pfn);
				zero_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
				if(!zero_buf)
					return -ENOMEM;

				if (memcmp(virt_addr, zero_buf, PAGE_SIZE) == 0
					|| pfn_to_page(pfn) == ZERO_PAGE(0))
					*count += 1;

				kfree(zero_buf);
			}
			node = kmalloc(sizeof(struct page_iter_list),
					GFP_KERNEL);
			if (!node) {
				ret = -ENOMEM;
				goto out;
			}
			node->pfn = pfn;
			list_add(&node->page_list, list);
		}
	}
out:
	return ret;
out_sem:
	up_read(&target_mm->mmap_sem);
	goto out;
}

static int expose_pte_range(struct mm_struct *target_mm,
			    pud_t *pud,
			    unsigned long va_curr,
			    unsigned long va_end, int toggle, long *count,
			    struct list_head *list)
{
	int ret = 0;
	pmd_t *pmd;

	va_end = min((va_curr + PMD_SIZE) & PMD_MASK, va_end);

	down_read(&target_mm->mmap_sem);
	pmd = pmd_offset(pud, va_curr);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto out_sem;
	up_read(&target_mm->mmap_sem);

	do {
		ret = expose_page_range(target_mm, pmd, va_curr, va_end,
				toggle, count, list);
		if (ret < 0)
			goto out;
		va_curr = ((va_curr + PAGE_SIZE) & PAGE_MASK);
	} while (va_curr < va_end);

out:
	return ret;
out_sem:
	up_read(&target_mm->mmap_sem);
	goto out;
}

static int expose_pmd_range(struct mm_struct *target_mm,
			    p4d_t *p4d,
			    unsigned long va_curr,
			    unsigned long va_end, int toggle, long *count,
			    struct list_head *list)
{
	int ret = 0;
	pud_t *pud;

	va_end = min((va_curr + PUD_SIZE) & PUD_MASK, va_end);

	down_read(&target_mm->mmap_sem);
	pud = pud_offset(p4d, va_curr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out_sem;
	up_read(&target_mm->mmap_sem);

	do {
		ret = expose_pte_range(target_mm, pud, va_curr, va_end,
				toggle, count, list);
		if (ret < 0)
			goto out;
		va_curr = ((va_curr + PMD_SIZE) & PMD_MASK);
	} while (va_curr < va_end);

out:
	return ret;
out_sem:
	up_read(&target_mm->mmap_sem);
	goto out;
}

static int expose_pud_range(struct mm_struct *target_mm,
			    pgd_t *pgd,
			    unsigned long va_curr,
			    unsigned long va_end, int toggle, long *count,
			    struct list_head *list)
{
	int ret = 0;
	p4d_t *p4d;

	va_end = min((va_curr + PGDIR_SIZE) & PGDIR_MASK, va_end);

	down_read(&target_mm->mmap_sem);
	p4d = p4d_offset(pgd, va_curr);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		goto out_sem;
	up_read(&target_mm->mmap_sem);

	do {
		ret = expose_pmd_range(target_mm, p4d, va_curr, va_end,
				toggle, count, list);
		if (ret < 0)
			goto out;
		va_curr = (va_curr + PUD_SIZE) & PUD_MASK;
	} while (va_curr < va_end);

out:
	return ret;
out_sem:
	up_read(&target_mm->mmap_sem);
	goto out;
}

static int expose_p4d_range(struct mm_struct *target_mm,
		unsigned long va_curr,
		unsigned long va_end, int toggle, long *count,
		struct list_head *list)
{
	int ret = 0;
	pgd_t *pgd;

	va_end = min((va_curr + PGDIR_SIZE) & PGDIR_MASK, va_end);

	down_read(&target_mm->mmap_sem);
	pgd = pgd_offset(target_mm, va_curr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto out_sem;
	up_read(&target_mm->mmap_sem);

	do {
		ret = expose_pud_range(target_mm, pgd, va_curr, va_end, toggle,
				count, list);
		if (ret < 0)
			goto out;
		va_curr = (va_curr + P4D_SIZE) & P4D_MASK;
	} while (va_curr < va_end);

out:
	return ret;
out_sem:
	up_read(&target_mm->mmap_sem);
	goto out;

}

int expose_vm_region(struct mm_struct *target_mm,
				unsigned long begin_vaddr,
				unsigned long end_vaddr, int toggle,
				long *count, struct list_head *list)
{
	unsigned long va_curr = begin_vaddr;
	unsigned long va_end = end_vaddr;
	int ret;

	do {
		ret = expose_p4d_range(target_mm, va_curr, va_end, toggle,
				count, list);

		if (ret < 0)
			goto out;
		va_curr = (va_curr + P4D_SIZE) & PGDIR_MASK;
	} while (va_curr < va_end);

out:
	return ret;
}
