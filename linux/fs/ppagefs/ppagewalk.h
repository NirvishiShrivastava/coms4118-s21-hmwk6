
struct page_iter_list {
	unsigned long pfn;
        struct list_head page_list;
};

extern int expose_vm_region(struct mm_struct *target_mm,
                                unsigned long begin_vaddr,
                                unsigned long end_vaddr, int toggle, 
				long *count, struct page_iter_list *list);

