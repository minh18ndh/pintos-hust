#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"

struct page;

void lru_list_init(void);
void add_page_to_lru_list(struct page *page);
void del_page_from_lru_list(struct page *page);
struct page* find_page_from_lru_list(void* kaddr);

struct page* alloc_page(enum palloc_flags flags);
void _free_page(struct page *page);
void free_page(void *kaddr);

struct list_elem* get_next_lru_clock();
void try_to_free_pages(void);
void try_free_page(void *kaddr);


#endif /* vm/frame.h */