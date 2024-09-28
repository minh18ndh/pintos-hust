#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <list.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "filesys/file.h"
#include "threads/synch.h"

#define VM_BIN 0                // loaded from binary file
#define VM_FILE 1               // loaded from mapped file
#define VM_ANON 2               // loaded from swap disk

struct vm_entry
{
	uint8_t type;				// VM_BIN, VM_FILE, VM_ANON
	void *vaddr;				// virtual address of an user page
	bool writable;			// is writable to address
	bool is_loaded;			// is loaded on physical memory

	// Used for lazy loading
	struct file *file;
	size_t offset;				// start address of file to read
	size_t read_bytes;		// bytes to read
	size_t zero_bytes;		// bytes to fill 0

	// Used for memory mapped file
	struct list_elem mmap_elem;

	// Used for swapping
	size_t swap_slot;
	bool pinned;

	// Used for hashing
	struct hash_elem elem;		// Hash table element
};

struct mmap_file
{
  int mapid;
  struct file *file;
  struct list_elem elem;
  struct list vme_list;
};

struct page
{
	void *kaddr;
	struct vm_entry *vme;
	struct thread *thread;
	struct list_elem lru;
};

void vm_init (struct hash *vm);
bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);
struct vm_entry *find_vme(void *vaddr);
void vm_destroy (struct hash *vm);

bool load_file (void* kaddr, struct vm_entry *vme);

#endif /* vm/page.h */