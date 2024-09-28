#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "vm/frame.h"
#include "vm/page.h"
#include <bitmap.h>

struct lock swap_lock;
struct bitmap *swap_bitmap;

#define NUM_SEC 8

void swap_init(size_t size)
{
	lock_init(&swap_lock);
	swap_bitmap = bitmap_create(size);

	// initialize bitmap to 0 (vacant)
	bitmap_set_all(swap_bitmap, 0);
}

// read data from swap slot into kaddr
void swap_in(size_t used_index, void* kaddr)
{
	lock_acquire(&swap_lock);

	// get swap block
	struct block *swap_block = block_get_role(BLOCK_SWAP);

	// read from swap disk
	for (int i = 0; i < NUM_SEC; i++)
		block_read(swap_block, used_index * NUM_SEC + i, kaddr + i * BLOCK_SECTOR_SIZE);

	// change bitmap into 1 (using)
	bitmap_flip(swap_bitmap, used_index);
	lock_release(&swap_lock);
}

// record the page pointed by kaddr into swap partition
// return swap slot number
size_t swap_out(void *kaddr)
{
	lock_acquire(&swap_lock);

	// get swap block
	struct block *swap_block = block_get_role(BLOCK_SWAP);

	// find free index
	size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);

	for (int i = 0; i < NUM_SEC; i++)
		block_write(swap_block, NUM_SEC * index + i, kaddr + i * BLOCK_SECTOR_SIZE);

	lock_release(&swap_lock);
	return index;
}