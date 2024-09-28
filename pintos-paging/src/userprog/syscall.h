#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/page.h"

struct intr_frame;
void syscall_init (void);
void exits(int exit_code, struct intr_frame *f);
void check(void *addr, int count);
void munmap(int mapid);

#endif /* userprog/syscall.h */
