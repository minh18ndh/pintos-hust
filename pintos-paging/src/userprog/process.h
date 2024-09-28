#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
bool handle_mm_fault(struct vm_entry *vme);

bool grow_stack(void *addr);

#endif /* userprog/process.h */
