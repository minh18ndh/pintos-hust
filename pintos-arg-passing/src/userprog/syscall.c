//#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"

/* syscall implementations are only used for
  the sake of running examples */

static void syscall_handler (struct intr_frame *);

/* 
Helper Functions
*/
void read_addr(void *dest, char *src, int count);
int read_byte(char *addr);
bool write_addr(char *dest, char byte);
bool check_byte(void *addr);
void check(void *addr, int count);

/* 
Memory access handler
*/
struct lock memory;

/* 
Handler Functions
*/

void exits(int exit_code, struct intr_frame *f);
tid_t execs(char *file, struct intr_frame *f);
int wait(int tid, struct intr_frame *f);
void create(char *name, size_t size, struct intr_frame *f);
void remove(char *name, struct intr_frame *f);
void open(char *name, struct intr_frame *f);
void filesize(int fd, struct intr_frame *f);
int read(int fd, void* buffer, int size, struct intr_frame *f);
int write(int fd, void* buffer, int size, struct intr_frame *f);
void seek(int fd, int count, struct intr_frame *f);
void tell(int fd, struct intr_frame *f);
void close(int fd, struct intr_frame *f);

/*
Main Functions
*/
void syscall_init(void);
static void syscall_handler(struct intr_frame *f);

void
syscall_init (void) 
{
	lock_init(&memory);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	/*
  printf ("system call!\n");
  thread_exit ();
  */
  void *esp = f->esp;
  // Check if esp is valid
  check(esp, 4);
  bool res = check_byte(esp);
  // fetch syscall number
  int call_no;

  read_addr(&call_no, esp, 4);

  //debug
  //printf("syscall number: %d\n", call_no);

  switch (call_no)
  {
  	case SYS_HALT:
  	{
  		shutdown_power_off();
  		break;
  	}

  	case SYS_EXIT:
  	{
  		int exit_code;
  		read_addr(&exit_code, esp+4, 4);
  		exits(exit_code, f);
  		break;
  	}

  	case SYS_EXEC:
  	{
  		char *file;
      read_addr(&file, esp+4, 4);
      check(file, 4);
      tid_t tid = execs(file, f);
      f->eax = tid;
      break;
    }

    case SYS_WAIT:
    {
    	int tid;
      read_addr(&tid, esp+4, sizeof(tid));
      f->eax = wait(tid, f);
      break;
    }

    case SYS_CREATE:
    {
    	check(esp + 4, 4);
      char *name;
      size_t size;
      read_addr(&name, esp+4, 4);
      read_addr(&size, esp+8, 4);
      create(name, size, f);
      break;
    }

    case SYS_REMOVE:
    {
      char *name;
      read_addr(&name, esp+4, 4);
      remove(name, f);
      break;
    }

    case SYS_OPEN:
    {
      char *name;
      read_addr(&name, esp+4, 4);
      open(name, f);
      break;
    }

    case SYS_FILESIZE:
    {
      int fd;
      read_addr(&fd, esp+4, sizeof(fd));
      filesize(fd, f);
      break;
    }

    case SYS_READ:
    {
      int fd;
      void *buffer;
      size_t size;
      read_addr(&fd, esp+4, 4);
      read_addr(&buffer, esp+8, 4);
      read_addr(&size, esp+12, 4);
      int ret = read(fd, buffer, size, f);
      f->eax = ret;
      break;
    }

    case SYS_WRITE:
    {
      int fd;
      unsigned size;
      void *buffer;
      read_addr(&fd, esp+4, 4);
      read_addr(&buffer, esp+8, 4);
      read_addr(&size, esp+12, 4);
      int ret = write(fd, buffer, size, f);
      f->eax = ret;
      break;
    }

    case SYS_SEEK:
    {
      int fd;
      int count;
      read_addr(&fd, esp+4, 4);
      read_addr(&count, esp+8, 4);
      seek(fd, count, f);
      break;
    }

    case SYS_TELL:
    {
      int fd;
      read_addr(&fd, esp+4, 4);
      tell(fd, f);
      break;
    }

    case SYS_CLOSE:
    {
      int fd;
      read_addr(&fd, esp+4, 4);
      close(fd, f);
      break;
    }
  }
}

/* 
Helper Functions
*/
void 
read_addr(void *dest, char *src, int count)
{
	check(src, count);
	for (int i=0; i<count; i++)
		*(char *) (dest + i) = read_byte(src + i) & 0xff;
}

int 
read_byte(char *addr)
{
	int buffer;
	memcpy(&buffer, addr, 1);
	return buffer;
}

bool 
write_addr(char *dest, char byte)
{
	if (check_byte(dest))
	{
		memcpy(dest, &byte, 1);
		return true;
	}
	else
		return false;
}

bool 
check_byte(void *addr)
{
  if((addr != NULL) && (((unsigned int)addr) < ((unsigned int)PHYS_BASE)) && (((unsigned int)addr) > ((unsigned int) 0x8048000)))
  {
    return true;
  }
  else
  	return false;
}

void 
check(void *addr, int count)
{

	unsigned int *down = (unsigned int) pg_round_down(addr);
	unsigned int *up = (unsigned int) pg_round_up(addr);

	unsigned char *c = addr;
  for(int i=0; i < count; i++)
  {
    if(!check_byte((void *)(c + i)))
      exits(-1, NULL);
    if(((unsigned int) addr + count - 1) > up)
    	if (((unsigned int) addr == up) && ((unsigned int) addr == down))
    	{

    	}
    	else
    		exits(-1, NULL);
    	if((pagedir_get_page(thread_current()->pagedir, addr)) == NULL)
    		exits(-1, NULL);
  }
}

/* 
Handler Functions
*/

void 
exits(int exit_code, struct intr_frame *f)
{
	printf("%s: exit(%d)\n", thread_current()->name, exit_code);
	thread_current()->exit_status = exit_code;
	thread_exit();
}

tid_t
execs(char *file, struct intr_frame *f)
{
	tid_t tid = process_execute(file);

	if (tid == -1)
		return tid;
	struct thread *new = get_child_proc(tid);
	sema_down(&new->load_sema);
  
  if (new->is_loaded != 1)
    return TID_ERROR;
	return tid;
}

int 
wait(int tid, struct intr_frame *f)
{
	int result = process_wait(tid);
	return result;
}

void 
create(char *name, size_t size, struct intr_frame *f)
{
  check(name, sizeof(name));
  lock_acquire(&memory);
  f->eax = filesys_create(name, size);
  lock_release(&memory);
}

void 
remove(char *name, struct intr_frame *f)
{
  check(name, sizeof(name));
  lock_acquire(&memory);
  f->eax = filesys_remove(name);
  lock_release(&memory);
}

void 
open(char *name, struct intr_frame *f)
{
  struct file *new;
  check(name, sizeof(name));
  lock_acquire(&memory);
  new = filesys_open(name);

  if (new != NULL)
  {
    if (strcmp(thread_current()->name, name) == 0) 
    {
      file_deny_write(new);
    }
    int new_fd = process_add_file(new);
    f->eax = new_fd;
  }
  else
  {
    f->eax = -1;
  }
  lock_release(&memory);
}

void 
filesize(int fd, struct intr_frame *f)
{
  int size;
  struct file *cur = process_get_file(fd);
  if (cur != NULL)
  {
    size = file_length(cur);
    f->eax = size;
  }
  else
  {
    f->eax = -1;
  }
}

int read(int fd, void* buffer, int size, struct intr_frame *f)
{
  check(buffer, sizeof(buffer));
  lock_acquire(&memory);

  if (fd == 0)
  {
    for (int i = 0; i < size; i++)
    {
      write_addr((char *) (buffer + i), input_getc());
    }
    lock_release(&memory);
    return size;
  }
  else if (fd == 1)
  {
    lock_release(&memory);
    return -1;
  }
  else
  {
    if ((unsigned int) fd > 131)
      exits(-1, NULL);
    struct file *cur = process_get_file(fd);
    int length = 0;

    if (cur == NULL)
    {
      exits(-1, NULL);
    }

    length = file_read(cur, buffer, size);
    lock_release(&memory);
    return length;
  }
}

int
write(int fd, void* buffer, int size, struct intr_frame *f)
{
	check(buffer, sizeof(buffer));
  if ((unsigned int) fd > 131)
    exits(-1, NULL);
  lock_acquire(&memory);
  if (fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&memory);
    return size;
  }
  else if (fd == 0)
  {
    lock_release(&memory);
    return -1;
  }
  else
  {
    struct file *cur_file = process_get_file(fd);
    int length = 0;

    if (cur_file == NULL)
    {
      lock_release(&memory);
      return -1;
    }

    else
    {
      if (thread_current()->files[fd]->deny_write) 
      {
        file_deny_write(thread_current()->files[fd]);
      }
      length = file_write(cur_file, buffer, size);
      lock_release(&memory);
      return length;
    }   
  }
}

void 
seek(int fd, int count, struct intr_frame *f)
{
  struct file *cur = process_get_file(fd);
  if (cur != NULL)
  {
    file_seek(cur, count);
  }
}

void 
tell(int fd, struct intr_frame *f)
{
  struct file *cur = process_get_file(fd);
  unsigned int location = 0;
  if (cur != NULL)
  {
    location = file_tell(cur);
    f->eax = location;
  }
}

void 
close(int fd, struct intr_frame *f)
{
  if ((unsigned int) fd > 131)
    exits(-1, NULL);
  struct file *cur = process_get_file(fd);
  struct thread *cur_thread = thread_current();
  int fd_v = fd; // file descriptor value
  if (cur != NULL)
  {
    file_close(cur);
    cur_thread->files[fd_v] = NULL;
  }
}


