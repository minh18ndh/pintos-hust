#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/exception.h"

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
void check_valid_string (const void *str);
void check_valid_buffer (void *buffer, unsigned size, bool to_write);
void check_vm (void *addr, unsigned size, bool to_write, void *esp);

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
int mmap(int fd, void *addr);
void munmap(int mapid);

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

  // mod: prj 3
  check_vm(esp, 4, false, esp);

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
      // modified 3-1.1
      check_vm(file, 4, false, esp);
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
      check(name, sizeof(name));
      check_vm(name, sizeof(name), false, esp);

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

      check(buffer, sizeof(buffer));
      check_vm(buffer, sizeof(buffer), true, esp);

      int ret = read(fd, buffer, size, f);
      f->eax = ret;
      break;
    }

    case SYS_WRITE:
    {
      //debug
      //printf("write called\n");
      int fd;
      unsigned size;
      void *buffer;
      read_addr(&fd, esp+4, 4);
      read_addr(&buffer, esp+8, 4);
      read_addr(&size, esp+12, 4);

      check(buffer, sizeof(buffer));
      check_vm(buffer, sizeof(buffer), false, esp);

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
    case SYS_MMAP:
    {
      int fd;
      void *addr;
      read_addr(&fd, esp+4, 4);
      read_addr(&addr, esp+8, 4);
      int res = mmap(fd, addr);
      f->eax = res;
      break;
    }
    case SYS_MUNMAP:
    {
      int mapid;
      read_addr(&mapid, esp+4, 4);
      munmap(mapid);
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
    {
      exits(-1, NULL);
    }
    if(((unsigned int) addr + count - 1) > up)
    	if (((unsigned int) addr == up) && ((unsigned int) addr == down))
    	{

      }
    	else
      {
    		exits(-1, NULL);
      }
  }
}

// mod prj 3
// check if addr has corresponding vm_entry
void 
check_vm (void *addr, unsigned size, bool to_write, void *esp)
{
  bool write_res = true;

  bool vm_res = true;

  for(int i=0; i < size; i++)
  {
    // get vme
    struct vm_entry *vme = find_vme(addr + i);

    // does exist
    if (vme == NULL)
    {
      if (verify_stack(addr, esp))
      {
        if (!grow_stack(addr))
          vm_res = false;
      }
      else
        vm_res = false;
    }

    else if (to_write && !vme->writable)
    {
      //printf("not writable\n");
      write_res = false;
    }
  }

  if (!write_res || !vm_res)
    exits(-1, NULL);
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
  if(cur != NULL)
  {
    size = file_length(cur);
    f->eax = size;
  }
  else
  {
    f->eax = -1;
  }
}

int 
read(int fd, void* buffer, int size, struct intr_frame *f)
{

  lock_acquire(&memory);

  if(fd == 0)
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
  if ((unsigned int) fd > 131)
    exits(-1, NULL);

  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  else if (fd == 0)
  {
    return -1;
  }
  else
  {
    lock_acquire(&memory);
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
  if(cur != NULL)
  {
    file_close(cur);
    cur_thread->files[fd_v] = NULL;
  }
}

// mod prj 3
int 
mmap(int fd, void *addr)
{
  struct thread *cur = thread_current();
  struct mmap_file *mmap_file;
  struct vm_entry *vme;
  struct file *file;
  void* current_addr = addr;
  int file_len;
  int32_t ofs = 0;

if ((unsigned int) addr % (unsigned int)PGSIZE != 0)
  return -1;

if (addr == NULL)
  return -1;


  mmap_file = calloc(1, sizeof(struct mmap_file));

  if (mmap_file == NULL)
  {
    printf("mmap file alloc failed\n");
    exits(-1, NULL);
  }

  // init mmap file
  mmap_file->mapid = cur->mmap_next;
  cur->mmap_next += 1;
  list_init(&mmap_file->vme_list);
  file = process_get_file(fd);
  mmap_file->file = file_reopen(file);
  if (mmap_file->file == NULL)
  {
    printf("cannot find mmap file\n");
    exits(-1, NULL);
  }

  // add mmap file into thread
  list_push_back(&cur->mmap_list, &mmap_file->elem);

  // iterate to add vm entry
  file_len = file_length(mmap_file->file);

  while (file_len > 0)
  {
    // remaining bytes to read
    size_t page_read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    vme = calloc(1, sizeof(struct vm_entry));

    // initialize new vm entry
    vme->type = VM_FILE;
    vme->vaddr = current_addr;
    vme->writable = 1;
    vme->is_loaded = 0;

    vme->file = mmap_file->file;
    vme->offset = ofs;
    vme->read_bytes = page_read_bytes;
    vme->zero_bytes = page_zero_bytes;

    // insert vm entry to mmap_file and vm
    list_push_back(&mmap_file->vme_list, &vme->mmap_elem);
    if (insert_vme(&cur->vm, vme) == NULL)
    {
      //printf("vme insert failed\n");
      return -1;
    }

    // proceed
    current_addr += PGSIZE;    // ?
    file_len -= page_read_bytes;
    ofs += page_read_bytes;
  }
   //printf("mmap: list size %d\n", list_size(&cur->mmap_list));
  return cur->mmap_next - 1;
}

void 
munmap(int mapid)
{
  struct mmap_file *mmap_file;
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct list_elem *prev;

  if (list_size(&cur->mmap_list) == 0)
    return;

  //printf("munmap: list size %d\n", list_size(&cur->mmap_list));

  if (cur->mmap_next <= mapid)
  {
    printf("invalid mapid %d, nent mapid is %d\n", mapid, cur->mmap_next);
    exits(-1, NULL);
  }

  for (e = list_begin(&cur->mmap_list);
       e != list_end(&cur->mmap_list);
       e = list_next(e))
  {
    mmap_file = list_entry(e, struct mmap_file, elem);

    if (mmap_file->mapid == mapid || mapid == 0)
    {
      // found wanted mmap file, call do_munmap
      do_munmap(mmap_file);

      // clean up
      file_close(mmap_file->file);

      // prepare to advance
      prev = list_prev(e);
      list_remove(e);
      e = prev;

      free(mmap_file);

      if (mapid != 0)
        return;
    }
  }
  if (mapid != 0)
  {
  printf("mmap file not found\n");
  exits(-1, NULL);
  }
}

void 
do_munmap(struct mmap_file *mmap_file)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct list_elem *prev;
  struct vm_entry *vme;
  void* pd;

  for (e = list_begin(&mmap_file->vme_list);
       e != list_end(&mmap_file->vme_list);
       e = list_next(e))
  {
    vme = list_entry(e, struct vm_entry, mmap_elem);
    pd = pagedir_get_page(cur->pagedir, vme->vaddr);
    // if vme is loaded to physical memory
    if (vme->is_loaded == true)
    {
      // if page is dirty, then must write back
      if (pagedir_is_dirty(cur->pagedir, vme->vaddr))
        file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
    }
    // clear page table 
    pagedir_clear_page(cur->pagedir, vme->vaddr);
    // free page
    try_free_page(pd);
    vme->is_loaded = false;

    // prepare to advnace
    prev = list_prev(e);
    list_remove(e);
    e = prev;

    // remove from thread
    list_remove(&mmap_file->elem);
    delete_vme(&cur->vm, vme);
  }
}

















































