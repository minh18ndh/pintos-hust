#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void argument_stack(char **parse, int count, void **esp);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
struct mmap_file* find_mmap_file(int mapid);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  // mod starts
  char program[64];
  int file_name_length = strlen(file_name)+1;
  char *save_ptr=NULL;
  char *token;
  struct list_elem* e;
  // mod ends

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  strlcpy(program, file_name, file_name_length); // maximum 64 bytes
  token = strtok_r(program, " ", &save_ptr); // tokenize

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (program, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
    return tid;
  }
  // mod starts
  struct thread *child = get_child_proc(tid);
  if (child->exit_status == -1)
    return process_wait(tid);
  // mod ends
  return tid;
}

// Set up the argument stack
void argument_stack(char **argv, int argc, void **esp)
  {
    int arg_addr[argc-1]; // variable to store the address of argv

    if (argv == NULL)
    {
      return;
    }
    // Push argv
    int i, j;
    for (i = argc-1; i > -1; i--)
    {
      for(j = strlen(argv[i]); j > -1; j--)
      {
        *esp -= 1;
        **(char **)esp = argv[i][j];
        // debug
        //printf("%d, %d, %#x, %c\n", i, j, *esp, parse[i][j]);
        //hex_dump(*esp, *esp, PHYS_BASE - *esp, true);
      }
      arg_addr[i] = *esp; // save the current location of esp in arg_addr
    }

    // debug
    //hex_dump(*esp, *esp, PHYS_BASE - *esp, true);

    // Word-align (padding)
    int addr = (- (int) *esp) % 4;
    for (i = 0; i < ((addr + (2*(addr%2))) % 4); i++)
    {
      *esp -= 1;
      *(char *)(*esp) = 0;
    }

    // argv[argc] = NULL
    *esp -= 4;
    *(int *)(*esp) = 0;

    // debug
    //hex_dump(*esp, *esp, PHYS_BASE - *esp, true);

    // Push address of each argv element
    for (i = argc-1; i > -1; i--)
    {
      *esp -= 4;
      *(int *)(*esp) = (int)arg_addr[i]; // save the address stored in arg_addr to the current value of esp
    }

    // Push argv address
    int argv_addr = *esp;
    *esp -= 4;
    *(int *)(*esp) = argv_addr;

    // debug
    //hex_dump(*esp, *esp, PHYS_BASE - *esp, true);

    // Push argc
    *esp -= 4;
    *(int *)(*esp) = argc;

    // Push fake address
    *esp -= 4;
    *(int*)(*esp) = 0;
  }
  
/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  // mod starts
  char *save_ptr=NULL;
  char *token;
  int argc = 0;
  char *argv[128]; // maximum argc
  char program[64];
  int file_name_length = strlen(file_name)+1;

  struct thread *new = thread_current();

  strlcpy (program, file_name, file_name_length);
  
  for (token = strtok_r(program, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
  {
    argv[argc] = token;
    argc ++;
  }
  // mod ends

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (argv[0], &if_.eip, &if_.esp);

  /* If load failed, quit. */
  if (!success)
  {
    // mod starts
    sema_up(&new->load_sema);
    palloc_free_page(file_name);
    new->is_loaded = -1;
    exits(-1, NULL);
  }
  else
  {
    new->is_loaded = 1;
    argument_stack(argv, argc, &if_.esp);
    palloc_free_page(file_name);
    //hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true);
    // mod ends
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();

  free(argv);
}

// mod starts
int process_add_file(struct file *f)
{ 
  struct thread *cur = thread_current();
  int next = cur->fd_next;

  if (cur->files[next] != NULL)
    return -1;

  cur->files[next] = f;
  cur->fd_next ++;
  return next;
}

struct file *process_get_file(int fd)
{
  struct thread *cur = thread_current();
  return cur->files[fd];
}

void process_close_file(int fd)
{
  struct thread *cur = thread_current();
  struct file *close = process_get_file(fd);
  if (close != NULL)
  {
    file_close(close);
    cur->files[fd] = NULL;
  }
}
// mod ends

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  // mod starts
  struct thread *child = get_child_proc(child_tid);
  if (child == NULL)
    return -1;

  sema_down(&child->exit_sema);

  int exit_status = child->exit_status;

  remove_child_proc(child);
  sema_up(&child->rm_sema);
  return exit_status;
  // mod ends
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  munmap(0);

  cur->is_exited = 1;
  // mod
  // close files in mmap_list
  //printf("exit, remaining mmap %d\n", cur->mmap_next);
  for (int i = 1; i < cur->mmap_next; i++)
  {
    struct mmap_file *found = find_mmap_file(i);
    if (!(found == NULL))
      munmap(i);
  }
  vm_destroy(&cur->vm);

/* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
static bool install_page (void *upage, void *kpage, bool writable);

// handle memory management fault when page fault calls
bool handle_mm_fault(struct vm_entry *vme)
{
  // page fault handler
  // get new physical memory page

  // mod: struct page
  struct page *kpage = alloc_page(PAL_USER);

  kpage->vme = vme;

  // if page allocation fails, return false
  if (kpage ==  NULL)
  {
    return false;
  }

  switch(vme->type)
  {
    // case 1: load from binary file
    case VM_BIN:
    {
      // try to load
      bool load_succ = load_file(kpage->kaddr, vme);

      if (!load_succ)
      {
        free_page(kpage->kaddr);
        return false;
      }
      break;
    }

    // case 2: load from mapped file
    case VM_FILE:
    {
      bool load_succ = load_file(kpage->kaddr, vme);

      if (!load_succ)
      {
        free_page(kpage->kaddr);
        return false;
      }
      break;
    }

    // case 3: loaded from swap disk
    case VM_ANON:
    {
      swap_in(vme->swap_slot, kpage->kaddr);
      break;
    }
  }

  // successfully loaded
  bool map_succ = install_page(vme->vaddr, kpage->kaddr, vme->writable);

  if (!map_succ)
  {
    free_page(kpage->kaddr);
    return false;
  }
  // mark vme as loaded
  vme->is_loaded = true;

  return true;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  // mod
  struct file* reopen = file_reopen(file);

  file_seek (reopen, ofs);

  int count = 1;
  // debug
  if (reopen == NULL)
    printf("reopen failed\n");

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      // mod
      // create and initialize vm_entry
      // use insert_vme() function to add vm_entry into hash table

      // create
      struct vm_entry *vme;
      vme = calloc(1, sizeof(struct vm_entry));

      if (vme == NULL)
      {
        printf("vme alloc fail\n");
        return false;
      }

      // initialize
      vme->type = VM_BIN;
      vme->vaddr = upage;
      vme->writable = writable;
      vme->is_loaded = 0;                 // not loaded yet

      vme->file = file;                   // used in lazy loading
      vme->offset = ofs;                  // used in lazy loading
      vme->read_bytes = page_read_bytes;  // used in lazy loading
      vme->zero_bytes = page_zero_bytes;  // used in lazy loading

      vme->swap_slot = 0;                 

      // add into hash table
      struct thread *cur = thread_current();
      bool res = insert_vme(&cur->vm, vme);

      cur->to_load += 1;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;

      // mod
      ofs += page_read_bytes;
      count ++;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
/* mod
   create vm_entry
   initialize vm_entry
   use insert_vme() to add vm_entry into hash table */
static bool
setup_stack (void **esp) 
{
  struct page *kpage;
  bool success = false;

  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success)
      {
        // mod: use struct page
        struct vm_entry *vme;
        vme = calloc(1, sizeof(struct vm_entry));

        if (vme == NULL)
          printf("setup stack vme alloc fail\n");

        // initialize
        vme->type = VM_ANON;              // loaded from swap disk
        vme->vaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
        vme->writable = 1;
        vme->is_loaded = 1;
        vme->pinned = true;

        // add vme to struct page
        kpage->vme = vme;

        // add page and vme
        add_page_to_lru_list(kpage);
        struct thread *cur = thread_current();
        insert_vme(&cur->vm, vme);

        *esp = PHYS_BASE;
      }
      else
        free_page(kpage->kaddr);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

// mod starts
bool grow_stack(void *addr)
{
  struct page *stack = alloc_page(PAL_USER | PAL_ZERO);

  if (stack == NULL)
    return false;

  struct vm_entry* vme = calloc(1, sizeof(struct vm_entry));
  bool install;

  if (vme == NULL)
  {
    free_page(stack->kaddr);
    return false;
  }
   //initialize vme
  vme->vaddr = pg_round_down(addr);
  vme->type = VM_ANON;
  vme->is_loaded = 1;
  vme->writable = 1;

  stack->vme = vme;

  install = install_page(vme->vaddr, stack->kaddr, vme->writable);
  if (!install)
  {
    free_page(stack->kaddr);
    free(vme);
    return false;
  }

  add_page_to_lru_list(stack);
  insert_vme(&thread_current()->vm, vme);
  return true;
}

struct mmap_file* find_mmap_file(int mapid)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  struct mmap_file *iter;
  for (e = list_begin(&cur->mmap_list);
       e != list_end(&cur->mmap_list);
       e = list_next(e))
  {
    iter = list_entry(e, struct mmap_file, elem);
    if (iter->mapid == mapid)
      return iter;
  }
  return NULL;
}
// mod ends























