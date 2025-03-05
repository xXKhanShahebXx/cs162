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
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Page-directory and page-table constants. */
#define PDSHIFT 22 /* Log2(PTSIZE) */
#define PTSHIFT 12 /* Log2(PGSIZE) */
#define PTBITS 10  /* Log2(PTSIZE/PGSIZE) */

/* Page table/directory entry flags. */
#define PTE_P 0x001         /* Present */
#define PTE_W 0x002         /* Writable */
#define PTE_U 0x004         /* User */
#define PTE_ADDR 0xfffff000 /* Physical address (mask) */

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

struct start_data {
  struct semaphore load;
  char* file_name;
  bool has_exec;
  struct list* children;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  size_t offset = 0;
  while (file_name[offset] != ' ' && file_name[offset] != '\0') {
    offset++;
  }
  char* program_name = malloc(sizeof(char) * (offset + 1));
  strlcpy(program_name, file_name, offset + 1);

  struct start_data start_data;
  start_data.file_name = fn_copy;
  sema_init(&(start_data.load), 0);
  start_data.children = &(thread_current()->pcb->children);
  start_data.has_exec = thread_current()->pcb->has_exec;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(program_name, PRI_DEFAULT, start_process, &start_data);

  sema_down(&(start_data.load));

  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  struct shared_data* shared_data = find_shared_data(&(thread_current()->pcb->children), tid);
  if (shared_data == NULL) {
    return -1;
  }

  if (!(shared_data->loaded)) {
    list_pop_front(start_data.children);
    free(shared_data);
    return -1;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* start_data) {
  struct start_data* child_data = (struct start_data*)start_data;
  char* file_name = (char*)child_data->file_name;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;
  bool fd_success;
  bool shared_data_success;

  /* Allocate process control block */
  struct process* new_pcb = calloc(sizeof(struct process), 1);
  struct fd_table* new_fd = calloc(sizeof(struct fd_table), 1);
  struct shared_data* new_shared_data = calloc(sizeof(struct shared_data), 1);

  pcb_success = new_pcb != NULL;
  fd_success = new_fd != NULL;
  shared_data_success = new_shared_data != NULL;

  success = pcb_success && fd_success && shared_data_success;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    init_table(new_fd);
    list_init(&(new_pcb)->children);
    init_shared_data(new_shared_data);

    new_pcb->fd_table = new_fd;
    new_pcb->shared_data = new_shared_data;
    new_pcb->is_forked_child = false;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
    if (!(child_data->has_exec)) {
      list_init(child_data->children);
    }
    list_push_front(child_data->children, &(new_shared_data->elem));
    new_pcb->has_exec = true;
  }

  char* token;
  char* save_ptr;
  int argc = 0;
  char* temp = calloc(strlen(file_name) + 1, 1);
  strlcpy(temp, file_name, strlen(file_name) + 1);

  for (token = strtok_r(temp, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    argc++;
  }

  free(temp);

  char* argv[argc + 1];
  argc = 0;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    argv[argc++] = token;
  }

  argv[argc] = NULL;

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(argv[0], &if_.eip, &if_.esp);
    new_shared_data->loaded = success;
  }

  if (success) {
    char* argv_ptr[argc];
    for (int i = 0; i < argc; i++) {
      if_.esp = if_.esp - (strlen(argv[i]) + 1);
      argv_ptr[i] = (char*)if_.esp;
      memcpy(if_.esp, argv[i], strlen(argv[i]) + 1);
    }
    uint32_t offset = (uint32_t)(if_.esp - ((uint32_t)argc + 3) * 4) % 16;
    if_.esp = if_.esp - offset;
    memset(if_.esp, 0, offset);

    if_.esp = if_.esp - sizeof(char*);
    memset(if_.esp, argv[argc], sizeof(char*));

    for (int i = 0; i < argc; i++) {
      if_.esp = if_.esp - sizeof(char*);
      *(int*)if_.esp = (uint32_t)argv_ptr[argc - i - 1];
    }

    if_.esp = if_.esp - sizeof(char*);
    char* prev = (char*)(if_.esp + (uint32_t)4);
    memcpy(if_.esp, &prev, sizeof(char*));

    if_.esp = if_.esp - sizeof(int);
    memset(if_.esp, argc, sizeof(int));
    *(int*)if_.esp = argc;

    if_.esp = if_.esp - sizeof(void*);
    memset(if_.esp, '\0', sizeof(void*));
  }

  if (!success && fd_success) {
    free_table(t->pcb->fd_table);
  }

  if (!success && shared_data_success) {
    new_shared_data->ref_count--;
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  sema_up(&(child_data->load));

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid UNUSED) {
  struct process* parent = thread_current()->pcb;
  struct shared_data* shared_data = find_shared_data(&(parent->children), child_pid);
  if (shared_data == NULL) {
    return -1;
  }
  if (shared_data->waited) {
    return -1;
  }
  shared_data->waited = true;
  if (shared_data->ref_count == 1) {
    return shared_data->exit_code;
  }
  sema_down(&(shared_data->wait));
  return shared_data->exit_code;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;

  sema_up(&(pcb_to_free->shared_data->wait));
  free_table(pcb_to_free->fd_table);
  if (pcb_to_free->executable != NULL) {
    file_allow_write(pcb_to_free->executable);
    if (!pcb_to_free->is_forked_child) {
      file_close(pcb_to_free->executable);
    }
  }

  if (!list_empty(&(pcb_to_free->children))) {
    struct list_elem* e;
    struct list* children = &(pcb_to_free->children);
    for (e = list_begin(children); e != list_end(children); e = list_next(e)) {
      struct shared_data* shared_data = list_entry(e, struct shared_data, elem);
      if (shared_data != NULL) {
        shared_data->ref_count = shared_data->ref_count - 1;
      }
    }
  }

  if (pcb_to_free->shared_data != NULL) {
    sema_up(&(pcb_to_free->shared_data->wait));
    pcb_to_free->shared_data->ref_count--;
    if (pcb_to_free->shared_data->ref_count == 0) {
      free(pcb_to_free->shared_data);
    }
  }

  cur->pcb = NULL;
  free(pcb_to_free);
  thread_exit();
}

struct fork_data {
  struct thread* parent;
  struct semaphore sema;
  bool success;
};

pid_t process_fork(void) {
  struct thread* current = thread_current();
  char thread_name[16];

  strlcpy(thread_name, current->name, sizeof thread_name);

  struct fork_data fork_data;
  fork_data.parent = current;
  sema_init(&fork_data.sema, 0);
  fork_data.success = false;

  tid_t tid = thread_create(thread_name, PRI_DEFAULT, start_fork_process, &fork_data);

  if (tid == TID_ERROR)
    return -1;

  sema_down(&fork_data.sema);

  if (!fork_data.success)
    return -1;

  return tid;
}

static void start_fork_process(void* aux) {
  struct fork_data* fork_data = (struct fork_data*)aux;
  struct thread* parent = fork_data->parent;
  struct thread* child = thread_current();
  bool success = false;

  child->pcb = calloc(sizeof(struct process), 1);
  if (child->pcb == NULL)
    goto done;

  child->pcb->pagedir = NULL;
  child->pcb->main_thread = child;
  strlcpy(child->pcb->process_name, child->name, sizeof child->name);
  child->pcb->is_forked_child = true;

  child->pcb->fd_table = calloc(sizeof(struct fd_table), 1);
  if (child->pcb->fd_table == NULL)
    goto done;
  init_table(child->pcb->fd_table);

  list_init(&child->pcb->children);
  child->pcb->has_exec = true;

  struct shared_data* shared_data = calloc(sizeof(struct shared_data), 1);
  if (shared_data == NULL)
    goto done;
  init_shared_data(shared_data);
  child->pcb->shared_data = shared_data;

  list_push_front(&parent->pcb->children, &shared_data->elem);

  child->pcb->pagedir = pagedir_create();
  if (child->pcb->pagedir == NULL)
    goto done;

  process_activate();

  if (!copy_page_directory(parent->pcb->pagedir, child->pcb->pagedir))
    goto done;

  struct list_elem* e;
  for (e = list_begin(&parent->pcb->fd_table->fds); e != list_end(&parent->pcb->fd_table->fds);
       e = list_next(e)) {
    struct fd* parent_fd = list_entry(e, struct fd, list_fd);

    struct file* parent_file = parent_fd->file;
    off_t parent_pos = file_tell(parent_file);

    struct file* child_file = file_dup(parent_file);
    if (child_file == NULL) {
      success = false;
      goto done;
    }

    char* name_copy = NULL;
    if (parent_fd->file_name != NULL) {
      name_copy = malloc(strlen(parent_fd->file_name) + 1);
      if (name_copy == NULL) {
        file_close(child_file);
        success = false;
        goto done;
      }
      strlcpy(name_copy, parent_fd->file_name, strlen(parent_fd->file_name) + 1);
    }

    struct fd* child_fd = add_fd(child->pcb->fd_table, child_file, name_copy);
    if (child_fd == NULL) {
      file_close(child_file);
      if (name_copy != NULL)
        free(name_copy);
      success = false;
      goto done;
    }
    child_fd->fd_num = parent_fd->fd_num;
  }

  if (parent->pcb->executable != NULL) {
    child->pcb->executable = file_reopen(parent->pcb->executable);
    if (child->pcb->executable != NULL) {
      file_deny_write(child->pcb->executable);
    } else {
      success = false;
      goto done;
    }
  }

  child->pcb->fd_table->next_fd = parent->pcb->fd_table->next_fd;

  struct intr_frame if_;
  memcpy(&if_, &parent->pcb->if_save, sizeof(struct intr_frame));
  if_.eax = 0;

  success = true;

done:
  fork_data->success = success;
  sema_up(&fork_data->sema);

  if (!success) {
    if (child->pcb != NULL) {
      if (child->pcb->fd_table != NULL) {
        struct list_elem* e;
        for (e = list_begin(&child->pcb->fd_table->fds);
             e != list_end(&child->pcb->fd_table->fds);) {
          struct fd* fd = list_entry(e, struct fd, list_fd);
          e = list_next(e);
          file_close(fd->file);
          free(fd);
        }
        free(child->pcb->fd_table);
      }
      if (child->pcb->pagedir != NULL)
        pagedir_destroy(child->pcb->pagedir);
      if (child->pcb->shared_data != NULL) {
        list_remove(&child->pcb->shared_data->elem);
        free(child->pcb->shared_data);
      }
      if (child->pcb->executable != NULL) {
        file_allow_write(child->pcb->executable);
        file_close(child->pcb->executable);
      }
      free(child->pcb);
    }
    thread_exit();
  }

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

static bool copy_page_directory(uint32_t* src_pd, uint32_t* dst_pd) {
  int i, j;

  for (i = 0; i < 1024; i++) {
    uint32_t pde = src_pd[i];
    if ((pde & PTE_P) == 0)
      continue;

    uint32_t* pt = pde_get_pt(pde);

    for (j = 0; j < 1024; j++) {
      uint32_t pte = pt[j];
      if ((pte & PTE_P) == 0)
        continue;

      void* upage = (void*)((i << 22) | (j << 12));

      if (!is_user_vaddr(upage))
        continue;

      void* kpage = pagedir_get_page(src_pd, upage);
      if (kpage == NULL)
        continue;

      void* new_kpage = palloc_get_page(PAL_USER);
      if (new_kpage == NULL)
        return false;

      memcpy(new_kpage, kpage, PGSIZE);

      bool writable = (pte & PTE_W) != 0;

      if (!pagedir_set_page(dst_pd, upage, new_kpage, writable)) {
        palloc_free_page(new_kpage);
        return false;
      }

      if (pagedir_is_dirty(src_pd, upage))
        pagedir_set_dirty(dst_pd, upage, true);
      if (pagedir_is_accessed(src_pd, upage))
        pagedir_set_accessed(dst_pd, upage, true);
    }
  }

  return true;
}

static uint32_t* pde_get_pt(uint32_t pde) { return ptov(pde & PTE_ADDR); }

void init_table(struct fd_table* fd_table) {
  struct list* fds = &(fd_table->fds);
  list_init(fds);
  fd_table->fds = *fds;
  fd_table->next_fd = 2;
}

void free_table(struct fd_table* fd_table) {
  struct list_elem* e;
  while (!list_empty(&(fd_table->fds))) {
    e = list_pop_front(&(fd_table->fds));
    struct fd* file_descriptor = list_entry(e, struct fd, list_fd);
    if (!thread_current()->pcb->is_forked_child) {
      file_close(file_descriptor->file);
    }

    free(file_descriptor);
  }
  free(fd_table);
}

struct fd* find_fd(struct fd_table* fd_table, int fd_num) {
  struct list_elem* e;
  for (e = list_begin(&(fd_table->fds)); e != list_end(&(fd_table->fds)); e = list_next(e)) {
    struct fd* file_descriptor = list_entry(e, struct fd, list_fd);
    if (file_descriptor != NULL && file_descriptor->fd_num == fd_num) {
      return file_descriptor;
    }
  }
  return NULL;
}

struct fd* add_fd(struct fd_table* fd_table, struct file* file, char* file_name) {
  if (file == NULL || fd_table == NULL) {
    return NULL;
  }
  struct fd* file_descriptor = calloc(sizeof(struct fd), 1);
  struct list_elem* e = &(file_descriptor->list_fd);
  file_descriptor->fd_num = fd_table->next_fd;
  file_descriptor->file = file;
  file_descriptor->file_name = file_name;
  fd_table->next_fd++;
  list_push_back(&(fd_table->fds), e);
  return file_descriptor;
}

int remove_fd(struct fd_table* fd_table, int fd) {
  struct fd* file_descriptor = find_fd(fd_table, fd);
  if (file_descriptor == NULL) {
    return -1;
  }
  struct list_elem* e = &(file_descriptor->list_fd);
  list_remove(e);
  free(file_descriptor);
  return 0;
}

void init_shared_data(struct shared_data* shared_data) {
  shared_data->ref_count = 2;
  shared_data->exit_code = 0;
  shared_data->waited = false;
  shared_data->loaded = false;
  sema_init(&(shared_data->wait), 0);
  shared_data->pid = thread_current()->tid;
}

struct shared_data* find_shared_data(struct list* children, int pid) {
  struct list_elem* e;
  for (e = list_begin(children); e != list_end(children); e = list_next(e)) {
    struct shared_data* shared_data = list_entry(e, struct shared_data, elem);
    if (shared_data->pid == pid) {
      return shared_data;
    }
  }
  return NULL;
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  file_deny_write(file);
  t->pcb->executable = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
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
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  // file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
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
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
