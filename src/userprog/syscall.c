#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

struct lock fd_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fd_lock);
}

void validate_ptr(void* ptr, struct intr_frame* f) {
  struct thread* t = thread_current();
  if (ptr == NULL || (uint32_t)ptr == 0 || is_kernel_vaddr(ptr) || is_kernel_vaddr(ptr + 1)) {
    f->eax = -1;
    t->pcb->shared_data->exit_code = -1;
    printf("%s: exit(%d)\n", t->pcb->process_name, -1);
    process_exit();
  }
  uint32_t* page_dir = t->pcb->pagedir;
  void* page = pagedir_get_page(page_dir, ptr);
  if (page == NULL) {
    f->eax = -1;
    t->pcb->shared_data->exit_code = -1;
    printf("%s: exit(%d)\n", t->pcb->process_name, -1);
    process_exit();
  }
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  validate_ptr(f->esp, f);
  validate_ptr((uint32_t*)f->esp + 1, f);
  validate_ptr((uint32_t*)f->esp + 2, f);
  validate_ptr((uint32_t*)f->esp + 3, f);
  validate_ptr((uint32_t*)f->esp + 4, f);

  if (16 + (uint32_t)f->esp > (uint32_t)PHYS_BASE) {
    f->eax = -1;
    thread_current()->pcb->shared_data->exit_code = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();
  }

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    thread_current()->pcb->shared_data->exit_code = args[1];
    process_exit();
  } else if (args[0] == SYS_WRITE) {
    validate_ptr((void*)args[2], f);
    lock_acquire(&fd_lock);
    f->eax = sys_write(args[1], (void*)args[2], args[3]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = sys_practice(args[1]);
    return;
  } else if (args[0] == SYS_CREATE) {
    validate_ptr((void*)args[1], f);
    f->eax = sys_create((void*)args[1], args[2]);
  } else if (args[0] == SYS_REMOVE) {
    validate_ptr((void*)args[1], f);
    f->eax = sys_remove((void*)args[1]);
  } else if (args[0] == SYS_OPEN) {
    validate_ptr((void*)args[1], f);
    lock_acquire(&fd_lock);
    f->eax = sys_open((void*)args[1]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_FILESIZE) {
    lock_acquire(&fd_lock);
    f->eax = sys_filesize(args[1]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_READ) {
    validate_ptr((void*)args[2], f);
    lock_acquire(&fd_lock);
    f->eax = sys_read(args[1], (void*)args[2], args[3]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_SEEK) {
    lock_acquire(&fd_lock);
    sys_seek(args[1], args[2]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_TELL) {
    lock_acquire(&fd_lock);
    f->eax = sys_tell(args[1]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_CLOSE) {
    lock_acquire(&fd_lock);
    sys_close(args[1]);
    lock_release(&fd_lock);
  } else if (args[0] == SYS_HALT) {
    sys_halt();
  } else if (args[0] == SYS_EXEC) {
    validate_ptr((void*)args[1], f);
    validate_ptr((void*)args[1] + 16, f);
    f->eax = sys_exec((char*)args[1]);
  } else if (args[0] == SYS_WAIT) {
    f->eax = sys_wait(args[1]);
  } else if (args[0] == SYS_FORK) {
    thread_current()->pcb->if_save = *f;
    f->eax = sys_fork();
  }
}

int sys_write(int fd, void* buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((const char*)buffer, (size_t)size);
    return size;
  } else if (fd == STDIN_FILENO) {
    return -1;
  } else {
    struct fd_table* fd_table = thread_current()->pcb->fd_table;
    struct fd* file_description = find_fd(fd_table, fd);
    if (file_description == NULL) {
      return -1;
    }
    struct file* file = file_description->file;

    if (!writable(file)) {
      return 0;
    }
    return file_write(file, buffer, (off_t)size);
  }
}

int sys_practice(int i) { return i + 1; }

bool sys_create(char* file, unsigned initial_size) {
  return filesys_create(file, (off_t)initial_size);
}

bool sys_remove(char* file) { return filesys_remove(file); }

int sys_open(char* name) {
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* fd;
  struct file* file = filesys_open(name);
  if (file == NULL) {
    return -1;
  }

  fd = add_fd(fd_table, file, name);

  if (fd == NULL) {
    return -1;
  }
  return fd->fd_num;
}

int sys_filesize(int fd) {
  struct fd* file_descriptor = find_fd(thread_current()->pcb->fd_table, fd);
  if (file_descriptor == NULL) {
    return -1;
  }
  return (int)file_length(file_descriptor->file);
}

int sys_read(int fd, void* buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    uint8_t temp;
    uint8_t* buffer = buffer;
    for (int total = 0; total < (int)size; total += 1) {
      temp = input_getc();
      buffer[total] = temp;
    }
    return size;
  } else if (fd == STDOUT_FILENO || fd < 0) {
    return -1;
  }
  struct fd* file_descriptor = find_fd(thread_current()->pcb->fd_table, fd);
  if (file_descriptor == NULL) {
    return -1;
  }
  return file_read(file_descriptor->file, (char*)buffer, size);
}

void sys_seek(int fd, unsigned position) {
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_descriptor = find_fd(fd_table, fd);
  if (file_descriptor != NULL) {
    file_seek(file_descriptor->file, (off_t)position);
  }
}

void sys_exit(int error_code) {
  printf("%s: exit(%d)", thread_current()->pcb->process_name, error_code);
  process_exit();
}

unsigned sys_tell(int fd) {
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_descriptor = find_fd(fd_table, fd);
  if (file_descriptor == NULL) {
    sys_exit(-1);
  }
  return (unsigned)file_tell(file_descriptor->file);
}

void sys_close(int fd) {
  if (fd < 2) {
    return;
  }
  struct fd_table* fd_table = thread_current()->pcb->fd_table;
  struct fd* file_descriptor = find_fd(fd_table, fd);
  if (file_descriptor == NULL) {
    return;
  }
  file_close(file_descriptor->file);
  int error_code = remove_fd(fd_table, fd);
  if (error_code != 0) {
    return;
  }
}

void sys_halt(void) { shutdown_power_off(); }

pid_t sys_exec(char* cmd_line) { return process_execute(cmd_line); }

int sys_wait(pid_t pid) { return process_wait(pid); }

pid_t sys_fork(void) { return process_fork(); }