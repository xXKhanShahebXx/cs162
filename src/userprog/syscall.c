#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"

// struct lock fd_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  // lock_init(&fd_lock);
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
    // lock_acquire(&fd_lock);
    f->eax = sys_write(args[1], (void*)args[2], args[3]);
    // lock_release(&fd_lock);
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
    // lock_acquire(&fd_lock);
    f->eax = sys_open((void*)args[1]);
    // lock_release(&fd_lock);
  } else if (args[0] == SYS_FILESIZE) {
    // lock_acquire(&fd_lock);
    f->eax = sys_filesize(args[1]);
    // lock_release(&fd_lock);
  } else if (args[0] == SYS_READ) {
    validate_ptr((void*)args[2], f);
    // lock_acquire(&fd_lock);
    f->eax = sys_read(args[1], (void*)args[2], args[3]);
    // lock_release(&fd_lock);
  } else if (args[0] == SYS_SEEK) {
    // lock_acquire(&fd_lock);
    sys_seek(args[1], args[2]);
    // lock_release(&fd_lock);
  } else if (args[0] == SYS_TELL) {
    // lock_acquire(&fd_lock);
    f->eax = sys_tell(args[1]);
    // lock_release(&fd_lock);
  } else if (args[0] == SYS_CLOSE) {
    // lock_acquire(&fd_lock);
    sys_close(args[1]);
    // lock_release(&fd_lock);
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
  } else if (args[0] == SYS_INUMBER) {
    f->eax = sys_inumber((int)args[1]);
  } else if (args[0] == SYS_CHDIR) {
    validate_ptr((void*)args[1], f);
    f->eax = sys_chdir((char*)args[1]);
  } else if (args[0] == SYS_MKDIR) {
    validate_ptr((void*)args[1], f);
    f->eax = sys_mkdir((char*)args[1]);
  } else if (args[0] == SYS_READDIR) {
    validate_ptr((void*)args[2], f);
    f->eax = sys_readdir(args[1], (char*)args[2]);
  } else if (args[0] == SYS_ISDIR) {
    f->eax = sys_isdir(args[1]);
  }
}

int sys_write(int fd, void* buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((const char*)buffer, (size_t)size);
    return size;
  } else if (fd == STDIN_FILENO) {
    return -1;
  } else {
    struct fd* fdesc = find_fd(thread_current()->pcb->fd_table, fd);
    if (!fdesc || fdesc->is_dir)
      return -1;
    if (!writable(fdesc->file)) {
      return 0;
    }
    return file_write(fdesc->file, buffer, size);
  }
}

int sys_practice(int i) { return i + 1; }

bool sys_create(char* path, unsigned initial_size) {
  struct dir* parent;
  char name[NAME_MAX + 1];

  if (!resolve_path(path, &parent, name))
    return false;

  struct inode* parent_inode = dir_get_inode(parent);
  if (parent_inode->removed) {
    dir_close(parent);
    return false;
  }

  block_sector_t sector = 0;
  bool ok = free_map_allocate(1, &sector);
  if (ok) {
    ok = inode_create(sector, (off_t)initial_size, false);
    if (ok)
      ok = dir_add(parent, name, sector);
    if (!ok)
      free_map_release(sector, 1);
  }

  dir_close(parent);
  block_cache_flush_all();
  free_map_sync();
  return ok;
}

bool sys_remove(char* path) {
  struct dir* parent;
  char name[NAME_MAX + 1];
  if (!resolve_path(path, &parent, name))
    return false;

  bool ok = dir_remove(parent, name);
  dir_close(parent);
  return ok;
}

int sys_open(char* path) {
  if (path != NULL && path[0] == '/' && path[1] == '\0') {
    struct dir* root = dir_open_root();
    if (root == NULL)
      return -1;
    struct fd* fdesc = add_fd(thread_current()->pcb->fd_table, NULL, root, path);
    return fdesc ? fdesc->fd_num : -1;
  }

  struct dir* parent;
  char name[NAME_MAX + 1];

  if (!resolve_path(path, &parent, name))
    return -1;

  struct inode* parent_inode = dir_get_inode(parent);
  if (parent_inode->removed) {
    dir_close(parent);
    return -1;
  }

  struct inode* inode = NULL;
  if (!dir_lookup(parent, name, &inode)) {
    dir_close(parent);
    return -1;
  }

  struct fd* fdesc;
  if (inode_is_dir(inode)) {
    struct dir* d = dir_open(inode);
    fdesc = add_fd(thread_current()->pcb->fd_table, NULL, d, path);
  } else {
    struct file* f = file_open(inode);
    fdesc = add_fd(thread_current()->pcb->fd_table, f, NULL, path);
  }

  dir_close(parent);
  return fdesc ? fdesc->fd_num : -1;
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
  struct fd* fdesc = find_fd(thread_current()->pcb->fd_table, fd);
  if (!fdesc || fdesc->is_dir)
    return -1;
  return file_read(fdesc->file, buffer, size);
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
  if (fd < 2)
    return;

  struct fd_table* fdt = thread_current()->pcb->fd_table;
  struct fd* fdesc = find_fd(fdt, fd);
  if (!fdesc)
    return;

  if (fdesc->is_dir)
    dir_close(fdesc->dir);
  else
    file_close(fdesc->file);

  remove_fd(fdt, fd);
}

void sys_halt(void) { shutdown_power_off(); }

pid_t sys_exec(char* cmd_line_) {
  char* cmd_line = palloc_get_page(0);
  if (cmd_line == NULL)
    return -1;

  strlcpy(cmd_line, cmd_line_, PGSIZE);

  char* save_ptr;
  char* prog = strtok_r(cmd_line, " ", &save_ptr);
  if (prog == NULL) {
    palloc_free_page(cmd_line);
    return -1;
  }

  struct dir* parent;
  char name[NAME_MAX + 1];
  if (!resolve_path(prog, &parent, name)) {
    palloc_free_page(cmd_line);
    return -1;
  }

  struct inode* inode = NULL;
  if (!dir_lookup(parent, name, &inode) || inode_is_dir(inode)) {
    inode_close(inode);
    dir_close(parent);
    palloc_free_page(cmd_line);
    return -1;
  }

  inode_close(inode);
  dir_close(parent);

  pid_t pid = process_execute(cmd_line_);

  palloc_free_page(cmd_line);
  return pid;
}

int sys_wait(pid_t pid) { return process_wait(pid); }

pid_t sys_fork(void) { return process_fork(); }

int sys_inumber(int fd) {
  struct fd* fdesc = find_fd(thread_current()->pcb->fd_table, fd);
  if (!fdesc)
    return -1;
  if (fdesc->is_dir) {
    struct inode* inode = dir_get_inode(fdesc->dir);
    return (int)inode_get_inumber(inode);
  } else {
    struct inode* inode = file_get_inode(fdesc->file);
    return (int)inode_get_inumber(inode);
  }
}

bool sys_chdir(const char* path) {
  struct dir* parent;
  char name[NAME_MAX + 1];
  if (!resolve_path(path, &parent, name))
    return false;

  struct inode* inode = NULL;
  if (!dir_lookup(parent, name, &inode)) {
    dir_close(parent);
    return false;
  }
  if (!inode_is_dir(inode)) {
    inode_close(inode);
    dir_close(parent);
    return false;
  }

  dir_close(thread_current()->pcb->cwd);
  thread_current()->pcb->cwd = dir_open(inode);
  dir_close(parent);
  return true;
}

bool sys_mkdir(const char* path) {
  struct dir* parent;
  char name[NAME_MAX + 1];

  if (!resolve_path(path, &parent, name))
    return false;

  block_sector_t sector;
  if (!free_map_allocate(1, &sector)) {
    dir_close(parent);
    return false;
  }

  if (!inode_create(sector, 16 * sizeof(struct dir_entry), true)) {
    free_map_release(sector, 1);
    dir_close(parent);
    return false;
  }

  struct dir* new_dir = dir_open(inode_open(sector));
  if (new_dir == NULL) {
    free_map_release(sector, 1);
    dir_close(parent);
    return false;
  }

  bool ok = dir_add(new_dir, ".", sector);

  block_sector_t parent_sector = inode_get_inumber(dir_get_inode(parent));
  ok = ok && dir_add(new_dir, "..", parent_sector);

  dir_close(new_dir);

  if (!ok) {
    free_map_release(sector, 1);
    dir_close(parent);
    return false;
  }

  ok = dir_add(parent, name, sector);
  if (!ok)
    free_map_release(sector, 1);

  dir_close(parent);
  block_cache_flush_all();
  free_map_sync();
  return ok;
}

bool sys_readdir(int fd, char* name) {
  struct fd* fdesc = find_fd(thread_current()->pcb->fd_table, fd);
  if (!fdesc || !fdesc->is_dir)
    return false;
  while (dir_readdir(fdesc->dir, name)) {
    if (strcmp(name, ".") && strcmp(name, ".."))
      return true;
  }
  return false;
}

bool sys_isdir(int fd) {
  struct fd* fdesc = find_fd(thread_current()->pcb->fd_table, fd);
  return fdesc && fdesc->is_dir;
}
