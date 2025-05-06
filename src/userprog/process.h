#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "threads/interrupt.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  struct fd_table* fd_table;
  struct list children;
  struct shared_data* shared_data;
  struct file* executable;
  bool has_exec;
  struct intr_frame if_save;
  bool is_forked_child;
  struct dir* cwd;
};

struct shared_data {
  int ref_count;
  int exit_code;
  bool waited;
  bool loaded;
  struct semaphore wait;
  pid_t pid;
  struct list_elem elem;
};

struct fd_table {
  struct list fds;
  int next_fd;
};

struct fd {
  int fd_num;
  char* file_name;
  struct file* file;
  struct dir* dir;
  bool is_dir;
  struct list_elem list_fd;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);
pid_t process_fork(void);
static void start_fork_process(void* aux);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

void init_table(struct fd_table* fd_table);
void free_table(struct fd_table* fd_table);
struct fd* find_fd(struct fd_table* fd_table, int fd_num);
struct fd* add_fd(struct fd_table* fd_table, struct file* file, struct dir* dir, const char* name);
int remove_fd(struct fd_table* fd_table, int fd);

void init_shared_data(struct shared_data* shared_data);
struct shared_data* find_shared_data(struct list* children, int pid);

static bool copy_page_directory(uint32_t* src_pd, uint32_t* dst_pd);
static uint32_t* pde_get_pt(uint32_t pde);

#endif /* userprog/process.h */
