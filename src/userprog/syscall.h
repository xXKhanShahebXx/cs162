#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "userprog/process.h"

void syscall_init(void);

bool sys_create(char* file, unsigned initial_size);
bool sys_remove(char* file);
int sys_open(char* name);
int sys_filesize(int fd);
int sys_read(int fd, void* buffer, unsigned size);
int sys_write(int fd, void* buffer, unsigned size);
void sys_seek(int fd, unsigned position);
void sys_exit(int error_code);
unsigned sys_tell(int fd);
void sys_close(int fd);
void sys_halt(void);
pid_t sys_exec(char* cmd_line);
int sys_wait(pid_t pid);
pid_t sys_fork(void);

#endif /* userprog/syscall.h */
