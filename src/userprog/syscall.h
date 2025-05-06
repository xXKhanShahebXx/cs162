#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "userprog/process.h"

void syscall_init(void);

bool sys_create(char* path, unsigned initial_size);
bool sys_remove(char* path);
int sys_open(char* path);
int sys_filesize(int fd);
int sys_read(int fd, void* buffer, unsigned size);
int sys_write(int fd, void* buffer, unsigned size);
void sys_seek(int fd, unsigned position);
void sys_exit(int error_code);
unsigned sys_tell(int fd);
void sys_close(int fd);
void sys_halt(void);
pid_t sys_exec(char* cmd_line_);
int sys_wait(pid_t pid);
pid_t sys_fork(void);

int sys_inumber(int fd);
bool sys_chdir(const char* path);
bool sys_mkdir(const char* path);
bool sys_readdir(int fd, char* name);
bool sys_isdir(int fd);

#endif /* userprog/syscall.h */
