#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"
#include <list.h>

struct bitmap;
#define INODE_DIRECT 123

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;
  block_sector_t direct[INODE_DIRECT];
  block_sector_t indirect;
  block_sector_t doubly_indirect;
  unsigned magic;
  uint32_t flags;
};

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
  struct lock resize_lock;
  bool is_dir;
};
void inode_init(void);
bool inode_create(block_sector_t sector, off_t length, bool is_dir);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);

bool inode_resize(struct inode* inode, off_t new_length);
bool inode_is_dir(const struct inode*);

#endif /* filesys/inode.h */
