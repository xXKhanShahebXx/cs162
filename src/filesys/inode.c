#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define PTRS_PER_BLOCK (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))

#define INODE_FLAG_DIR 0x1

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

static block_sector_t inode_get_sector(const struct inode_disk* disk, size_t blk) {
  block_sector_t ptrs[PTRS_PER_BLOCK];

  if (blk < INODE_DIRECT)
    return disk->direct[blk];

  blk -= INODE_DIRECT;
  if (blk < PTRS_PER_BLOCK) {
    if (disk->indirect == 0)
      return 0;
    block_read(fs_device, disk->indirect, ptrs);
    return ptrs[blk];
  }

  blk -= PTRS_PER_BLOCK;
  if (disk->doubly_indirect == 0)
    return 0;
  block_read(fs_device, disk->doubly_indirect, ptrs);
  size_t idx1 = blk / PTRS_PER_BLOCK;
  size_t idx2 = blk % PTRS_PER_BLOCK;
  if (ptrs[idx1] == 0)
    return 0;
  block_read(fs_device, ptrs[idx1], ptrs);
  return ptrs[idx2];
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < 0 || pos >= inode->data.length)
    return -1;
  return inode_get_sector(&inode->data, pos / BLOCK_SECTOR_SIZE);
}

static bool inode_set_sector(struct inode_disk* disk, size_t blk, block_sector_t new_sector) {
  block_sector_t ptrs[PTRS_PER_BLOCK];
  size_t i;

  if (blk < INODE_DIRECT) {
    disk->direct[blk] = new_sector;
    return true;
  }
  blk -= INODE_DIRECT;

  if (blk < PTRS_PER_BLOCK) {
    if (disk->indirect == 0) {
      if (!free_map_allocate(1, &disk->indirect))
        return false;

      memset(ptrs, 0, BLOCK_SECTOR_SIZE);
      block_write(fs_device, disk->indirect, ptrs);
    }
    block_read(fs_device, disk->indirect, ptrs);
    ptrs[blk] = new_sector;
    block_write(fs_device, disk->indirect, ptrs);
    return true;
  }

  blk -= PTRS_PER_BLOCK;
  size_t idx1 = blk / PTRS_PER_BLOCK;
  size_t idx2 = blk % PTRS_PER_BLOCK;

  if (disk->doubly_indirect == 0) {
    if (!free_map_allocate(1, &disk->doubly_indirect))
      return false;
    memset(ptrs, 0, BLOCK_SECTOR_SIZE);
    block_write(fs_device, disk->doubly_indirect, ptrs);
  }

  block_read(fs_device, disk->doubly_indirect, ptrs);

  if (ptrs[idx1] == 0) {
    block_sector_t new_indirect;
    if (!free_map_allocate(1, &new_indirect))
      return false;

    ptrs[idx1] = new_indirect;
    block_write(fs_device, disk->doubly_indirect, ptrs);

    block_sector_t indirect_ptrs[PTRS_PER_BLOCK];
    memset(indirect_ptrs, 0, BLOCK_SECTOR_SIZE);
    indirect_ptrs[idx2] = new_sector;
    block_write(fs_device, new_indirect, indirect_ptrs);
  } else {
    block_sector_t indirect_ptrs[PTRS_PER_BLOCK];
    block_read(fs_device, ptrs[idx1], indirect_ptrs);
    indirect_ptrs[idx2] = new_sector;
    block_write(fs_device, ptrs[idx1], indirect_ptrs);
  }

  return true;
}

bool inode_resize(struct inode* inode, off_t new_length) {
  size_t old_sectors = bytes_to_sectors(inode->data.length);
  size_t new_sectors = bytes_to_sectors(new_length);

  lock_acquire(&inode->resize_lock);

  if (new_sectors > old_sectors) {
    size_t i;
    for (i = old_sectors; i < new_sectors; i++) {
      block_sector_t b;
      if (!free_map_allocate(1, &b))
        goto fail;
      static char zeros[BLOCK_SECTOR_SIZE];
      block_write(fs_device, b, zeros);
      if (!inode_set_sector(&inode->data, i, b))
        goto fail;
    }
  }

  inode->data.length = new_length;
  block_write(fs_device, inode->sector, &inode->data);

  lock_release(&inode->resize_lock);
  return true;

fail:
  inode->data.length = inode->data.length;
  block_write(fs_device, inode->sector, &inode->data);
  lock_release(&inode->resize_lock);
  return false;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  struct inode_disk disk;
  size_t i;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);

  memset(&disk, 0, sizeof disk);
  disk.length = 0;
  disk.magic = INODE_MAGIC;
  for (i = 0; i < INODE_DIRECT; i++)
    disk.direct[i] = 0;
  disk.indirect = 0;
  disk.doubly_indirect = 0;
  disk.flags = is_dir ? INODE_FLAG_DIR : 0;

  block_write(fs_device, sector, &disk);

  if (length > 0) {
    struct inode* tmp = inode_open(sector);
    bool ok = inode_resize(tmp, length);
    inode_close(tmp);
    return ok;
  }
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->resize_lock);
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      size_t total_secs = bytes_to_sectors(inode->data.length);
      for (size_t i = 0; i < total_secs; i++) {
        block_sector_t b = inode_get_sector(&inode->data, i);
        if (b != 0)
          free_map_release(b, 1);
      }

      if (inode->data.indirect) {
        free_map_release(inode->data.indirect, 1);
      }

      if (inode->data.doubly_indirect) {
        block_sector_t ptrs[PTRS_PER_BLOCK];
        block_read(fs_device, inode->data.doubly_indirect, ptrs);

        for (int j = 0; j < PTRS_PER_BLOCK; j++) {
          if (ptrs[j] != 0)
            free_map_release(ptrs[j], 1);
        }
        free_map_release(inode->data.doubly_indirect, 1);
      }
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (offset + size > inode_length(inode))
    inode_resize(inode, offset + size);

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

bool inode_is_dir(const struct inode* inode) { return (inode->data.flags & INODE_FLAG_DIR) != 0; }