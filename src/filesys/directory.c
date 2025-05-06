#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  if (!inode_create(sector, entry_cnt * sizeof(struct dir_entry), true))
    return false;
  struct dir* d = dir_open(inode_open(sector));
  if (d == NULL)
    return false;
  bool ok = dir_add(d, ".", sector) && dir_add(d, "..", ROOT_DIR_SECTOR);
  dir_close(d);

  return ok;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

bool dir_is_empty(const struct dir* dir) {
  struct dir_entry e;
  off_t ofs = 0;
  while (inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e) {
    ofs += sizeof e;
    if (e.in_use && strcmp(e.name, ".") && strcmp(e.name, ".."))
      return false;
  }
  return true;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  off_t ofs;
  bool success = false;

  if (!lookup(dir, name, &e, &ofs))
    return false;

  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    return false;

  if (inode_is_dir(inode)) {
    if (e.inode_sector == ROOT_DIR_SECTOR) {
      inode_close(inode);
      return false;
    }

    struct dir* dir = dir_open(inode);
    bool is_empty = dir_is_empty(dir);
    dir_close(dir);

    if (!is_empty) {
      inode_close(inode);
      return false;
    }
  }

  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e) {
    inode_close(inode);
    return false;
  }

  inode_remove(inode);
  success = true;

  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;
  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use && strcmp(e.name, ".") != 0 && strcmp(e.name, "..") != 0) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}

int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';
  *srcp = src;
  return 1;
}

bool resolve_path(const char* path, struct dir** dir_out, char name_out[NAME_MAX + 1]) {
  struct dir* cur;
  if (path[0] == '/')
    cur = dir_open_root();
  else
    cur = dir_reopen(thread_current()->pcb->cwd);

  const char* src = path;
  char part[NAME_MAX + 1];
  int r;

  while ((r = get_next_part(part, &src)) == 1) {
    const char* peek = src;
    char tmp[NAME_MAX + 1];
    if (get_next_part(tmp, &peek) == 0) {
      strlcpy(name_out, part, NAME_MAX + 1);
      *dir_out = cur;
      return true;
    }

    if (!strcmp(part, ".")) {
    } else if (!strcmp(part, "..")) {
      struct dir_entry e;
      off_t ofs;
      if (!lookup(cur, "..", &e, &ofs)) {
        dir_close(cur);
        return false;
      }
      struct dir* up = dir_open(inode_open(e.inode_sector));
      dir_close(cur);
      cur = up;
    } else {
      struct inode* inode = NULL;
      if (!dir_lookup(cur, part, &inode) || !inode_is_dir(inode)) {
        inode_close(inode);
        dir_close(cur);
        return false;
      }
      struct dir* next = dir_open(inode);
      dir_close(cur);
      cur = next;
    }
  }

  dir_close(cur);
  return false;
}
