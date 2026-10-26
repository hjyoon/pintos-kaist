#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Disk used for file system. */
extern struct disk *filesys_disk;

/* Drain filesystem operations before shutdown. Nested calls in one thread
   count once; accounting disables interrupts only for counter updates. GCC's
   scope cleanup balances every return path, including allocation failures. */
void filesys_operation_begin (void);
void filesys_operation_end (int *scope);
#define FILESYS_OPERATION \
	int filesys_scope __attribute__((cleanup(filesys_operation_end), unused)) = \
	    (filesys_operation_begin (), 0)

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);
bool filesys_chdir (const char *name);
bool filesys_mkdir (const char *name);
int filesys_symlink (const char *target, const char *linkpath);

#endif /* filesys/filesys.h */
