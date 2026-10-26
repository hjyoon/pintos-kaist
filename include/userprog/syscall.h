#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>

void syscall_init (void);
bool user_buffer_valid (const void *, size_t, bool writable);
void syscall_exit (int status) NO_RETURN;

#endif /* userprog/syscall.h */
