#ifndef PROC_ATTACK_H
#define PROC_ATTACK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define HANDLE_ERR(s)                                                          \
  {                                                                            \
    perror(s);                                                                 \
    exit(1);                                                                   \
  }

extern void read_data(pid_t prgID, long src, unsigned char *dest, uint32_t len);
extern void inject_data(pid_t prgID, long dest, unsigned char *src,
                        uint32_t len);

#endif // PROC_ATTACK_H
