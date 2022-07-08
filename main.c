#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>

typedef struct BreakPoint BreakPoint;

// BreakPoint struct
struct BreakPoint {
    BreakPoint *next;
    long addr;
    long orig_text;
    char name[8];
};

BreakPoint *bp_head;

// find breakpoint using address
// return: breakpoint pointer
// arg:
//    addr: breakpoint address
BreakPoint *find_bp_with_addr(long addr) {
    BreakPoint *cur;

    for(cur = bp_head; cur; cur = cur->next) {
        if(cur->addr == addr) {
            return cur;
        }
    }

    return NULL;
}

/*
BreakPoint *find_bp_with_name(char *name) {
    BreakPoint *cur;

    for(cur = bp; cur; cur = cur->next) {
    }

    return NULL;
}
*/

// write breakpoint to process
// arg:
//    pid: target process id
//    tmp: breakpoint struct pointer
void write_breakpoint(int pid, BreakPoint *tmp) {
    void *addr_ptr;

    addr_ptr = (void *)tmp->addr;

    // write INT 3(SIGTRAP)
    // orig_text & 0xFFFFFFFFFFFFFF00 -> first byte is 0x00, after orig_text.
    // (orig_text & 0xFFFFFFFFFFFFFF00) | 0xCC -> first byte is 0xCC, after orig_text.
    ptrace(PTRACE_POKETEXT, pid, addr_ptr, ((tmp->orig_text & 0xFFFFFFFFFFFFFF00) | 0xCC));
}

// create breakpoint
// arg:
//    pid: target procces id
void create_breakpoint(int pid) {
    long addr;
    void *addr_ptr;
    BreakPoint *tmp;

    printf("BreakPoint addr: ");
    scanf("%lx", &addr);

    if(find_bp_with_addr(addr)) {
        printf("Already created\n");
        return;
    }

    tmp = calloc(1, sizeof(BreakPoint));
    tmp->next = bp_head;
    bp_head = tmp;
    tmp->addr = addr;

//    printf("BreakPoint name: ");
//    scanf("%s", tmp->name);

    addr_ptr = (void *)tmp->addr;

    // store addr text
    bp_head->orig_text = ptrace(PTRACE_PEEKTEXT, pid, addr_ptr, NULL);

    write_breakpoint(pid, tmp);

    printf("Set breakpoint at 0x%016lx as %s.\n", tmp->addr, tmp->name);
}

// detach process
// arg:
//    pid: target process id
long detach(int pid) {
    long ret;
    // detach
    ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if(ret < 0) {
        printf("Detach %d failed\n", pid);
        return -1;
    }

    printf("Detach %d\n", pid);
    return ret;
}

int main() {
    int pid;
    int status;
    int i;
    int mode;
    int is_singlestep = 0;
    long ret;
    long addr;
    BreakPoint *tmp;
    struct user_regs_struct regs;

    printf("Attach pid:");
    scanf("%d", &pid);

    // attach to pid
    ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if(ret < 0) {
        printf("Attach %d failed\n", pid);
        return -1;
    }

    printf("Attach %d\n", pid);

    // start debugger
    while(1) {
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            break;
        } else if(WIFSTOPPED(status)) {
            tmp = bp_head;
            while(tmp) {
                ptrace(PTRACE_POKETEXT, pid, (void *)tmp->addr, tmp->orig_text);
                tmp = tmp->next;
            }
            // breakpoint check
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            tmp = find_bp_with_addr((long)regs.rip - 1);

            if(is_singlestep) {
                is_singlestep = 0;
            } else if(tmp) {
                regs.rip = (unsigned long)tmp->addr;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);

                // read reg again
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            }

            printf("orig_rax:0x%016llx\n", regs.orig_rax);
            printf("rax:0x%016llx\n", regs.rax);
            printf("rbx:0x%016llx\n", regs.rbx);
            printf("rcx:0x%016llx\n", regs.rcx);
            printf("rdx:0x%016llx\n", regs.rdx);
            printf("rsi:0x%016llx\n", regs.rsi);
            printf("rdi:0x%016llx\n", regs.rdi);
            printf("\n");
            printf("rbp:0x%016llx\n", regs.rbp);
            printf("rsp:0x%016llx\n", regs.rsp);
            printf("\n");
            printf("rip:0x%016llx\n", regs.rip);

        }
        // select mode
        while(1) {
            printf("\n");
            printf("1:PTRACE_SYSCALL\n");
            printf("2:PTRACE_SINGLESTEP\n");
            printf("3:PTRACE_CONT\n");
            printf("4:set breakpoint\n");
            printf("5:show breakpoint\n");
            printf("0:exit\n");

            printf("> ");
            scanf("%d", &mode);

            if(!mode) {
                ret = detach(pid);
                return 0;
            }

            if(mode == 1) {
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                break;
            } else if(mode == 2) {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                is_singlestep = 1;
                break;
            } else if(mode == 3) {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                waitpid(pid, &status, 0);

                tmp = bp_head;
                while(tmp) {
                    write_breakpoint(pid, tmp);
                    tmp = tmp->next;
                }

                ptrace(PTRACE_CONT, pid, NULL, NULL);
                break;
            } else if(mode == 4) {
                create_breakpoint(pid);
            } else if(mode == 5) {
                printf("breakpoint list\n");
                i = 0;
                tmp = bp_head;
                while(tmp) {
                    printf("  [%d] addr: 0x%016lx\n", i, tmp->addr);
                    i++;
                    tmp = tmp->next;
                }
                printf("\n");
            } else {
                printf("Invalid number: %d\n", mode);
            }
        }
    }

    return 0;
}

