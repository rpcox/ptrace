/* syscall.c

  Basic usage of ptrace(2) with PTRACE_TRACEME, PTRACE_GETREGS, PTRACE_SYSCALL
  to demonstrate tracing system calls in a child process.  If using Solaris
  void *addr & void *data need to be switched around.

  Only the x64 and common ABI sys entry calls are documented in the function
  const char* sys_call(long call) at bottom.  See data/syscall_table to
  consider using the x32 ABI calls.  See src/parse_call_tbl to modify the
  related script.

 */

#ifndef __linux__
  #error "Not a Linux system.  Check ptrace() arg order for *addr and *data"
#endif

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#if __WORDSIZE == 64              // x86_64
  #define REG(reg) reg.orig_rax
#else                             // x86
  #define REG(reg) reg.orig_eax
#endif

const char* sys_call(long call);

int main(int argc, char* argv[]) {

  if (argc < 2) {
    fprintf(stderr, "usage: syscall PROGRAM [ OPTIONS ]\n");
    exit(1);
  }

  char* chargs[argc];
  int i = 0;

  while (i < argc - 1) {        // using execvp(3).  collect all of the cmdline pieces
    chargs[i] = argv[i+1];
    i++;
  }

  chargs[i] = NULL;

  pid_t pid = fork();
  int line = 1;
  int status;

  switch(pid) {

    case -1:
      fprintf(stderr, "fork failed\n");
      exit(EXIT_FAILURE);

    case 0:
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execvp(chargs[0], chargs);
      break;

    default:
      while(waitpid(pid, &status, 0) && ! WIFEXITED(status)) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        fprintf(stderr, "%6d: [%d]  %4llu  %s\n", line, pid, REG(regs), sys_call(REG(regs)));
        line++;
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
      }

      break;
  }

  return EXIT_SUCCESS;
}

/* sys_call */

const char* sys_call(long call) {
  switch(call) {

  #ifdef SYS_read                       // 0, 0x0000
    case SYS_read: return "sys_read";
  #endif

  #ifdef SYS_write                      // 1, 0x0001
    case SYS_write: return "sys_write";
  #endif

  #ifdef SYS_open                       // 2, 0x0002
    case SYS_open: return "sys_open";
  #endif

  #ifdef SYS_close                      // 3, 0x0003
    case SYS_close: return "sys_close";
  #endif

  #ifdef SYS_stat                       // 4, 0x0004
    case SYS_stat: return "sys_stat";
  #endif

  #ifdef SYS_fstat                      // 5, 0x0005
    case SYS_fstat: return "sys_fstat";
  #endif

  #ifdef SYS_lstat                      // 6, 0x0006
    case SYS_lstat: return "sys_lstat";
  #endif

  #ifdef SYS_poll                       // 7, 0x0007
    case SYS_poll: return "sys_poll";
  #endif

  #ifdef SYS_lseek                      // 8, 0x0008
    case SYS_lseek: return "sys_lseek";
  #endif

  #ifdef SYS_mmap                       // 9, 0x0009
    case SYS_mmap: return "sys_mmap";
  #endif

  #ifdef SYS_mprotect                   // 10, 0x000A
    case SYS_mprotect: return "sys_mprotect";
  #endif

  #ifdef SYS_munmap                     // 11, 0x000B
    case SYS_munmap: return "sys_munmap";
  #endif

  #ifdef SYS_brk                        // 12, 0x000C
    case SYS_brk: return "sys_brk";
  #endif

  #ifdef SYS_rt_sigaction               // 13, 0x000D
    case SYS_rt_sigaction: return "sys_rt_sigaction";
  #endif

  #ifdef SYS_rt_sigprocmask             // 14, 0x000E
    case SYS_rt_sigprocmask: return "sys_rt_sigprocmask";
  #endif

  #ifdef SYS_rt_sigreturn               // 15, 0x000F
    case SYS_rt_sigreturn: return "sys_rt_sigreturn";
  #endif

  #ifdef SYS_ioctl                      // 16, 0x0010
    case SYS_ioctl: return "sys_ioctl";
  #endif

  #ifdef SYS_pread64                    // 17, 0x0011
    case SYS_pread64: return "sys_pread64";
  #endif

  #ifdef SYS_pwrite64                   // 18, 0x0012
    case SYS_pwrite64: return "sys_pwrite64";
  #endif

  #ifdef SYS_readv                      // 19, 0x0013
    case SYS_readv: return "sys_readv";
  #endif

  #ifdef SYS_writev                     // 20, 0x0014
    case SYS_writev: return "sys_writev";
  #endif

  #ifdef SYS_access                     // 21, 0x0015
    case SYS_access: return "sys_access";
  #endif

  #ifdef SYS_pipe                       // 22, 0x0016
    case SYS_pipe: return "sys_pipe";
  #endif

  #ifdef SYS_select                     // 23, 0x0017
    case SYS_select: return "sys_select";
  #endif

  #ifdef SYS_sched_yield                // 24, 0x0018
    case SYS_sched_yield: return "sys_sched_yield";
  #endif

  #ifdef SYS_mremap                     // 25, 0x0019
    case SYS_mremap: return "sys_mremap";
  #endif

  #ifdef SYS_msync                      // 26, 0x001A
    case SYS_msync: return "sys_msync";
  #endif

  #ifdef SYS_mincore                    // 27, 0x001B
    case SYS_mincore: return "sys_mincore";
  #endif

  #ifdef SYS_madvise                    // 28, 0x001C
    case SYS_madvise: return "sys_madvise";
  #endif

  #ifdef SYS_shmget                     // 29, 0x001D
    case SYS_shmget: return "sys_shmget";
  #endif

  #ifdef SYS_shmat                      // 30, 0x001E
    case SYS_shmat: return "sys_shmat";
  #endif

  #ifdef SYS_shmctl                     // 31, 0x001F
    case SYS_shmctl: return "sys_shmctl";
  #endif

  #ifdef SYS_dup                        // 32, 0x0020
    case SYS_dup: return "sys_dup";
  #endif

  #ifdef SYS_dup2                       // 33, 0x0021
    case SYS_dup2: return "sys_dup2";
  #endif

  #ifdef SYS_pause                      // 34, 0x0022
    case SYS_pause: return "sys_pause";
  #endif

  #ifdef SYS_nanosleep                  // 35, 0x0023
    case SYS_nanosleep: return "sys_nanosleep";
  #endif

  #ifdef SYS_getitimer                  // 36, 0x0024
    case SYS_getitimer: return "sys_getitimer";
  #endif

  #ifdef SYS_alarm                      // 37, 0x0025
    case SYS_alarm: return "sys_alarm";
  #endif

  #ifdef SYS_setitimer                  // 38, 0x0026
    case SYS_setitimer: return "sys_setitimer";
  #endif

  #ifdef SYS_getpid                     // 39, 0x0027
    case SYS_getpid: return "sys_getpid";
  #endif

  #ifdef SYS_sendfile                   // 40, 0x0028
    case SYS_sendfile: return "sys_sendfile";
  #endif

  #ifdef SYS_socket                     // 41, 0x0029
    case SYS_socket: return "sys_socket";
  #endif

  #ifdef SYS_connect                    // 42, 0x002A
    case SYS_connect: return "sys_connect";
  #endif

  #ifdef SYS_accept                     // 43, 0x002B
    case SYS_accept: return "sys_accept";
  #endif

  #ifdef SYS_sendto                     // 44, 0x002C
    case SYS_sendto: return "sys_sendto";
  #endif

  #ifdef SYS_recvfrom                   // 45, 0x002D
    case SYS_recvfrom: return "sys_recvfrom";
  #endif

  #ifdef SYS_sendmsg                    // 46, 0x002E
    case SYS_sendmsg: return "sys_sendmsg";
  #endif

  #ifdef SYS_recvmsg                    // 47, 0x002F
    case SYS_recvmsg: return "sys_recvmsg";
  #endif

  #ifdef SYS_shutdown                   // 48, 0x0030
    case SYS_shutdown: return "sys_shutdown";
  #endif

  #ifdef SYS_bind                       // 49, 0x0031
    case SYS_bind: return "sys_bind";
  #endif

  #ifdef SYS_listen                     // 50, 0x0032
    case SYS_listen: return "sys_listen";
  #endif

  #ifdef SYS_getsockname                // 51, 0x0033
    case SYS_getsockname: return "sys_getsockname";
  #endif

  #ifdef SYS_getpeername                // 52, 0x0034
    case SYS_getpeername: return "sys_getpeername";
  #endif

  #ifdef SYS_socketpair                 // 53, 0x0035
    case SYS_socketpair: return "sys_socketpair";
  #endif

  #ifdef SYS_setsockopt                 // 54, 0x0036
    case SYS_setsockopt: return "sys_setsockopt";
  #endif

  #ifdef SYS_getsockopt                 // 55, 0x0037
    case SYS_getsockopt: return "sys_getsockopt";
  #endif

  #ifdef SYS_clone                      // 56, 0x0038
    case SYS_clone: return "sys_clone";
  #endif

  #ifdef SYS_fork                       // 57, 0x0039
    case SYS_fork: return "sys_fork";
  #endif

  #ifdef SYS_vfork                      // 58, 0x003A
    case SYS_vfork: return "sys_vfork";
  #endif

  #ifdef SYS_execve                     // 59, 0x003B
    case SYS_execve: return "sys_execve";
  #endif

  #ifdef SYS_exit                       // 60, 0x003C
    case SYS_exit: return "sys_exit";
  #endif

  #ifdef SYS_wait4                      // 61, 0x003D
    case SYS_wait4: return "sys_wait4";
  #endif

  #ifdef SYS_kill                       // 62, 0x003E
    case SYS_kill: return "sys_kill";
  #endif

  #ifdef SYS_uname                      // 63, 0x003F
    case SYS_uname: return "sys_uname";
  #endif

  #ifdef SYS_semget                     // 64, 0x0040
    case SYS_semget: return "sys_semget";
  #endif

  #ifdef SYS_semop                      // 65, 0x0041
    case SYS_semop: return "sys_semop";
  #endif

  #ifdef SYS_semctl                     // 66, 0x0042
    case SYS_semctl: return "sys_semctl";
  #endif

  #ifdef SYS_shmdt                      // 67, 0x0043
    case SYS_shmdt: return "sys_shmdt";
  #endif

  #ifdef SYS_msgget                     // 68, 0x0044
    case SYS_msgget: return "sys_msgget";
  #endif

  #ifdef SYS_msgsnd                     // 69, 0x0045
    case SYS_msgsnd: return "sys_msgsnd";
  #endif

  #ifdef SYS_msgrcv                     // 70, 0x0046
    case SYS_msgrcv: return "sys_msgrcv";
  #endif

  #ifdef SYS_msgctl                     // 71, 0x0047
    case SYS_msgctl: return "sys_msgctl";
  #endif

  #ifdef SYS_fcntl                      // 72, 0x0048
    case SYS_fcntl: return "sys_fcntl";
  #endif

  #ifdef SYS_flock                      // 73, 0x0049
    case SYS_flock: return "sys_flock";
  #endif

  #ifdef SYS_fsync                      // 74, 0x004A
    case SYS_fsync: return "sys_fsync";
  #endif

  #ifdef SYS_fdatasync                  // 75, 0x004B
    case SYS_fdatasync: return "sys_fdatasync";
  #endif

  #ifdef SYS_truncate                   // 76, 0x004C
    case SYS_truncate: return "sys_truncate";
  #endif

  #ifdef SYS_ftruncate                  // 77, 0x004D
    case SYS_ftruncate: return "sys_ftruncate";
  #endif

  #ifdef SYS_getdents                   // 78, 0x004E
    case SYS_getdents: return "sys_getdents";
  #endif

  #ifdef SYS_getcwd                     // 79, 0x004F
    case SYS_getcwd: return "sys_getcwd";
  #endif

  #ifdef SYS_chdir                      // 80, 0x0050
    case SYS_chdir: return "sys_chdir";
  #endif

  #ifdef SYS_fchdir                     // 81, 0x0051
    case SYS_fchdir: return "sys_fchdir";
  #endif

  #ifdef SYS_rename                     // 82, 0x0052
    case SYS_rename: return "sys_rename";
  #endif

  #ifdef SYS_mkdir                      // 83, 0x0053
    case SYS_mkdir: return "sys_mkdir";
  #endif

  #ifdef SYS_rmdir                      // 84, 0x0054
    case SYS_rmdir: return "sys_rmdir";
  #endif

  #ifdef SYS_creat                      // 85, 0x0055
    case SYS_creat: return "sys_creat";
  #endif

  #ifdef SYS_link                       // 86, 0x0056
    case SYS_link: return "sys_link";
  #endif

  #ifdef SYS_unlink                     // 87, 0x0057
    case SYS_unlink: return "sys_unlink";
  #endif

  #ifdef SYS_symlink                    // 88, 0x0058
    case SYS_symlink: return "sys_symlink";
  #endif

  #ifdef SYS_readlink                   // 89, 0x0059
    case SYS_readlink: return "sys_readlink";
  #endif

  #ifdef SYS_chmod                      // 90, 0x005A
    case SYS_chmod: return "sys_chmod";
  #endif

  #ifdef SYS_fchmod                     // 91, 0x005B
    case SYS_fchmod: return "sys_fchmod";
  #endif

  #ifdef SYS_chown                      // 92, 0x005C
    case SYS_chown: return "sys_chown";
  #endif

  #ifdef SYS_fchown                     // 93, 0x005D
    case SYS_fchown: return "sys_fchown";
  #endif

  #ifdef SYS_lchown                     // 94, 0x005E
    case SYS_lchown: return "sys_lchown";
  #endif

  #ifdef SYS_umask                      // 95, 0x005F
    case SYS_umask: return "sys_umask";
  #endif

  #ifdef SYS_gettimeofday               // 96, 0x0060
    case SYS_gettimeofday: return "sys_gettimeofday";
  #endif

  #ifdef SYS_getrlimit                  // 97, 0x0061
    case SYS_getrlimit: return "sys_getrlimit";
  #endif

  #ifdef SYS_getrusage                  // 98, 0x0062
    case SYS_getrusage: return "sys_getrusage";
  #endif

  #ifdef SYS_sysinfo                    // 99, 0x0063
    case SYS_sysinfo: return "sys_sysinfo";
  #endif

  #ifdef SYS_times                      // 100, 0x0064
    case SYS_times: return "sys_times";
  #endif

  #ifdef SYS_ptrace                     // 101, 0x0065
    case SYS_ptrace: return "sys_ptrace";
  #endif

  #ifdef SYS_getuid                     // 102, 0x0066
    case SYS_getuid: return "sys_getuid";
  #endif

  #ifdef SYS_syslog                     // 103, 0x0067
    case SYS_syslog: return "sys_syslog";
  #endif

  #ifdef SYS_getgid                     // 104, 0x0068
    case SYS_getgid: return "sys_getgid";
  #endif

  #ifdef SYS_setuid                     // 105, 0x0069
    case SYS_setuid: return "sys_setuid";
  #endif

  #ifdef SYS_setgid                     // 106, 0x006A
    case SYS_setgid: return "sys_setgid";
  #endif

  #ifdef SYS_geteuid                    // 107, 0x006B
    case SYS_geteuid: return "sys_geteuid";
  #endif

  #ifdef SYS_getegid                    // 108, 0x006C
    case SYS_getegid: return "sys_getegid";
  #endif

  #ifdef SYS_setpgid                    // 109, 0x006D
    case SYS_setpgid: return "sys_setpgid";
  #endif

  #ifdef SYS_getppid                    // 110, 0x006E
    case SYS_getppid: return "sys_getppid";
  #endif

  #ifdef SYS_getpgrp                    // 111, 0x006F
    case SYS_getpgrp: return "sys_getpgrp";
  #endif

  #ifdef SYS_setsid                     // 112, 0x0070
    case SYS_setsid: return "sys_setsid";
  #endif

  #ifdef SYS_setreuid                   // 113, 0x0071
    case SYS_setreuid: return "sys_setreuid";
  #endif

  #ifdef SYS_setregid                   // 114, 0x0072
    case SYS_setregid: return "sys_setregid";
  #endif

  #ifdef SYS_getgroups                  // 115, 0x0073
    case SYS_getgroups: return "sys_getgroups";
  #endif

  #ifdef SYS_setgroups                  // 116, 0x0074
    case SYS_setgroups: return "sys_setgroups";
  #endif

  #ifdef SYS_setresuid                  // 117, 0x0075
    case SYS_setresuid: return "sys_setresuid";
  #endif

  #ifdef SYS_getresuid                  // 118, 0x0076
    case SYS_getresuid: return "sys_getresuid";
  #endif

  #ifdef SYS_setresgid                  // 119, 0x0077
    case SYS_setresgid: return "sys_setresgid";
  #endif

  #ifdef SYS_getresgid                  // 120, 0x0078
    case SYS_getresgid: return "sys_getresgid";
  #endif

  #ifdef SYS_getpgid                    // 121, 0x0079
    case SYS_getpgid: return "sys_getpgid";
  #endif

  #ifdef SYS_setfsuid                   // 122, 0x007A
    case SYS_setfsuid: return "sys_setfsuid";
  #endif

  #ifdef SYS_setfsgid                   // 123, 0x007B
    case SYS_setfsgid: return "sys_setfsgid";
  #endif

  #ifdef SYS_getsid                     // 124, 0x007C
    case SYS_getsid: return "sys_getsid";
  #endif

  #ifdef SYS_capget                     // 125, 0x007D
    case SYS_capget: return "sys_capget";
  #endif

  #ifdef SYS_capset                     // 126, 0x007E
    case SYS_capset: return "sys_capset";
  #endif

  #ifdef SYS_rt_sigpending              // 127, 0x007F
    case SYS_rt_sigpending: return "sys_rt_sigpending";
  #endif

  #ifdef SYS_rt_sigtimedwait            // 128, 0x0080
    case SYS_rt_sigtimedwait: return "sys_rt_sigtimedwait";
  #endif

  #ifdef SYS_rt_sigqueueinfo            // 129, 0x0081
    case SYS_rt_sigqueueinfo: return "sys_rt_sigqueueinfo";
  #endif

  #ifdef SYS_rt_sigsuspend              // 130, 0x0082
    case SYS_rt_sigsuspend: return "sys_rt_sigsuspend";
  #endif

  #ifdef SYS_sigaltstack                // 131, 0x0083
    case SYS_sigaltstack: return "sys_sigaltstack";
  #endif

  #ifdef SYS_utime                      // 132, 0x0084
    case SYS_utime: return "sys_utime";
  #endif

  #ifdef SYS_mknod                      // 133, 0x0085
    case SYS_mknod: return "sys_mknod";
  #endif

  #ifdef SYS_personality                // 135, 0x0087
    case SYS_personality: return "sys_personality";
  #endif

  #ifdef SYS_ustat                      // 136, 0x0088
    case SYS_ustat: return "sys_ustat";
  #endif

  #ifdef SYS_statfs                     // 137, 0x0089
    case SYS_statfs: return "sys_statfs";
  #endif

  #ifdef SYS_fstatfs                    // 138, 0x008A
    case SYS_fstatfs: return "sys_fstatfs";
  #endif

  #ifdef SYS_sysfs                      // 139, 0x008B
    case SYS_sysfs: return "sys_sysfs";
  #endif

  #ifdef SYS_getpriority                // 140, 0x008C
    case SYS_getpriority: return "sys_getpriority";
  #endif

  #ifdef SYS_setpriority                // 141, 0x008D
    case SYS_setpriority: return "sys_setpriority";
  #endif

  #ifdef SYS_sched_setparam             // 142, 0x008E
    case SYS_sched_setparam: return "sys_sched_setparam";
  #endif

  #ifdef SYS_sched_getparam             // 143, 0x008F
    case SYS_sched_getparam: return "sys_sched_getparam";
  #endif

  #ifdef SYS_sched_setscheduler         // 144, 0x0090
    case SYS_sched_setscheduler: return "sys_sched_setscheduler";
  #endif

  #ifdef SYS_sched_getscheduler         // 145, 0x0091
    case SYS_sched_getscheduler: return "sys_sched_getscheduler";
  #endif

  #ifdef SYS_sched_get_priority_max     // 146, 0x0092
    case SYS_sched_get_priority_max: return "sys_sched_get_priority_max";
  #endif

  #ifdef SYS_sched_get_priority_min     // 147, 0x0093
    case SYS_sched_get_priority_min: return "sys_sched_get_priority_min";
  #endif

  #ifdef SYS_sched_rr_get_interval      // 148, 0x0094
    case SYS_sched_rr_get_interval: return "sys_sched_rr_get_interval";
  #endif

  #ifdef SYS_mlock                      // 149, 0x0095
    case SYS_mlock: return "sys_mlock";
  #endif

  #ifdef SYS_munlock                    // 150, 0x0096
    case SYS_munlock: return "sys_munlock";
  #endif

  #ifdef SYS_mlockall                   // 151, 0x0097
    case SYS_mlockall: return "sys_mlockall";
  #endif

  #ifdef SYS_munlockall                 // 152, 0x0098
    case SYS_munlockall: return "sys_munlockall";
  #endif

  #ifdef SYS_vhangup                    // 153, 0x0099
    case SYS_vhangup: return "sys_vhangup";
  #endif

  #ifdef SYS_modify_ldt                 // 154, 0x009A
    case SYS_modify_ldt: return "sys_modify_ldt";
  #endif

  #ifdef SYS_pivot_root                 // 155, 0x009B
    case SYS_pivot_root: return "sys_pivot_root";
  #endif

  #ifdef SYS__sysctl                    // 156, 0x009C
    case SYS__sysctl: return "sys__sysctl";
  #endif

  #ifdef SYS_prctl                      // 157, 0x009D
    case SYS_prctl: return "sys_prctl";
  #endif

  #ifdef SYS_arch_prctl                 // 158, 0x009E
    case SYS_arch_prctl: return "sys_arch_prctl";
  #endif

  #ifdef SYS_adjtimex                   // 159, 0x009F
    case SYS_adjtimex: return "sys_adjtimex";
  #endif

  #ifdef SYS_setrlimit                  // 160, 0x00A0
    case SYS_setrlimit: return "sys_setrlimit";
  #endif

  #ifdef SYS_chroot                     // 161, 0x00A1
    case SYS_chroot: return "sys_chroot";
  #endif

  #ifdef SYS_sync                       // 162, 0x00A2
    case SYS_sync: return "sys_sync";
  #endif

  #ifdef SYS_acct                       // 163, 0x00A3
    case SYS_acct: return "sys_acct";
  #endif

  #ifdef SYS_settimeofday               // 164, 0x00A4
    case SYS_settimeofday: return "sys_settimeofday";
  #endif

  #ifdef SYS_mount                      // 165, 0x00A5
    case SYS_mount: return "sys_mount";
  #endif

  #ifdef SYS_umount2                    // 166, 0x00A6
    case SYS_umount2: return "sys_umount2";
  #endif

  #ifdef SYS_swapon                     // 167, 0x00A7
    case SYS_swapon: return "sys_swapon";
  #endif

  #ifdef SYS_swapoff                    // 168, 0x00A8
    case SYS_swapoff: return "sys_swapoff";
  #endif

  #ifdef SYS_reboot                     // 169, 0x00A9
    case SYS_reboot: return "sys_reboot";
  #endif

  #ifdef SYS_sethostname                // 170, 0x00AA
    case SYS_sethostname: return "sys_sethostname";
  #endif

  #ifdef SYS_setdomainname              // 171, 0x00AB
    case SYS_setdomainname: return "sys_setdomainname";
  #endif

  #ifdef SYS_iopl                       // 172, 0x00AC
    case SYS_iopl: return "sys_iopl";
  #endif

  #ifdef SYS_ioperm                     // 173, 0x00AD
    case SYS_ioperm: return "sys_ioperm";
  #endif

  #ifdef SYS_init_module                // 175, 0x00AF
    case SYS_init_module: return "sys_init_module";
  #endif

  #ifdef SYS_delete_module              // 176, 0x00B0
    case SYS_delete_module: return "sys_delete_module";
  #endif

  #ifdef SYS_quotactl                   // 179, 0x00B3
    case SYS_quotactl: return "sys_quotactl";
  #endif

  #ifdef SYS_gettid                     // 186, 0x00BA
    case SYS_gettid: return "sys_gettid";
  #endif

  #ifdef SYS_readahead                  // 187, 0x00BB
    case SYS_readahead: return "sys_readahead";
  #endif

  #ifdef SYS_setxattr                   // 188, 0x00BC
    case SYS_setxattr: return "sys_setxattr";
  #endif

  #ifdef SYS_lsetxattr                  // 189, 0x00BD
    case SYS_lsetxattr: return "sys_lsetxattr";
  #endif

  #ifdef SYS_fsetxattr                  // 190, 0x00BE
    case SYS_fsetxattr: return "sys_fsetxattr";
  #endif

  #ifdef SYS_getxattr                   // 191, 0x00BF
    case SYS_getxattr: return "sys_getxattr";
  #endif

  #ifdef SYS_lgetxattr                  // 192, 0x00C0
    case SYS_lgetxattr: return "sys_lgetxattr";
  #endif

  #ifdef SYS_fgetxattr                  // 193, 0x00C1
    case SYS_fgetxattr: return "sys_fgetxattr";
  #endif

  #ifdef SYS_listxattr                  // 194, 0x00C2
    case SYS_listxattr: return "sys_listxattr";
  #endif

  #ifdef SYS_llistxattr                 // 195, 0x00C3
    case SYS_llistxattr: return "sys_llistxattr";
  #endif

  #ifdef SYS_flistxattr                 // 196, 0x00C4
    case SYS_flistxattr: return "sys_flistxattr";
  #endif

  #ifdef SYS_removexattr                // 197, 0x00C5
    case SYS_removexattr: return "sys_removexattr";
  #endif

  #ifdef SYS_lremovexattr               // 198, 0x00C6
    case SYS_lremovexattr: return "sys_lremovexattr";
  #endif

  #ifdef SYS_fremovexattr               // 199, 0x00C7
    case SYS_fremovexattr: return "sys_fremovexattr";
  #endif

  #ifdef SYS_tkill                      // 200, 0x00C8
    case SYS_tkill: return "sys_tkill";
  #endif

  #ifdef SYS_time                       // 201, 0x00C9
    case SYS_time: return "sys_time";
  #endif

  #ifdef SYS_futex                      // 202, 0x00CA
    case SYS_futex: return "sys_futex";
  #endif

  #ifdef SYS_sched_setaffinity          // 203, 0x00CB
    case SYS_sched_setaffinity: return "sys_sched_setaffinity";
  #endif

  #ifdef SYS_sched_getaffinity          // 204, 0x00CC
    case SYS_sched_getaffinity: return "sys_sched_getaffinity";
  #endif

  #ifdef SYS_io_setup                   // 206, 0x00CE
    case SYS_io_setup: return "sys_io_setup";
  #endif

  #ifdef SYS_io_destroy                 // 207, 0x00CF
    case SYS_io_destroy: return "sys_io_destroy";
  #endif

  #ifdef SYS_io_getevents               // 208, 0x00D0
    case SYS_io_getevents: return "sys_io_getevents";
  #endif

  #ifdef SYS_io_submit                  // 209, 0x00D1
    case SYS_io_submit: return "sys_io_submit";
  #endif

  #ifdef SYS_io_cancel                  // 210, 0x00D2
    case SYS_io_cancel: return "sys_io_cancel";
  #endif

  #ifdef SYS_lookup_dcookie             // 212, 0x00D4
    case SYS_lookup_dcookie: return "sys_lookup_dcookie";
  #endif

  #ifdef SYS_epoll_create               // 213, 0x00D5
    case SYS_epoll_create: return "sys_epoll_create";
  #endif

  #ifdef SYS_remap_file_pages           // 216, 0x00D8
    case SYS_remap_file_pages: return "sys_remap_file_pages";
  #endif

  #ifdef SYS_getdents64                 // 217, 0x00D9
    case SYS_getdents64: return "sys_getdents64";
  #endif

  #ifdef SYS_set_tid_address            // 218, 0x00DA
    case SYS_set_tid_address: return "sys_set_tid_address";
  #endif

  #ifdef SYS_restart_syscall            // 219, 0x00DB
    case SYS_restart_syscall: return "sys_restart_syscall";
  #endif

  #ifdef SYS_semtimedop                 // 220, 0x00DC
    case SYS_semtimedop: return "sys_semtimedop";
  #endif

  #ifdef SYS_fadvise64                  // 221, 0x00DD
    case SYS_fadvise64: return "sys_fadvise64";
  #endif

  #ifdef SYS_timer_create               // 222, 0x00DE
    case SYS_timer_create: return "sys_timer_create";
  #endif

  #ifdef SYS_timer_settime              // 223, 0x00DF
    case SYS_timer_settime: return "sys_timer_settime";
  #endif

  #ifdef SYS_timer_gettime              // 224, 0x00E0
    case SYS_timer_gettime: return "sys_timer_gettime";
  #endif

  #ifdef SYS_timer_getoverrun           // 225, 0x00E1
    case SYS_timer_getoverrun: return "sys_timer_getoverrun";
  #endif

  #ifdef SYS_timer_delete               // 226, 0x00E2
    case SYS_timer_delete: return "sys_timer_delete";
  #endif

  #ifdef SYS_clock_settime              // 227, 0x00E3
    case SYS_clock_settime: return "sys_clock_settime";
  #endif

  #ifdef SYS_clock_gettime              // 228, 0x00E4
    case SYS_clock_gettime: return "sys_clock_gettime";
  #endif

  #ifdef SYS_clock_getres               // 229, 0x00E5
    case SYS_clock_getres: return "sys_clock_getres";
  #endif

  #ifdef SYS_clock_nanosleep            // 230, 0x00E6
    case SYS_clock_nanosleep: return "sys_clock_nanosleep";
  #endif

  #ifdef SYS_exit_group                 // 231, 0x00E7
    case SYS_exit_group: return "sys_exit_group";
  #endif

  #ifdef SYS_epoll_wait                 // 232, 0x00E8
    case SYS_epoll_wait: return "sys_epoll_wait";
  #endif

  #ifdef SYS_epoll_ctl                  // 233, 0x00E9
    case SYS_epoll_ctl: return "sys_epoll_ctl";
  #endif

  #ifdef SYS_tgkill                     // 234, 0x00EA
    case SYS_tgkill: return "sys_tgkill";
  #endif

  #ifdef SYS_utimes                     // 235, 0x00EB
    case SYS_utimes: return "sys_utimes";
  #endif

  #ifdef SYS_mbind                      // 237, 0x00ED
    case SYS_mbind: return "sys_mbind";
  #endif

  #ifdef SYS_set_mempolicy              // 238, 0x00EE
    case SYS_set_mempolicy: return "sys_set_mempolicy";
  #endif

  #ifdef SYS_get_mempolicy              // 239, 0x00EF
    case SYS_get_mempolicy: return "sys_get_mempolicy";
  #endif

  #ifdef SYS_mq_open                    // 240, 0x00F0
    case SYS_mq_open: return "sys_mq_open";
  #endif

  #ifdef SYS_mq_unlink                  // 241, 0x00F1
    case SYS_mq_unlink: return "sys_mq_unlink";
  #endif

  #ifdef SYS_mq_timedsend               // 242, 0x00F2
    case SYS_mq_timedsend: return "sys_mq_timedsend";
  #endif

  #ifdef SYS_mq_timedreceive            // 243, 0x00F3
    case SYS_mq_timedreceive: return "sys_mq_timedreceive";
  #endif

  #ifdef SYS_mq_notify                  // 244, 0x00F4
    case SYS_mq_notify: return "sys_mq_notify";
  #endif

  #ifdef SYS_mq_getsetattr              // 245, 0x00F5
    case SYS_mq_getsetattr: return "sys_mq_getsetattr";
  #endif

  #ifdef SYS_kexec_load                 // 246, 0x00F6
    case SYS_kexec_load: return "sys_kexec_load";
  #endif

  #ifdef SYS_waitid                     // 247, 0x00F7
    case SYS_waitid: return "sys_waitid";
  #endif

  #ifdef SYS_add_key                    // 248, 0x00F8
    case SYS_add_key: return "sys_add_key";
  #endif

  #ifdef SYS_request_key                // 249, 0x00F9
    case SYS_request_key: return "sys_request_key";
  #endif

  #ifdef SYS_keyctl                     // 250, 0x00FA
    case SYS_keyctl: return "sys_keyctl";
  #endif

  #ifdef SYS_ioprio_set                 // 251, 0x00FB
    case SYS_ioprio_set: return "sys_ioprio_set";
  #endif

  #ifdef SYS_ioprio_get                 // 252, 0x00FC
    case SYS_ioprio_get: return "sys_ioprio_get";
  #endif

  #ifdef SYS_inotify_init               // 253, 0x00FD
    case SYS_inotify_init: return "sys_inotify_init";
  #endif

  #ifdef SYS_inotify_add_watch          // 254, 0x00FE
    case SYS_inotify_add_watch: return "sys_inotify_add_watch";
  #endif

  #ifdef SYS_inotify_rm_watch           // 255, 0x00FF
    case SYS_inotify_rm_watch: return "sys_inotify_rm_watch";
  #endif

  #ifdef SYS_migrate_pages              // 256, 0x0100
    case SYS_migrate_pages: return "sys_migrate_pages";
  #endif

  #ifdef SYS_openat                     // 257, 0x0101
    case SYS_openat: return "sys_openat";
  #endif

  #ifdef SYS_mkdirat                    // 258, 0x0102
    case SYS_mkdirat: return "sys_mkdirat";
  #endif

  #ifdef SYS_mknodat                    // 259, 0x0103
    case SYS_mknodat: return "sys_mknodat";
  #endif

  #ifdef SYS_fchownat                   // 260, 0x0104
    case SYS_fchownat: return "sys_fchownat";
  #endif

  #ifdef SYS_futimesat                  // 261, 0x0105
    case SYS_futimesat: return "sys_futimesat";
  #endif

  #ifdef SYS_newfstatat                 // 262, 0x0106
    case SYS_newfstatat: return "sys_newfstatat";
  #endif

  #ifdef SYS_unlinkat                   // 263, 0x0107
    case SYS_unlinkat: return "sys_unlinkat";
  #endif

  #ifdef SYS_renameat                   // 264, 0x0108
    case SYS_renameat: return "sys_renameat";
  #endif

  #ifdef SYS_linkat                     // 265, 0x0109
    case SYS_linkat: return "sys_linkat";
  #endif

  #ifdef SYS_symlinkat                  // 266, 0x010A
    case SYS_symlinkat: return "sys_symlinkat";
  #endif

  #ifdef SYS_readlinkat                 // 267, 0x010B
    case SYS_readlinkat: return "sys_readlinkat";
  #endif

  #ifdef SYS_fchmodat                   // 268, 0x010C
    case SYS_fchmodat: return "sys_fchmodat";
  #endif

  #ifdef SYS_faccessat                  // 269, 0x010D
    case SYS_faccessat: return "sys_faccessat";
  #endif

  #ifdef SYS_pselect6                   // 270, 0x010E
    case SYS_pselect6: return "sys_pselect6";
  #endif

  #ifdef SYS_ppoll                      // 271, 0x010F
    case SYS_ppoll: return "sys_ppoll";
  #endif

  #ifdef SYS_unshare                    // 272, 0x0110
    case SYS_unshare: return "sys_unshare";
  #endif

  #ifdef SYS_set_robust_list            // 273, 0x0111
    case SYS_set_robust_list: return "sys_set_robust_list";
  #endif

  #ifdef SYS_get_robust_list            // 274, 0x0112
    case SYS_get_robust_list: return "sys_get_robust_list";
  #endif

  #ifdef SYS_splice                     // 275, 0x0113
    case SYS_splice: return "sys_splice";
  #endif

  #ifdef SYS_tee                        // 276, 0x0114
    case SYS_tee: return "sys_tee";
  #endif

  #ifdef SYS_sync_file_range            // 277, 0x0115
    case SYS_sync_file_range: return "sys_sync_file_range";
  #endif

  #ifdef SYS_vmsplice                   // 278, 0x0116
    case SYS_vmsplice: return "sys_vmsplice";
  #endif

  #ifdef SYS_move_pages                 // 279, 0x0117
    case SYS_move_pages: return "sys_move_pages";
  #endif

  #ifdef SYS_utimensat                  // 280, 0x0118
    case SYS_utimensat: return "sys_utimensat";
  #endif

  #ifdef SYS_epoll_pwait                // 281, 0x0119
    case SYS_epoll_pwait: return "sys_epoll_pwait";
  #endif

  #ifdef SYS_signalfd                   // 282, 0x011A
    case SYS_signalfd: return "sys_signalfd";
  #endif

  #ifdef SYS_timerfd_create             // 283, 0x011B
    case SYS_timerfd_create: return "sys_timerfd_create";
  #endif

  #ifdef SYS_eventfd                    // 284, 0x011C
    case SYS_eventfd: return "sys_eventfd";
  #endif

  #ifdef SYS_fallocate                  // 285, 0x011D
    case SYS_fallocate: return "sys_fallocate";
  #endif

  #ifdef SYS_timerfd_settime            // 286, 0x011E
    case SYS_timerfd_settime: return "sys_timerfd_settime";
  #endif

  #ifdef SYS_timerfd_gettime            // 287, 0x011F
    case SYS_timerfd_gettime: return "sys_timerfd_gettime";
  #endif

  #ifdef SYS_accept4                    // 288, 0x0120
    case SYS_accept4: return "sys_accept4";
  #endif

  #ifdef SYS_signalfd4                  // 289, 0x0121
    case SYS_signalfd4: return "sys_signalfd4";
  #endif

  #ifdef SYS_eventfd2                   // 290, 0x0122
    case SYS_eventfd2: return "sys_eventfd2";
  #endif

  #ifdef SYS_epoll_create1              // 291, 0x0123
    case SYS_epoll_create1: return "sys_epoll_create1";
  #endif

  #ifdef SYS_dup3                       // 292, 0x0124
    case SYS_dup3: return "sys_dup3";
  #endif

  #ifdef SYS_pipe2                      // 293, 0x0125
    case SYS_pipe2: return "sys_pipe2";
  #endif

  #ifdef SYS_inotify_init1              // 294, 0x0126
    case SYS_inotify_init1: return "sys_inotify_init1";
  #endif

  #ifdef SYS_preadv                     // 295, 0x0127
    case SYS_preadv: return "sys_preadv";
  #endif

  #ifdef SYS_pwritev                    // 296, 0x0128
    case SYS_pwritev: return "sys_pwritev";
  #endif

  #ifdef SYS_rt_tgsigqueueinfo          // 297, 0x0129
    case SYS_rt_tgsigqueueinfo: return "sys_rt_tgsigqueueinfo";
  #endif

  #ifdef SYS_perf_event_open            // 298, 0x012A
    case SYS_perf_event_open: return "sys_perf_event_open";
  #endif

  #ifdef SYS_recvmmsg                   // 299, 0x012B
    case SYS_recvmmsg: return "sys_recvmmsg";
  #endif

  #ifdef SYS_fanotify_init              // 300, 0x012C
    case SYS_fanotify_init: return "sys_fanotify_init";
  #endif

  #ifdef SYS_fanotify_mark              // 301, 0x012D
    case SYS_fanotify_mark: return "sys_fanotify_mark";
  #endif

  #ifdef SYS_prlimit64                  // 302, 0x012E
    case SYS_prlimit64: return "sys_prlimit64";
  #endif

  #ifdef SYS_name_to_handle_at          // 303, 0x012F
    case SYS_name_to_handle_at: return "sys_name_to_handle_at";
  #endif

  #ifdef SYS_open_by_handle_at          // 304, 0x0130
    case SYS_open_by_handle_at: return "sys_open_by_handle_at";
  #endif

  #ifdef SYS_clock_adjtime              // 305, 0x0131
    case SYS_clock_adjtime: return "sys_clock_adjtime";
  #endif

  #ifdef SYS_syncfs                     // 306, 0x0132
    case SYS_syncfs: return "sys_syncfs";
  #endif

  #ifdef SYS_sendmmsg                   // 307, 0x0133
    case SYS_sendmmsg: return "sys_sendmmsg";
  #endif

  #ifdef SYS_setns                      // 308, 0x0134
    case SYS_setns: return "sys_setns";
  #endif

  #ifdef SYS_getcpu                     // 309, 0x0135
    case SYS_getcpu: return "sys_getcpu";
  #endif

  #ifdef SYS_process_vm_readv           // 310, 0x0136
    case SYS_process_vm_readv: return "sys_process_vm_readv";
  #endif

  #ifdef SYS_process_vm_writev          // 311, 0x0137
    case SYS_process_vm_writev: return "sys_process_vm_writev";
  #endif

  #ifdef SYS_kcmp                       // 312, 0x0138
    case SYS_kcmp: return "sys_kcmp";
  #endif

  #ifdef SYS_finit_module               // 313, 0x0139
    case SYS_finit_module: return "sys_finit_module";
  #endif

  #ifdef SYS_sched_setattr              // 314, 0x013A
    case SYS_sched_setattr: return "sys_sched_setattr";
  #endif

  #ifdef SYS_sched_getattr              // 315, 0x013B
    case SYS_sched_getattr: return "sys_sched_getattr";
  #endif

  #ifdef SYS_renameat2                  // 316, 0x013C
    case SYS_renameat2: return "sys_renameat2";
  #endif

  #ifdef SYS_seccomp                    // 317, 0x013D
    case SYS_seccomp: return "sys_seccomp";
  #endif

  #ifdef SYS_getrandom                  // 318, 0x013E
    case SYS_getrandom: return "sys_getrandom";
  #endif

  #ifdef SYS_memfd_create               // 319, 0x013F
    case SYS_memfd_create: return "sys_memfd_create";
  #endif

  #ifdef SYS_kexec_file_load            // 320, 0x0140
    case SYS_kexec_file_load: return "sys_kexec_file_load";
  #endif

  #ifdef SYS_bpf                        // 321, 0x0141
    case SYS_bpf: return "sys_bpf";
  #endif

  #ifdef SYS_execveat                   // 322, 0x0142
    case SYS_execveat: return "sys_execveat";
  #endif

  #ifdef SYS_userfaultfd                // 323, 0x0143
    case SYS_userfaultfd: return "sys_userfaultfd";
  #endif

  #ifdef SYS_membarrier                 // 324, 0x0144
    case SYS_membarrier: return "sys_membarrier";
  #endif

  #ifdef SYS_mlock2                     // 325, 0x0145
    case SYS_mlock2: return "sys_mlock2";
  #endif

  #ifdef SYS_copy_file_range            // 326, 0x0146
    case SYS_copy_file_range: return "sys_copy_file_range";
  #endif

  #ifdef SYS_preadv2                    // 327, 0x0147
    case SYS_preadv2: return "sys_preadv2";
  #endif

  #ifdef SYS_pwritev2                   // 328, 0x0148
    case SYS_pwritev2: return "sys_pwritev2";
  #endif

  #ifdef SYS_pkey_mprotect              // 329, 0x0149
    case SYS_pkey_mprotect: return "sys_pkey_mprotect";
  #endif

  #ifdef SYS_pkey_alloc                 // 330, 0x014A
    case SYS_pkey_alloc: return "sys_pkey_alloc";
  #endif

  #ifdef SYS_pkey_free                  // 331, 0x014B
    case SYS_pkey_free: return "sys_pkey_free";
  #endif

  #ifdef SYS_statx                      // 332, 0x014C
    case SYS_statx: return "sys_statx";
  #endif

  #ifdef SYS_io_pgetevents              // 333, 0x014D
    case SYS_io_pgetevents: return "sys_io_pgetevents";
  #endif

  #ifdef SYS_rseq                       // 334, 0x014E
    case SYS_rseq: return "sys_rseq";
  #endif

  #ifdef SYS_pidfd_send_signal          // 424, 0x01A8
    case SYS_pidfd_send_signal: return "sys_pidfd_send_signal";
  #endif

  #ifdef SYS_io_uring_setup             // 425, 0x01A9
    case SYS_io_uring_setup: return "sys_io_uring_setup";
  #endif

  #ifdef SYS_io_uring_enter             // 426, 0x01AA
    case SYS_io_uring_enter: return "sys_io_uring_enter";
  #endif

  #ifdef SYS_io_uring_register          // 427, 0x01AB
    case SYS_io_uring_register: return "sys_io_uring_register";
  #endif

  #ifdef SYS_open_tree                  // 428, 0x01AC
    case SYS_open_tree: return "sys_open_tree";
  #endif

  #ifdef SYS_move_mount                 // 429, 0x01AD
    case SYS_move_mount: return "sys_move_mount";
  #endif

  #ifdef SYS_fsopen                     // 430, 0x01AE
    case SYS_fsopen: return "sys_fsopen";
  #endif

  #ifdef SYS_fsconfig                   // 431, 0x01AF
    case SYS_fsconfig: return "sys_fsconfig";
  #endif

  #ifdef SYS_fsmount                    // 432, 0x01B0
    case SYS_fsmount: return "sys_fsmount";
  #endif

  #ifdef SYS_fspick                     // 433, 0x01B1
    case SYS_fspick: return "sys_fspick";
  #endif

  #ifdef SYS_pidfd_open                 // 434, 0x01B2
    case SYS_pidfd_open: return "sys_pidfd_open";
  #endif

  #ifdef SYS_clone3                     // 435, 0x01B3
    case SYS_clone3: return "sys_clone3";
  #endif

  #ifdef SYS_openat2                    // 437, 0x01B5
    case SYS_openat2: return "sys_openat2";
  #endif

  #ifdef SYS_pidfd_getfd                // 438, 0x01B6
    case SYS_pidfd_getfd: return "sys_pidfd_getfd";
  #endif

  default:
    return "unknown";
  }
}
