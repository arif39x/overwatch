use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{info, warn};





#[derive(Debug, Deserialize)]
struct PoCSpec {
    template_id: String,
    params: HashMap<String, String>,
    expected_signal: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxResult {
    verified: bool,
    signal_observed: Option<String>,
    execution_time_ms: u128,
    sandbox_mode: String,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SynthesizedArtifact {
    script: String,
    expected_signal: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxConfig {
    execution_timeout_secs: u64,
    max_memory_mb: u64,
    max_processes: u64,
    enable_seccomp: bool,
    enable_namespaces: bool,
    enable_network: bool,
    sandbox_mode: SandboxMode,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            execution_timeout_secs: 30,
            max_memory_mb: 256,
            max_processes: 16,
            enable_seccomp: true,
            enable_namespaces: true,
            enable_network: false,
            sandbox_mode: SandboxMode::Namespace,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum SandboxMode {
    Namespace,
    Wasm,
    Legacy,
}





mod seccomp {
    use libc;

    
    const SYS_READ: i64 = 0;
    const SYS_WRITE: i64 = 1;
    const SYS_OPEN: i64 = 2;
    const SYS_CLOSE: i64 = 3;
    const SYS_STAT: i64 = 4;
    const SYS_FSTAT: i64 = 5;
    const SYS_LSTAT: i64 = 6;
    const SYS_POLL: i64 = 7;
    const SYS_LSEEK: i64 = 8;
    const SYS_MMAP: i64 = 9;
    const SYS_MPROTECT: i64 = 10;
    const SYS_MUNMAP: i64 = 11;
    const SYS_BRK: i64 = 12;
    const SYS_RT_SIGACTION: i64 = 13;
    const SYS_RT_SIGPROCMASK: i64 = 14;
    const SYS_RT_SIGRETURN: i64 = 15;
    const SYS_IOCTL: i64 = 16;
    const SYS_PREAD64: i64 = 17;
    const SYS_PWRITE64: i64 = 18;
    const SYS_READV: i64 = 19;
    const SYS_WRITEV: i64 = 20;
    const SYS_ACCESS: i64 = 21;
    const SYS_PIPE: i64 = 22;
    const SYS_SELECT: i64 = 23;
    const SYS_SCHED_YIELD: i64 = 24;
    const SYS_MREMAP: i64 = 25;
    const SYS_MSYNC: i64 = 26;
    const SYS_MINCORE: i64 = 27;
    const SYS_MADVISE: i64 = 28;
    const SYS_SHMGET: i64 = 29;
    const SYS_SHMAT: i64 = 30;
    const SYS_SHMCTL: i64 = 32;
    const SYS_DUP: i64 = 33;
    const SYS_DUP2: i64 = 34;
    const SYS_PAUSE: i64 = 35;
    const SYS_NANOSLEEP: i64 = 36;
    const SYS_GETITIMER: i64 = 37;
    const SYS_ALARM: i64 = 38;
    const SYS_SETITIMER: i64 = 38;
    const SYS_GETPID: i64 = 39;
    const SYS_SENDFILE: i64 = 40;
    const SYS_SOCKET: i64 = 41;
    const SYS_CONNECT: i64 = 42;
    const SYS_ACCEPT: i64 = 43;
    const SYS_SENDTO: i64 = 44;
    const SYS_RECVFROM: i64 = 45;
    const SYS_SENDMSG: i64 = 46;
    const SYS_RECVMSG: i64 = 47;
    const SYS_SHUTDOWN: i64 = 48;
    const SYS_BIND: i64 = 49;
    const SYS_LISTEN: i64 = 50;
    const SYS_GETSOCKNAME: i64 = 51;
    const SYS_GETPEERNAME: i64 = 52;
    const SYS_SOCKETPAIR: i64 = 53;
    const SYS_SETSOCKOPT: i64 = 54;
    const SYS_GETSOCKOPT: i64 = 55;
    const SYS_CLONE: i64 = 56;
    const SYS_FORK: i64 = 57;
    const SYS_VFORK: i64 = 58;
    const SYS_EXECVE: i64 = 59;
    const SYS_EXIT: i64 = 60;
    const SYS_WAIT4: i64 = 61;
    const SYS_KILL: i64 = 62;
    const SYS_UNAME: i64 = 63;
    const SYS_SEMGET: i64 = 64;
    const SYS_SEMOP: i64 = 65;
    const SYS_SEMCTL: i64 = 66;
    const SYS_FCNTL: i64 = 72;
    const SYS_FLOCK: i64 = 73;
    const SYS_FSYNC: i64 = 74;
    const SYS_FDATASYNC: i64 = 75;
    const SYS_TRUNCATE: i64 = 76;
    const SYS_FTRUNCATE: i64 = 77;
    const SYS_GETDENTS: i64 = 78;
    const SYS_GETCWD: i64 = 79;
    const SYS_CHDIR: i64 = 80;
    const SYS_FCHDIR: i64 = 81;
    const SYS_RENAME: i64 = 82;
    const SYS_MKDIR: i64 = 83;
    const SYS_RMDIR: i64 = 84;
    const SYS_CREAT: i64 = 85;
    const SYS_LINK: i64 = 86;
    const SYS_UNLINK: i64 = 87;
    const SYS_SYMLINK: i64 = 88;
    const SYS_READLINK: i64 = 89;
    const SYS_CHMOD: i64 = 90;
    const SYS_FCHMOD: i64 = 91;
    const SYS_CHOWN: i64 = 92;
    const SYS_FCHOWN: i64 = 93;
    const SYS_LCHOWN: i64 = 94;
    const SYS_UMASK: i64 = 95;
    const SYS_GETTIMEOFDAY: i64 = 96;
    const SYS_GETRLIMIT: i64 = 97;
    const SYS_GETRUSAGE: i64 = 98;
    const SYS_SYSINFO: i64 = 99;
    const SYS_TIMES: i64 = 100;
    const SYS_PTRACE: i64 = 101;
    const SYS_GETUID: i64 = 102;
    const SYS_SYSLOG: i64 = 103;
    const SYS_GETGID: i64 = 104;
    const SYS_SETUID: i64 = 105;
    const SYS_SETGID: i64 = 106;
    const SYS_GETEUID: i64 = 107;
    const SYS_GETEGID: i64 = 108;
    const SYS_SETPGID: i64 = 109;
    const SYS_GETPPID: i64 = 110;
    const SYS_GETPGRP: i64 = 111;
    const SYS_SETSID: i64 = 112;
    const SYS_SETREUID: i64 = 113;
    const SYS_SETREGID: i64 = 114;
    const SYS_GETGROUPS: i64 = 115;
    const SYS_SETGROUPS: i64 = 116;
    const SYS_SETRESUID: i64 = 117;
    const SYS_GETRESUID: i64 = 118;
    const SYS_SETRESGID: i64 = 119;
    const SYS_GETRESGID: i64 = 120;
    const SYS_GETPGID: i64 = 121;
    const SYS_SETFSUID: i64 = 122;
    const SYS_SETFSGID: i64 = 123;
    const SYS_GETSID: i64 = 124;
    const SYS_CAPGET: i64 = 125;
    const SYS_CAPSET: i64 = 126;
    const SYS_RT_SIGPENDING: i64 = 127;
    const SYS_RT_SIGTIMEDWAIT: i64 = 128;
    const SYS_RT_SIGQUEUEINFO: i64 = 129;
    const SYS_RT_SIGSUSPEND: i64 = 130;
    const SYS_SIGALTSTACK: i64 = 131;
    const SYS_UTIME: i64 = 132;
    const SYS_MKNOD: i64 = 133;
    const SYS_USELIB: i64 = 134;
    const SYS_PERSONALITY: i64 = 135;
    const SYS_USTAT: i64 = 136;
    const SYS_STATFS: i64 = 137;
    const SYS_FSTATFS: i64 = 138;
    const SYS_SYSFS: i64 = 139;
    const SYS_GETPRIORITY: i64 = 140;
    const SYS_SETPRIORITY: i64 = 141;
    const SYS_SCHED_SETPARAM: i64 = 142;
    const SYS_SCHED_GETPARAM: i64 = 143;
    const SYS_SCHED_SETSCHEDULER: i64 = 144;
    const SYS_SCHED_GETSCHEDULER: i64 = 145;
    const SYS_SCHED_GET_PRIORITY_MAX: i64 = 146;
    const SYS_SCHED_GET_PRIORITY_MIN: i64 = 147;
    const SYS_SCHED_RR_GET_INTERVAL: i64 = 148;
    const SYS_MLOCK: i64 = 149;
    const SYS_MUNLOCK: i64 = 150;
    const SYS_MLOCKALL: i64 = 151;
    const SYS_MUNLOCKALL: i64 = 152;
    const SYS_VHANGUP: i64 = 153;
    const SYS_MODIFY_LDT: i64 = 154;
    const SYS_PIVOT_ROOT: i64 = 155;
    const SYS__SYSCTL: i64 = 156;
    const SYS_PRCTL: i64 = 157;
    const SYS_ARCH_PRCTL: i64 = 158;
    const SYS_ADJTIMEX: i64 = 159;
    const SYS_SETRLIMIT: i64 = 160;
    const SYS_CHROOT: i64 = 161;
    const SYS_SYNC: i64 = 162;
    const SYS_ACCT: i64 = 163;
    const SYS_SETTIMEOFDAY: i64 = 164;
    const SYS_MOUNT: i64 = 165;
    const SYS_UMOUNT2: i64 = 166;
    const SYS_SWAPON: i64 = 167;
    const SYS_SWAPOFF: i64 = 168;
    const SYS_REBOOT: i64 = 169;
    const SYS_SETHOSTNAME: i64 = 170;
    const SYS_SETDOMAINNAME: i64 = 171;
    const SYS_IOPL: i64 = 172;
    const SYS_IOPERM: i64 = 173;
    const SYS_CREATE_MODULE: i64 = 174;
    const SYS_INIT_MODULE: i64 = 175;
    const SYS_DELETE_MODULE: i64 = 176;
    const SYS_GET_KERNEL_SYMS: i64 = 177;
    const SYS_QUERY_MODULE: i64 = 178;
    const SYS_QUOTACTL: i64 = 179;
    const SYS_NFSSERVCTL: i64 = 180;
    const SYS_GETPMSG: i64 = 181;
    const SYS_PUTPMSG: i64 = 182;
    const SYS_AFS_SYSCALL: i64 = 183;
    const SYS_TUXCALL: i64 = 184;
    const SYS_SECURITY: i64 = 185;
    const SYS_GETTID: i64 = 186;
    const SYS_READAHEAD: i64 = 187;
    const SYS_SETXATTR: i64 = 188;
    const SYS_LSETXATTR: i64 = 189;
    const SYS_FSETXATTR: i64 = 190;
    const SYS_GETXATTR: i64 = 191;
    const SYS_LGETXATTR: i64 = 192;
    const SYS_FGETXATTR: i64 = 193;
    const SYS_LISTXATTR: i64 = 194;
    const SYS_LLISTXATTR: i64 = 195;
    const SYS_FLISTXATTR: i64 = 196;
    const SYS_REMOVEXATTR: i64 = 197;
    const SYS_LREMOVEXATTR: i64 = 198;
    const SYS_FREMOVEXATTR: i64 = 199;
    const SYS_TKILL: i64 = 200;
    const SYS_TIME: i64 = 201;
    const SYS_FUTEX: i64 = 202;
    const SYS_SCHED_SETAFFINITY: i64 = 203;
    const SYS_SCHED_GETAFFINITY: i64 = 204;
    const SYS_SET_THREAD_AREA: i64 = 205;
    const SYS_IO_SETUP: i64 = 206;
    const SYS_IO_DESTROY: i64 = 207;
    const SYS_IO_GETEVENTS: i64 = 208;
    const SYS_IO_SUBMIT: i64 = 209;
    const SYS_IO_CANCEL: i64 = 210;
    const SYS_GET_THREAD_AREA: i64 = 211;
    const SYS_LOOKUP_DCOOKIE: i64 = 212;
    const SYS_EPOLL_CREATE: i64 = 213;
    const SYS_EPOLL_CTL_OLD: i64 = 214;
    const SYS_EPOLL_WAIT_OLD: i64 = 215;
    const SYS_REMAP_FILE_PAGES: i64 = 216;
    const SYS_GETDENTS64: i64 = 217;
    const SYS_SET_TID_ADDRESS: i64 = 218;
    const SYS_RESTART_SYSCALL: i64 = 219;
    const SYS_SEMTIMEDOP: i64 = 220;
    const SYS_FADVISE64: i64 = 221;
    const SYS_TIMER_CREATE: i64 = 222;
    const SYS_TIMER_SETTIME: i64 = 223;
    const SYS_TIMER_GETTIME: i64 = 224;
    const SYS_TIMER_GETOVERRUN: i64 = 225;
    const SYS_TIMER_DELETE: i64 = 226;
    const SYS_CLOCK_SETTIME: i64 = 227;
    const SYS_CLOCK_GETTIME: i64 = 228;
    const SYS_CLOCK_GETRES: i64 = 229;
    const SYS_CLOCK_NANOSLEEP: i64 = 230;
    const SYS_EXIT_GROUP: i64 = 231;
    const SYS_EPOLL_WAIT: i64 = 232;
    const SYS_EPOLL_CTL: i64 = 233;
    const SYS_TGKILL: i64 = 234;
    const SYS_UTIMES: i64 = 235;
    const SYS_VSERVER: i64 = 236;
    const SYS_MBIND: i64 = 237;
    const SYS_SET_MEMPOLICY: i64 = 238;
    const SYS_GET_MEMPOLICY: i64 = 239;
    const SYS_MQ_OPEN: i64 = 240;
    const SYS_MQ_UNLINK: i64 = 241;
    const SYS_MQ_TIMEDSEND: i64 = 242;
    const SYS_MQ_TIMEDRECEIVE: i64 = 243;
    const SYS_MQ_NOTIFY: i64 = 244;
    const SYS_MQ_GETSETATTR: i64 = 245;
    const SYS_KEXEC_LOAD: i64 = 246;
    const SYS_WAITID: i64 = 247;
    const SYS_ADD_KEY: i64 = 248;
    const SYS_REQUEST_KEY: i64 = 249;
    const SYS_KEYCTL: i64 = 250;
    const SYS_IOPRIO_SET: i64 = 251;
    const SYS_IOPRIO_GET: i64 = 252;
    const SYS_INOTIFY_INIT: i64 = 253;
    const SYS_INOTIFY_ADD_WATCH: i64 = 254;
    const SYS_INOTIFY_RM_WATCH: i64 = 255;
    const SYS_MIGRATE_PAGES: i64 = 256;
    const SYS_OPENAT: i64 = 257;
    const SYS_MKDIRAT: i64 = 258;
    const SYS_MKNODAT: i64 = 259;
    const SYS_FCHOWNAT: i64 = 260;
    const SYS_FUTIMESAT: i64 = 261;
    const SYS_NEWFSTATAT: i64 = 262;
    const SYS_UNLINKAT: i64 = 263;
    const SYS_RENAMEAT: i64 = 264;
    const SYS_LINKAT: i64 = 265;
    const SYS_SYMLINKAT: i64 = 266;
    const SYS_READLINKAT: i64 = 267;
    const SYS_FCHMODAT: i64 = 268;
    const SYS_FACCESSAT: i64 = 269;
    const SYS_PSELECT6: i64 = 270;
    const SYS_PPOLL: i64 = 271;
    const SYS_UNSHARE: i64 = 272;
    const SYS_SET_ROBUST_LIST: i64 = 273;
    const SYS_GET_ROBUST_LIST: i64 = 274;
    const SYS_SPLICE: i64 = 275;
    const SYS_TEE: i64 = 276;
    const SYS_SYNC_FILE_RANGE: i64 = 277;
    const SYS_VMSPLICE: i64 = 278;
    const SYS_MOVE_PAGES: i64 = 279;
    const SYS_UTIMENSAT: i64 = 280;
    const SYS_EPOLL_PWAIT: i64 = 281;
    const SYS_SIGNALFD: i64 = 282;
    const SYS_TIMERFD_CREATE: i64 = 283;
    const SYS_EVENTFD: i64 = 284;
    const SYS_FALLOCATE: i64 = 285;
    const SYS_TIMERFD_SETTIME: i64 = 286;
    const SYS_TIMERFD_GETTIME: i64 = 287;
    const SYS_ACCEPT4: i64 = 288;
    const SYS_SIGNALFD4: i64 = 289;
    const SYS_EVENTFD2: i64 = 290;
    const SYS_EPOLL_CREATE1: i64 = 291;
    const SYS_DUP3: i64 = 292;
    const SYS_PIPE2: i64 = 293;
    const SYS_INOTIFY_INIT1: i64 = 294;
    const SYS_PREADV: i64 = 295;
    const SYS_PWRITEV: i64 = 296;
    const SYS_RT_TGSIGQUEUEINFO: i64 = 297;
    const SYS_PERF_EVENT_OPEN: i64 = 298;
    const SYS_RECVMMSG: i64 = 299;
    const SYS_FANOTIFY_INIT: i64 = 300;
    const SYS_FANOTIFY_MARK: i64 = 301;
    const SYS_PRLIMIT64: i64 = 302;
    const SYS_NAME_TO_HANDLE_AT: i64 = 303;
    const SYS_OPEN_BY_HANDLE_AT: i64 = 304;
    const SYS_CLOCK_ADJTIME: i64 = 305;
    const SYS_SYNCFS: i64 = 306;
    const SYS_SENDMMSG: i64 = 307;
    const SYS_SETNS: i64 = 308;
    const SYS_GETCPU: i64 = 309;
    const SYS_PROCESS_VM_READV: i64 = 310;
    const SYS_PROCESS_VM_WRITEV: i64 = 311;
    const SYS_KCMP: i64 = 312;
    const SYS_FINIT_MODULE: i64 = 313;
    const SYS_SCHED_SETATTR: i64 = 314;
    const SYS_SCHED_GETATTR: i64 = 315;
    const SYS_RENAMEAT2: i64 = 316;
    const SYS_SECCOMP: i64 = 317;
    const SYS_GETRANDOM: i64 = 318;
    const SYS_MEMFD_CREATE: i64 = 319;
    const SYS_KEXEC_FILE_LOAD: i64 = 320;
    const SYS_BPF: i64 = 321;
    const SYS_EXECVEAT: i64 = 322;
    const SYS_USERFAULTFD: i64 = 323;
    const SYS_MEMBARRIER: i64 = 324;
    const SYS_MLOCK2: i64 = 325;
    const SYS_COPY_FILE_RANGE: i64 = 326;
    const SYS_PREADV2: i64 = 327;
    const SYS_PWRITEV2: i64 = 328;

    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;

    const SECCOMP_RET_KILL: u32 = 0x00000000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

    
    #[repr(C)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    fn bpf_stmt(code: u16, k: u32) -> sock_filter {
        sock_filter { code, jt: 0, jf: 0, k }
    }

    fn bpf_jump(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
        sock_filter { code, jt, jf, k }
    }

    
    const BPF_LD: u16 = 0x00;
    const BPF_LDX: u16 = 0x01;
    const BPF_ALU: u16 = 0x04;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;
    const BPF_K: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JEQ: u16 = 0x10;
    const BPF_JSET: u16 = 0x40;

    
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;

    
    const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

    fn allow_syscall(sysno: i64) -> Vec<sock_filter> {
        vec![
            bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_NR_OFFSET),
            bpf_jump(BPF_JMP + BPF_JEQ, 0, 1, sysno as u32),
            bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        ]
    }

    
    
    fn build_bpf(allowed: &[i64]) -> Vec<sock_filter> {
        let mut prog = Vec::new();

        
        prog.push(bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        prog.push(bpf_jump(BPF_JMP + BPF_JEQ, 0, 1, AUDIT_ARCH_X86_64));
        prog.push(bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_KILL));

        
        prog.push(bpf_stmt(BPF_LD + BPF_W + BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        
        let mut sorted = allowed.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        prog.extend(build_binary_search(&sorted, 0, sorted.len()));

        
        prog.push(bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_KILL));
        prog
    }

    fn build_binary_search(sorted: &[i64], lo: usize, hi: usize) -> Vec<sock_filter> {
        if lo >= hi || lo >= sorted.len() {
            return vec![];
        }

        let mid = lo + (hi - lo) / 2;
        let val = sorted[mid] as u32;

        let mut prog = Vec::new();

        if hi - lo == 1 {
            
            prog.push(bpf_jump(BPF_JMP + BPF_JEQ, 0, 1, val));
            prog.push(bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
        } else {
            
            let _left_count = mid - lo;
            let _right_count = hi - mid;
            let _left_insns: usize = if _left_count == 1 { 2 } else { estimate_insn_count(sorted, lo, mid) };
            let _jt = (_left_insns + 1) as u8;

            
            prog.push(bpf_jump(BPF_JMP + BPF_JEQ, 0, 0, val));
            prog.push(bpf_stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));

            
            prog.extend(build_binary_search(sorted, lo, mid));

            
            let _right_insns = estimate_insn_count(sorted, mid + 1, hi);
            prog.extend(build_binary_search(sorted, mid + 1, hi));
        }

        prog
    }

    
    fn estimate_insn_count(sorted: &[i64], lo: usize, hi: usize) -> usize {
        if lo >= hi || lo >= sorted.len() {
            return 0;
        }
        let count = hi - lo;
        if count == 1 {
            2 
        } else {
            
            let mid = lo + (hi - lo) / 2;
            3 + estimate_insn_count(sorted, lo, mid)
                .max(estimate_insn_count(sorted, mid + 1, hi))
        }
    }

    
    
    pub fn default_allowlist() -> Vec<i64> {
        vec![
            SYS_READ, SYS_WRITE, SYS_OPEN, SYS_CLOSE,
            SYS_STAT, SYS_FSTAT, SYS_LSTAT,
            SYS_POLL, SYS_LSEEK, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP, SYS_BRK,
            SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK, SYS_RT_SIGRETURN,
            SYS_IOCTL, SYS_PREAD64, SYS_PWRITE64, SYS_READV, SYS_WRITEV,
            SYS_ACCESS, SYS_PIPE, SYS_SELECT,
            SYS_SCHED_YIELD, SYS_MREMAP, SYS_MSYNC, SYS_MADVISE,
            SYS_DUP, SYS_DUP2,
            SYS_NANOSLEEP, SYS_CLOCK_GETTIME, SYS_CLOCK_NANOSLEEP,
            SYS_GETPID, SYS_GETTID, SYS_GETTIMEOFDAY,
            SYS_SOCKET, SYS_CONNECT, SYS_ACCEPT, SYS_ACCEPT4,
            SYS_SENDTO, SYS_RECVFROM, SYS_SENDMSG, SYS_RECVMSG,
            SYS_SHUTDOWN, SYS_BIND, SYS_LISTEN,
            SYS_GETSOCKNAME, SYS_GETPEERNAME, SYS_SOCKETPAIR,
            SYS_SETSOCKOPT, SYS_GETSOCKOPT,
            SYS_CLONE, SYS_FORK, SYS_VFORK,
            SYS_EXECVE, SYS_EXIT, SYS_EXIT_GROUP, SYS_WAIT4, SYS_WAITID,
            SYS_KILL, SYS_TGKILL, SYS_TKILL, SYS_UNAME,
            SYS_FCNTL, SYS_FSYNC, SYS_FDATASYNC,
            SYS_GETDENTS64, SYS_GETCWD, SYS_CHDIR,
            SYS_OPENAT, SYS_READLINKAT, SYS_NEWFSTATAT,
            SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT,
            SYS_EVENTFD2, SYS_SIGNALFD4, SYS_TIMERFD_CREATE, SYS_TIMERFD_SETTIME, SYS_TIMERFD_GETTIME,
            SYS_FUTEX, SYS_SET_ROBUST_LIST, SYS_GET_ROBUST_LIST,
            SYS_GETRANDOM, SYS_SCHED_GETAFFINITY, SYS_SCHED_SETAFFINITY,
            SYS_GETRLIMIT, SYS_SETRLIMIT, SYS_PRLIMIT64,
            SYS_READLINK, SYS_LINK, SYS_UNLINK, SYS_UNLINKAT,
            SYS_RENAME, SYS_RENAMEAT,
            SYS_SETITIMER, SYS_GETITIMER,
            SYS_PRCTL, SYS_ARCH_PRCTL,
            SYS_PSELECT6, SYS_PPOLL,
            SYS_SPLICE, SYS_TEE,
            SYS_SENDFILE, SYS_COPY_FILE_RANGE,
            SYS_NEWFSTATAT, SYS_FACCESSAT,
            SYS_SCHED_GETPARAM, SYS_SCHED_SETPARAM,
            SYS_SCHED_GETSCHEDULER, SYS_SCHED_SETSCHEDULER,
            SYS_SCHED_GET_PRIORITY_MAX, SYS_SCHED_GET_PRIORITY_MIN,
            SYS_SCHED_RR_GET_INTERVAL,
            SYS_UMASK, SYS_SYSINFO,
            SYS_GETUID, SYS_GETGID, SYS_GETEUID, SYS_GETEGID,
            SYS_GETPPID, SYS_GETPGRP, SYS_GETPGID, SYS_GETSID,
            SYS_GETGROUPS, SYS_SETGROUPS,
            SYS_TIME,
            SYS_MEMFD_CREATE,
        ]
    }

    
    
    pub fn install_filter(allowed: &[i64]) -> Result<(), String> {
        let prog = build_bpf(allowed);

        let sock_fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut sock_filter as *mut libc::sock_filter,
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &sock_fprog as *const libc::sock_fprog,
            )
        };

        if ret != 0 {
            return Err(format!("seccomp() failed: errno={}", unsafe { *libc::__errno_location() }));
        }

        Ok(())
    }

    
    pub fn set_no_new_privs() -> Result<(), String> {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(format!("prctl(PR_SET_NO_NEW_PRIVS) failed: errno={}", unsafe { *libc::__errno_location() }));
        }
        Ok(())
    }
}





mod rlimits {
    use libc;

    pub struct ResourceLimits {
        pub cpu_time_secs: u64,
        pub address_space_mb: u64,
        pub process_count: u64,
        pub file_size_mb: u64,
    }

    impl ResourceLimits {
        pub fn apply(&self) -> Result<(), String> {
            
            let cpu_rlim = libc::rlimit {
                rlim_cur: self.cpu_time_secs,
                rlim_max: self.cpu_time_secs,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu_rlim) } != 0 {
                return Err("setrlimit(RLIMIT_CPU) failed".into());
            }

            
            let as_rlim = libc::rlimit {
                rlim_cur: self.address_space_mb * 1024 * 1024,
                rlim_max: self.address_space_mb * 1024 * 1024,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_AS, &as_rlim) } != 0 {
                return Err("setrlimit(RLIMIT_AS) failed".into());
            }

            
            let nproc_rlim = libc::rlimit {
                rlim_cur: self.process_count,
                rlim_max: self.process_count,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &nproc_rlim) } != 0 {
                return Err("setrlimit(RLIMIT_NPROC) failed".into());
            }

            
            let fsize_rlim = libc::rlimit {
                rlim_cur: self.file_size_mb * 1024 * 1024,
                rlim_max: self.file_size_mb * 1024 * 1024,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &fsize_rlim) } != 0 {
                return Err("setrlimit(RLIMIT_FSIZE) failed".into());
            }

            
            let core_rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_rlim) } != 0 {
                return Err("setrlimit(RLIMIT_CORE) failed".into());
            }

            Ok(())
        }
    }
}





mod namespaces {
    use std::fs;

    
    
    pub fn enter_namespaces(enable_network: bool) -> Result<(), String> {
        let mut flags = nix::sched::CloneFlags::CLONE_NEWNS
            | nix::sched::CloneFlags::CLONE_NEWPID
            | nix::sched::CloneFlags::CLONE_NEWUTS;

        if !enable_network {
            flags |= nix::sched::CloneFlags::CLONE_NEWNET;
        }

        
        let has_user_ns = unsafe { libc::unshare(libc::CLONE_NEWUSER) == 0 };

        
        nix::sched::unshare(flags).map_err(|e| format!("unshare(namespaces) failed: {e}"))?;

        if has_user_ns {
            
            let uid = nix::unistd::getuid();

            
            let uid_map = format!("{} {} 1\n", uid, uid);
            fs::write("/proc/self/uid_map", uid_map.as_bytes())
                .map_err(|e| format!("write uid_map failed: {e}"))?;

            
            fs::write("/proc/self/setgroups", "deny\n".as_bytes())
                .map_err(|e| format!("write setgroups deny failed: {e}"))?;

            
            let gid = nix::unistd::getgid();
            let gid_map = format!("{} {} 1\n", gid, gid);
            fs::write("/proc/self/gid_map", gid_map.as_bytes())
                .map_err(|e| format!("write gid_map failed: {e}"))?;
        }

        Ok(())
    }
}





mod template {
    use sha2::Digest;
    use sha2::Sha256;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    pub struct TemplateEngine {
        template_dir: PathBuf,
        checksums: HashMap<String, String>,
    }

    impl TemplateEngine {
        pub fn new(template_dir: &Path) -> Self {
            let mut engine = Self {
                template_dir: template_dir.to_path_buf(),
                checksums: HashMap::new(),
            };
            engine.load_checksums();
            engine
        }

        fn load_checksums(&mut self) {
            let checksum_path = self.template_dir.join("checksums.sha256");
            let content = match fs::read_to_string(&checksum_path) {
                Ok(c) => c,
                Err(_) => return,
            };

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.splitn(2, "  ").collect();
                if parts.len() == 2 {
                    self.checksums.insert(parts[1].to_string(), parts[0].to_string());
                }
            }
        }

        pub fn verify_integrity(&self, template_id: &str) -> Result<(), String> {
            let filename = format!("{template_id}.py");
            let expected_hash = self.checksums.get(&filename).ok_or_else(|| {
                format!("no checksum for template: {filename}")
            })?;

            let template_path = self.template_dir.join(&filename);
            let content = fs::read(&template_path)
                .map_err(|e| format!("read template {filename}: {e}"))?;

            let mut hasher = Sha256::default();
            hasher.update(&content);
            let actual_hash = hex::encode(hasher.finalize());

            if &actual_hash != expected_hash {
                return Err(format!(
                    "checksum mismatch for {filename}: expected {expected_hash}, got {actual_hash}"
                ));
            }

            Ok(())
        }

        pub fn load(&self, template_id: &str) -> Result<String, String> {
            let filename = format!("{template_id}.py");
            let template_path = self.template_dir.join(&filename);
            fs::read_to_string(&template_path)
                .map_err(|e| format!("load template {filename}: {e}"))
        }

        pub fn substitute(template: &str, params: &HashMap<String, String>) -> String {
            let mut result = template.to_string();
            for (key, value) in params {
                let placeholder = format!("{{{{{key}}}}}");
                result = result.replace(&placeholder, value);
            }
            result
        }

        pub fn synthesize(&self, spec: &super::PoCSpec) -> Result<super::SynthesizedArtifact, String> {
            self.verify_integrity(&spec.template_id)?;
            let template = self.load(&spec.template_id)?;
            let script = Self::substitute(&template, &spec.params);
            Ok(super::SynthesizedArtifact {
                script,
                expected_signal: spec.expected_signal.clone(),
            })
        }
    }
}





mod wasm {
    use std::collections::HashMap;
    use std::time::Instant;

    pub struct WasmRuntime {
        engine: wasmtime::Engine,
        store: wasmtime::Store<()>,
    }

    impl WasmRuntime {
        pub fn new() -> Result<Self, String> {
            let mut config = wasmtime::Config::new();
            config.wasm_memory64(false);
            config.wasm_reference_types(true);
            config.wasm_function_references(true);
            config.consume_fuel(true);

            let engine = wasmtime::Engine::new(&config)
                .map_err(|e| format!("wasmtime Engine::new: {e}"))?;
            let store = wasmtime::Store::new(&engine, ());
            Ok(Self { engine, store })
        }

        
        
        pub fn execute(
            &mut self,
            wasm_bytes: &[u8],
            expected_signal: &str,
            _fuel_limit: u64,
        ) -> Result<(bool, Option<String>, u128), String> {
            let start = Instant::now();

            let module = wasmtime::Module::new(&self.engine, wasm_bytes)
                .map_err(|e| format!("wasmtime Module::new: {e}"))?;

            
            
            

            let instance = wasmtime::Instance::new(&mut self.store, &module, &[])
                .map_err(|e| format!("wasmtime Instance::new: {e}"))?;

            
            let func = match instance.get_export(&mut self.store, "_start") {
                Some(wasmtime::Extern::Func(f)) => f,
                _ => match instance.get_export(&mut self.store, "main") {
                    Some(wasmtime::Extern::Func(f)) => f,
                    _ => return Err("no _start or main export found in WASM module".into()),
                },
            };

            let mut results = [wasmtime::Val::I32(1)];
            func.call(&mut self.store, &[], &mut results)
                .map_err(|e| format!("wasmtime call: {e}"))?;

            let elapsed = start.elapsed().as_millis();

            
            let signal_found = if let Some(mem) = instance
                .get_export(&mut self.store, "memory")
                .and_then(|e| e.into_memory())
            {
                let data = mem.data(&self.store);
                let output = String::from_utf8_lossy(data).to_string();
                output.contains(expected_signal)
            } else {
                results[0].i32() == Some(0)
            };

            Ok((signal_found, None, elapsed))
        }
    }
}





async fn execute_python(
    script: &str,
    expected_signal: &str,
    config: &SandboxConfig,
) -> SandboxResult {
    let start = Instant::now();

    
    let tmp_dir = std::env::temp_dir().join(format!("overwatch_poc_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp_dir).ok();
    let script_path = tmp_dir.join("poc_script.py");
    if let Err(e) = fs::write(&script_path, script) {
        return SandboxResult {
            verified: false,
            signal_observed: None,
            execution_time_ms: start.elapsed().as_millis(),
            sandbox_mode: format!("{:?}", config.sandbox_mode),
            error: Some(format!("write script: {e}")),
        };
    }

    
    let mut cmd = Command::new("python3");
    cmd.arg(script_path.to_str().unwrap_or("poc_script.py"));
    cmd.current_dir(&tmp_dir);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("HOME", "/tmp");
    cmd.env("PYTHONIOENCODING", "utf-8");
    cmd.env("PYTHONDONTWRITEBYTECODE", "1");

    
    if config.sandbox_mode == SandboxMode::Namespace && cfg!(target_os = "linux") {
        let timeout_secs = config.execution_timeout_secs;
        let mem_mb = config.max_memory_mb;
        let max_procs = config.max_processes;
        let enable_sec = config.enable_seccomp;

        unsafe {
            cmd.pre_exec(move || {
                
                if let Err(e) = seccomp::set_no_new_privs() {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }

                
                let limits = rlimits::ResourceLimits {
                    cpu_time_secs: timeout_secs,
                    address_space_mb: mem_mb,
                    process_count: max_procs,
                    file_size_mb: 10,
                };
                if let Err(e) = limits.apply() {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                }

                
                if enable_sec {
                    let allowed = seccomp::default_allowlist();
                    if let Err(e) = seccomp::install_filter(&allowed) {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                    }
                }

                Ok(())
            });
        }
    }

    
    let result = match timeout(Duration::from_secs(config.execution_timeout_secs + 5), cmd.output()).await {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = format!("{stdout}\n{stderr}");
            let elapsed = start.elapsed().as_millis();

            let verified = combined.contains(expected_signal);
            let signal = if verified {
                Some(combined.clone())
            } else {
                None
            };

            let err = if !verified && output.status.code().unwrap_or(1) != 0 {
                Some(format!("exit code {:?}, stderr: {stderr}", output.status.code()))
            } else {
                None
            };

            SandboxResult {
                verified,
                signal_observed: signal,
                execution_time_ms: elapsed,
                sandbox_mode: format!("{:?}", config.sandbox_mode),
                error: err,
            }
        }
        Ok(Err(e)) => SandboxResult {
            verified: false,
            signal_observed: None,
            execution_time_ms: start.elapsed().as_millis(),
            sandbox_mode: format!("{:?}", config.sandbox_mode),
            error: Some(format!("execution error: {e}")),
        },
        Err(_elapsed) => {
            
            let _ = std::process::Command::new("pkill")
                .args(["-f", "poc_script.py"])
                .output();

            SandboxResult {
                verified: false,
                signal_observed: None,
                execution_time_ms: (config.execution_timeout_secs * 1000) as u128,
                sandbox_mode: format!("{:?}", config.sandbox_mode),
                error: Some("execution timed out".into()),
            }
        }
    };

    
    let _ = fs::remove_dir_all(&tmp_dir);

    result
}





async fn consume_redis_queue(config: &SandboxConfig) -> Result<(), Box<dyn std::error::Error>> {
    let redis_url = std::env::var("OVERWATCH_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());

    let client = redis::Client::open(redis_url.as_str())?;
    let mut conn = client.get_async_connection().await?;

    info!("Listening on Redis queue 'overwatch:poc:queue'...");

    loop {
        let result: Option<String> = conn
            .brpop("overwatch:poc:queue", 5.0)
            .await
            .map(|v: (String, String)| Some(v.1))
            .unwrap_or(None);

        if let Some(payload) = result {
            match serde_json::from_str::<PoCSpec>(&payload) {
                Ok(spec) => {
                    let result = process_spec(&spec, config).await;
                    let _: () = conn
                        .lpush("overwatch:poc:results", serde_json::to_string(&result).unwrap())
                        .await?;
                    info!("Processed PoC {} — verified: {}", spec.template_id, result.verified);
                }
                Err(e) => {
                    warn!("Invalid PoCSpec from queue: {e}");
                }
            }
        }
    }
}

async fn process_spec(spec: &PoCSpec, config: &SandboxConfig) -> SandboxResult {
    let start = Instant::now();
    let templates_dir = PathBuf::from(
        std::env::var("OVERWATCH_TEMPLATES_DIR")
            .unwrap_or_else(|_| "templates".to_string()),
    );

    let engine = template::TemplateEngine::new(&templates_dir);

    
    if let Err(e) = engine.verify_integrity(&spec.template_id) {
        return SandboxResult {
            verified: false,
            signal_observed: None,
            execution_time_ms: start.elapsed().as_millis(),
            sandbox_mode: format!("{:?}", config.sandbox_mode),
            error: Some(format!("integrity check failed: {e}")),
        };
    }

    
    let artifact = match engine.synthesize(spec) {
        Ok(a) => a,
        Err(e) => {
            return SandboxResult {
                verified: false,
                signal_observed: None,
                execution_time_ms: start.elapsed().as_millis(),
                sandbox_mode: format!("{:?}", config.sandbox_mode),
                error: Some(format!("synthesis failed: {e}")),
            };
        }
    };

    
    if config.sandbox_mode == SandboxMode::Wasm {
        
        
        let _runtime = match wasm::WasmRuntime::new() {
            Ok(r) => r,
            Err(e) => {
                return SandboxResult {
                    verified: false,
                    signal_observed: None,
                    execution_time_ms: start.elapsed().as_millis(),
                    sandbox_mode: "Wasm".into(),
                    error: Some(format!("WASM runtime init: {e}")),
                };
            }
        };

        
        
        info!("WASM mode requested but no WASM template available; falling through");
    }

    
    execute_python(&artifact.script, &spec.expected_signal, config).await
}





async fn run_single(config: &SandboxConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let spec: PoCSpec = serde_json::from_str(&input)?;
    let result = process_spec(&spec, config).await;
    let output = serde_json::to_string(&result)?;
    println!("{output}");
    Ok(())
}





fn run_verify(_config: &SandboxConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let spec: PoCSpec = serde_json::from_str(&input)?;
    let templates_dir = PathBuf::from(
        std::env::var("OVERWATCH_TEMPLATES_DIR")
            .unwrap_or_else(|_| "templates".to_string()),
    );

    let engine = template::TemplateEngine::new(&templates_dir);

    match engine.synthesize(&spec) {
        Ok(artifact) => {
            let output = serde_json::to_string(&artifact)?;
            println!("{output}");
            Ok(())
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}





#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let dangerous = args.contains(&"--dangerous".to_string())
        || std::env::var("OVERWATCH_DANGEROUS_OK").is_ok();

    
    let config = SandboxConfig {
        execution_timeout_secs: std::env::var("OVERWATCH_EXECUTION_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        max_memory_mb: std::env::var("OVERWATCH_MAX_MEMORY_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256),
        max_processes: std::env::var("OVERWATCH_MAX_PROCESSES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16),
        enable_seccomp: !std::env::var("OVERWATCH_DISABLE_SECCOMP").is_ok(),
        enable_namespaces: !std::env::var("OVERWATCH_DISABLE_NAMESPACES").is_ok(),
        enable_network: std::env::var("OVERWATCH_ENABLE_NETWORK").is_ok(),
        sandbox_mode: match std::env::var("OVERWATCH_SANDBOX_MODE")
            .unwrap_or_default()
            .as_str()
        {
            "wasm" => SandboxMode::Wasm,
            "legacy" => SandboxMode::Legacy,
            _ => SandboxMode::Namespace,
        },
    };

    
    info!(
        "Overwatch PoC Sandbox v{} | dangerous={} | mode={:?} | timeout={}s | seccomp={} | namespaces={} | network={} | memory={}MB",
        env!("CARGO_PKG_VERSION"),
        dangerous,
        config.sandbox_mode,
        config.execution_timeout_secs,
        config.enable_seccomp,
        config.enable_namespaces,
        config.enable_network,
        config.max_memory_mb,
    );

    if !dangerous {
        warn!("⚠  Running in SAFE mode. Use --dangerous or OVERWATCH_DANGEROUS_OK to enable execution.");
    }

    
    let mode = if args.len() > 1 && !args[1].starts_with("--") {
        args[1].clone()
    } else if args.len() > 2 && !args[2].starts_with("--") {
        args[2].clone()
    } else {
        "--all".to_string()
    };

    match mode.as_str() {
        "--single" | "-s" => {
            if !dangerous {
                
                run_verify(&config)?;
            } else {
                run_single(&config).await?;
            }
        }
        "--verify" | "-v" => {
            run_verify(&config)?;
        }
        "--daemon" | "-d" => {
            if !dangerous {
                eprintln!("ERROR: Daemon mode requires --dangerous or OVERWATCH_DANGEROUS_OK");
                std::process::exit(1);
            }
            consume_redis_queue(&config).await?;
        }
        "--wasm" | "-w" => {
            let mut wasm_config = SandboxConfig { sandbox_mode: SandboxMode::Wasm, ..config };
            if dangerous {
                run_single(&wasm_config).await?;
            } else {
                run_verify(&wasm_config)?;
            }
        }
        "--legacy" | "-l" => {
            let legacy_config = SandboxConfig {
                sandbox_mode: SandboxMode::Legacy,
                enable_seccomp: false,
                enable_namespaces: false,
                ..config
            };
            if dangerous {
                run_single(&legacy_config).await?;
            } else {
                run_verify(&legacy_config)?;
            }
        }
        "--all" | "-a" | _ => {
            
            if dangerous {
                run_single(&config).await?;
            } else {
                
                let mut input = String::new();
                io::stdin().read_to_string(&mut input)?;
                let spec: PoCSpec = serde_json::from_str(&input)?;
                let templates_dir = PathBuf::from(
                std::env::var("OVERWATCH_TEMPLATES_DIR")
                    .unwrap_or_else(|_| "templates".to_string()),
                );
                let engine = template::TemplateEngine::new(&templates_dir);
                match engine.synthesize(&spec) {
                    Ok(artifact) => {
                        let output = serde_json::to_string(&artifact)?;
                        println!("{output}");
                        eprintln!("INFO: Template '{}' synthesized ({} bytes). Use --dangerous to execute.", spec.template_id, artifact.script.len());
                    }
                    Err(e) => {
                        eprintln!("ERROR: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    Ok(())
}
