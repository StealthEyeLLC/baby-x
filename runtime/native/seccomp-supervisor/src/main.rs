use std::env;
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::raw::{c_int, c_long, c_ulong};
use std::process;

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const SECCOMP_SET_MODE_FILTER: c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_ulong = 1 << 3;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SYS_SECCOMP: c_long = 317;
const SYS_GETPID: u32 = 39;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
#[repr(C)]
struct SockFprog { len: u16, filter: *mut SockFilter }
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData { nr: i32, arch: u32, instruction_pointer: u64, args: [u64; 6] }
#[repr(C)]
struct SeccompNotif { id: u64, pid: u32, flags: u32, data: SeccompData }
#[repr(C)]
struct SeccompNotifResp { id: u64, val: i64, error: i32, flags: u32 }

unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}

const fn ioc(dir: c_ulong, kind: c_ulong, nr: c_ulong, size: c_ulong) -> c_ulong {
    (dir << 30) | (size << 16) | (kind << 8) | nr
}
const IOC_READ_WRITE: c_ulong = 3;
const SECCOMP_IOC_MAGIC: c_ulong = b'!' as c_ulong;
const NOTIF_RECV: c_ulong = ioc(IOC_READ_WRITE, SECCOMP_IOC_MAGIC, 0, size_of::<SeccompNotif>() as c_ulong);
const NOTIF_SEND: c_ulong = ioc(IOC_READ_WRITE, SECCOMP_IOC_MAGIC, 1, size_of::<SeccompNotifResp>() as c_ulong);
const USER_NOTIF_FLAG_CONTINUE: u32 = 1;

fn listener() -> io::Result<c_int> {
    let mut filter = [
        SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 },
        SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 1, k: SYS_GETPID },
        SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF },
        SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
    ];
    let program = SockFprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
    let no_new_privs = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs != 0 { return Err(io::Error::last_os_error()); }
    let fd = unsafe { syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program as *const SockFprog) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(fd as c_int)
}

fn probe() -> io::Result<()> {
    let fd = listener()?;
    let child = unsafe { fork() };
    if child < 0 { return Err(io::Error::last_os_error()); }
    if child == 0 {
        let _ = unsafe { libc_getpid() };
        process::exit(0);
    }
    let mut notification: SeccompNotif = unsafe { zeroed() };
    if unsafe { ioctl(fd, NOTIF_RECV, &mut notification as *mut SeccompNotif as *mut c_void) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let response = SeccompNotifResp { id: notification.id, val: 0, error: 0, flags: USER_NOTIF_FLAG_CONTINUE };
    if unsafe { ioctl(fd, NOTIF_SEND, &response as *const SeccompNotifResp as *const c_void) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut status = 0;
    unsafe { waitpid(child, &mut status, 0); close(fd); }
    println!("{{\"ok\":true,\"notificationPid\":{},\"syscall\":{}}}", notification.pid, notification.data.nr);
    Ok(())
}

unsafe fn libc_getpid() -> c_int { unsafe { syscall(SYS_GETPID as c_long) as c_int } }

fn main() {
    let action = env::args().nth(1).unwrap_or_else(|| "describe".to_string());
    let result = match action.as_str() {
        "describe" => { println!("{{\"product\":\"baby-x-seccomp-supervisor\",\"realUserNotification\":true,\"actions\":[\"describe\",\"probe\"]}}"); Ok(()) },
        "probe" => probe(),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown action")),
    };
    if let Err(error) = result {
        eprintln!("{{\"ok\":false,\"error\":{:?}}}", error.to_string());
        process::exit(1);
    }
}
