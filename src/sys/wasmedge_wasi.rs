// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;
#[cfg(not(target_os = "redox"))]
use std::io::IoSlice;
use std::marker::PhantomData;
use std::mem::{self, size_of, MaybeUninit};
use std::net::Shutdown;
use std::net::{Ipv4Addr, Ipv6Addr};

use std::os::wasi::ffi::OsStrExt;
use std::os::wasi::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};
use std::{io, slice};

use libc::ssize_t;
use libc::{in6_addr, in_addr};

use crate::{Domain, Protocol, SockAddr, Type};
use crate::{MsgHdr, MsgHdrMut, RecvFlags};

pub(crate) use libc::c_int;

// Used in `Domain`.
pub(crate) const AF_UNSPEC: c_int = wasmedge_wasi_socket::socket::AddressFamily::Unspec as c_int;
pub(crate) const AF_INET: c_int = wasmedge_wasi_socket::socket::AddressFamily::Inet4 as c_int;
pub(crate) const AF_INET6: c_int = wasmedge_wasi_socket::socket::AddressFamily::Inet6 as c_int;
// Used in `Type`.
pub(crate) const SOCK_STREAM: c_int = wasmedge_wasi_socket::socket::SocketType::Stream as c_int;
pub(crate) const SOCK_DGRAM: c_int = wasmedge_wasi_socket::socket::SocketType::Datagram as c_int;

// Used in `Protocol`.
pub(crate) const IPPROTO_TCP: c_int = wasmedge_wasi_socket::socket::AiProtocol::IPProtoTCP as c_int;
pub(crate) const IPPROTO_UDP: c_int = wasmedge_wasi_socket::socket::AiProtocol::IPProtoUDP as c_int;
// Used in `SockAddr`.

// Used in `RecvFlags`.

// Used in `Socket`.
pub(crate) const MSG_PEEK: c_int = 1 as c_int; // __WASI_RIFLAGS_RECV_PEEK
pub(crate) const MSG_WAITALL: c_int = 2 as c_int; // __WASI_RIFLAGS_RECV_WAITALL
pub(crate) const MSG_TRUNC: c_int = 1 as c_int; // __WASI_RIFLAGS_RECV_WAITALL

pub(crate) const SOL_SOCKET: c_int =
    wasmedge_wasi_socket::socket::SocketOptLevel::SolSocket as c_int;

pub(crate) const SO_REUSEADDR: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoReuseaddr as c_int;
pub(crate) const SO_TYPE: c_int = wasmedge_wasi_socket::socket::SocketOptName::SoType as c_int;
pub(crate) const SO_ERROR: c_int = wasmedge_wasi_socket::socket::SocketOptName::SoError as c_int;
pub(crate) const SO_BROADCAST: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoBroadcast as c_int;
pub(crate) const SO_RCVBUF: c_int = wasmedge_wasi_socket::socket::SocketOptName::SoRcvbuf as c_int;
pub(crate) const SO_RCVTIMEO: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoRcvtimeo as c_int;
pub(crate) const SO_SNDBUF: c_int = wasmedge_wasi_socket::socket::SocketOptName::SoSndbuf as c_int;
pub(crate) const SO_SNDTIMEO: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoSndtimeo as c_int;
pub(crate) const SO_KEEPALIVE: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoKeepalive as c_int;
pub(crate) const SO_OOBINLINE: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoOobinline as c_int;
pub(crate) const SO_LINGER: c_int = wasmedge_wasi_socket::socket::SocketOptName::SoLinger as c_int;
pub(crate) const SO_ACCEPTCONN: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoAcceptconn as c_int;
pub(crate) const SO_BINDTODEVICE: c_int =
    wasmedge_wasi_socket::socket::SocketOptName::SoBindToDevice as c_int;

// See this type in the Windows file.
pub(crate) type Bool = c_int;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

/// Maximum size of a buffer passed to system call like `recv` and `send`.
const MAX_BUF_LEN: usize = ssize_t::MAX as usize;

// TCP_CA_NAME_MAX isn't defined in user space include files(not in libc)
#[cfg(feature = "all")]
const TCP_CA_NAME_MAX: usize = 16;

type IovLen = c_int;

impl_debug!(Domain, self::AF_INET, self::AF_INET6, self::AF_UNSPEC,);

/// Unix only API.
impl Type {
    /// Set `SOCK_NONBLOCK` on the `Type`.
    #[cfg(feature = "all")]
    #[cfg_attr(docsrs, doc(cfg(feature = "all")))]
    pub const fn nonblocking(self) -> Type {
        Type(self.0 | libc::O_NONBLOCK)
    }
}

impl_debug!(Type, self::SOCK_STREAM, self::SOCK_DGRAM,);

impl_debug!(Protocol, self::IPPROTO_TCP, self::IPPROTO_UDP,);

#[cfg(not(target_os = "redox"))]
impl std::fmt::Debug for RecvFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("RecvFlags");
        s.field("is_truncated", &self.is_truncated());
        s.finish()
    }
}

#[repr(transparent)]
pub struct MaybeUninitSlice<'a> {
    vec: libc::iovec,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

unsafe impl<'a> Send for MaybeUninitSlice<'a> {}

unsafe impl<'a> Sync for MaybeUninitSlice<'a> {}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> MaybeUninitSlice<'a> {
        MaybeUninitSlice {
            vec: libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts(self.vec.iov_base.cast(), self.vec.iov_len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts_mut(self.vec.iov_base.cast(), self.vec.iov_len) }
    }
}

// Used in `MsgHdr`.

pub(crate) type Socket = c_int;

pub(crate) unsafe fn socket_from_raw(socket: Socket) -> crate::socket::Inner {
    crate::socket::Inner::from_raw_fd(socket)
}

pub(crate) fn socket_as_raw(socket: &crate::socket::Inner) -> Socket {
    socket.as_raw_fd()
}

pub(crate) fn socket_into_raw(socket: crate::socket::Inner) -> Socket {
    socket.into_raw_fd()
}

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<Socket> {
    syscall!(socket(family, ty, protocol))
}

pub(crate) fn bind(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(fd, addr.as_ptr(), addr.len() as _)).map(|_| ())
}

pub(crate) fn connect(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(connect(fd, addr.as_ptr(), addr.len())).map(|_| ())
}

pub(crate) fn poll_connect(socket: &crate::Socket, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();

    let mut pollfd = libc::pollfd {
        fd: socket.as_raw(),
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(io::ErrorKind::TimedOut.into());
        }

        let timeout = (timeout - elapsed).as_millis();
        let timeout = timeout.clamp(1, c_int::MAX as u128) as c_int;

        match syscall!(poll(&mut pollfd, 1, timeout)) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => {
                // Error or hang up indicates an error (or failure to connect).
                if (pollfd.revents & libc::POLLHUP) != 0 || (pollfd.revents & libc::POLLERR) != 0 {
                    match socket.take_error() {
                        Ok(Some(err)) | Err(err) => return Err(err),
                        Ok(None) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "no error set after POLLHUP",
                            ))
                        }
                    }
                }
                return Ok(());
            }
            // Got interrupted, try again.
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

pub(crate) fn listen(fd: Socket, backlog: c_int) -> io::Result<()> {
    syscall!(listen(fd, backlog)).map(|_| ())
}

pub(crate) fn accept(fd: Socket) -> io::Result<(Socket, SockAddr)> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::try_init(|storage, len| syscall!(accept(fd, storage.cast(), len))) }
}

pub(crate) fn getsockname(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::try_init(|storage, len| syscall!(getsockname(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn getpeername(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::try_init(|storage, len| syscall!(getpeername(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn try_clone(fd: Socket) -> io::Result<Socket> {
    syscall!(fcntl(fd, libc::F_DUPFD_CLOEXEC, 0))
}

#[cfg(feature = "all")]
pub(crate) fn nonblocking(fd: Socket) -> io::Result<bool> {
    let file_status_flags = fcntl_get(fd, libc::F_GETFL)?;
    Ok((file_status_flags & libc::O_NONBLOCK) != 0)
}

#[cfg(feature = "all")]
pub(crate) fn set_nonblocking(fd: Socket, nonblocking: bool) -> io::Result<()> {
    if nonblocking {
        fcntl_add(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    } else {
        fcntl_remove(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    }
}

pub(crate) fn shutdown(fd: Socket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Write => libc::SHUT_WR,
        Shutdown::Read => libc::SHUT_RD,
        Shutdown::Both => libc::SHUT_RDWR,
    };
    syscall!(shutdown(fd, how)).map(|_| ())
}

pub(crate) fn recv(fd: Socket, buf: &mut [MaybeUninit<u8>], flags: c_int) -> io::Result<usize> {
    syscall!(recv(
        fd,
        buf.as_mut_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

pub(crate) fn recv_from(
    fd: Socket,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    // Safety: `recvfrom` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::try_init(|addr, addrlen| {
            syscall!(recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                min(buf.len(), MAX_BUF_LEN),
                flags,
                addr.cast(),
                addrlen
            ))
            .map(|n| n as usize)
        })
    }
}

pub(crate) fn peek_sender(fd: Socket) -> io::Result<SockAddr> {
    // Unix-like platforms simply truncate the returned data, so this implementation is trivial.
    // However, for Windows this requires suppressing the `WSAEMSGSIZE` error,
    // so that requires a different approach.
    // NOTE: macOS does not populate `sockaddr` if you pass a zero-sized buffer.
    let (_, sender) = recv_from(fd, &mut [MaybeUninit::uninit(); 8], MSG_PEEK)?;
    Ok(sender)
}

pub(crate) fn recv_vectored(
    fd: Socket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags)> {
    let mut msg = MsgHdrMut::new().with_buffers(bufs);
    let n = recvmsg(fd, &mut msg, flags)?;
    Ok((n, msg.flags()))
}

pub(crate) fn recv_from_vectored(
    fd: Socket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags, SockAddr)> {
    let mut msg = MsgHdrMut::new().with_buffers(bufs);
    // SAFETY: `recvmsg` initialises the address storage and we set the length
    // manually.
    let (n, addr) = unsafe {
        SockAddr::try_init(|storage, len| {
            msg.inner.msg_name = storage.cast();
            msg.inner.msg_namelen = *len;
            let n = recvmsg(fd, &mut msg, flags)?;
            // Set the correct address length.
            *len = msg.inner.msg_namelen;
            Ok(n)
        })?
    };
    Ok((n, msg.flags(), addr))
}

pub(crate) fn recvmsg(
    fd: Socket,
    msg: &mut MsgHdrMut<'_, '_, '_>,
    flags: c_int,
) -> io::Result<usize> {
    syscall!(recvmsg(fd, &mut msg.inner, flags)).map(|n| n as usize)
}

pub(crate) fn send(fd: Socket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    syscall!(send(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

pub(crate) fn send_vectored(fd: Socket, bufs: &[IoSlice<'_>], flags: c_int) -> io::Result<usize> {
    let msg = MsgHdr::new().with_buffers(bufs);
    sendmsg(fd, &msg, flags)
}

pub(crate) fn send_to(fd: Socket, buf: &[u8], addr: &SockAddr, flags: c_int) -> io::Result<usize> {
    syscall!(sendto(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
        addr.as_ptr(),
        addr.len(),
    ))
    .map(|n| n as usize)
}

pub(crate) fn send_to_vectored(
    fd: Socket,
    bufs: &[IoSlice<'_>],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    let msg = MsgHdr::new().with_addr(addr).with_buffers(bufs);
    sendmsg(fd, &msg, flags)
}

pub(crate) fn sendmsg(fd: Socket, msg: &MsgHdr<'_, '_, '_>, flags: c_int) -> io::Result<usize> {
    syscall!(sendmsg(fd, &msg.inner, flags)).map(|n| n as usize)
}

/// Wrapper around `getsockopt` to deal with platform specific timeouts.
pub(crate) fn timeout_opt(fd: Socket, opt: c_int, val: c_int) -> io::Result<Option<Duration>> {
    unsafe { getsockopt(fd, opt, val).map(from_timeval) }
}

const fn from_timeval(duration: libc::timeval) -> Option<Duration> {
    if duration.tv_sec == 0 && duration.tv_usec == 0 {
        None
    } else {
        let sec = duration.tv_sec as u64;
        let nsec = (duration.tv_usec as u32) * 1000;
        Some(Duration::new(sec, nsec))
    }
}

/// Wrapper around `setsockopt` to deal with platform specific timeouts.
pub(crate) fn set_timeout_opt(
    fd: Socket,
    opt: c_int,
    val: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_timeval(duration);
    unsafe { setsockopt(fd, opt, val, duration) }
}

fn into_timeval(duration: Option<Duration>) -> libc::timeval {
    match duration {
        // https://github.com/rust-lang/libc/issues/1848
        #[cfg_attr(target_env = "musl", allow(deprecated))]
        Some(duration) => libc::timeval {
            tv_sec: min(duration.as_secs(), libc::time_t::MAX as u64) as libc::time_t,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    }
}

fn into_secs(duration: Duration) -> c_int {
    min(duration.as_secs(), c_int::MAX as u64) as c_int
}

/// Get the flags using `cmd`.
fn fcntl_get(fd: Socket, cmd: c_int) -> io::Result<c_int> {
    syscall!(fcntl(fd, cmd))
}

/// Add `flag` to the current set flags of `F_GETFD`.
fn fcntl_add(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = fcntl_get(fd, get_cmd)?;
    let new = previous | flag;
    if new != previous {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Remove `flag` to the current set flags of `F_GETFD`.
fn fcntl_remove(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = fcntl_get(fd, get_cmd)?;
    let new = previous & !flag;
    if new != previous {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn getsockopt<T>(fd: Socket, opt: c_int, val: c_int) -> io::Result<T> {
    let mut payload: MaybeUninit<T> = MaybeUninit::uninit();
    let mut len = size_of::<T>() as libc::socklen_t;
    syscall!(getsockopt(
        fd,
        opt,
        val,
        payload.as_mut_ptr().cast(),
        &mut len,
    ))
    .map(|_| {
        debug_assert_eq!(len as usize, size_of::<T>());
        // Safety: `getsockopt` initialised `payload` for us.
        payload.assume_init()
    })
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn setsockopt<T>(
    fd: Socket,
    opt: c_int,
    val: c_int,
    payload: T,
) -> io::Result<()> {
    let payload = ptr::addr_of!(payload).cast();
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) const fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    // `s_addr` is stored as BE on all machines, and the array is in BE order.
    // So the native endian conversion method is used so that it's never
    // swapped.
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(in_addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())
}

pub(crate) const fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

/// Unix only API.
impl crate::Socket {
    /// Returns `true` if `listen(2)` was called on this socket by checking the
    /// `SO_ACCEPTCONN` option on this socket.
    #[cfg(feature = "all")]
    #[cfg_attr(docsrs, doc(cfg(feature = "all")))]
    pub fn is_listener(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), self::SOL_SOCKET, self::SO_ACCEPTCONN)
                .map(|v| v != 0)
        }
    }

    /// Gets the value for the `SO_BINDTODEVICE` option on this socket.
    ///
    /// This value gets the socket binded device's interface name.
    #[cfg(feature = "all")]
    #[cfg_attr(docsrs, doc(cfg(feature = "all")))]
    pub fn device(&self) -> io::Result<Option<Vec<u8>>> {
        // TODO: replace with `MaybeUninit::uninit_array` once stable.
        let mut buf: [MaybeUninit<u8>; libc::IFNAMSIZ] =
            unsafe { MaybeUninit::uninit().assume_init() };
        let mut len = buf.len() as libc::socklen_t;
        syscall!(getsockopt(
            self.as_raw(),
            self::SOL_SOCKET,
            self::SO_BINDTODEVICE,
            buf.as_mut_ptr().cast(),
            &mut len,
        ))?;
        if len == 0 {
            Ok(None)
        } else {
            let buf = &buf[..len as usize - 1];
            // TODO: use `MaybeUninit::slice_assume_init_ref` once stable.
            Ok(Some(unsafe { &*(buf as *const [_] as *const [u8]) }.into()))
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(unix)))]
impl AsFd for crate::Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: lifetime is bound by self.
        unsafe { BorrowedFd::borrow_raw(self.as_raw()) }
    }
}

#[cfg_attr(docsrs, doc(cfg(unix)))]
impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> c_int {
        self.as_raw()
    }
}

#[cfg_attr(docsrs, doc(cfg(unix)))]
impl From<crate::Socket> for OwnedFd {
    fn from(sock: crate::Socket) -> OwnedFd {
        // SAFETY: sock.into_raw() always returns a valid fd.
        unsafe { OwnedFd::from_raw_fd(sock.into_raw()) }
    }
}

#[cfg_attr(docsrs, doc(cfg(unix)))]
impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> c_int {
        self.into_raw()
    }
}

#[cfg_attr(docsrs, doc(cfg(unix)))]
impl From<OwnedFd> for crate::Socket {
    fn from(fd: OwnedFd) -> crate::Socket {
        // SAFETY: `OwnedFd` ensures the fd is valid.
        unsafe { crate::Socket::from_raw_fd(fd.into_raw_fd()) }
    }
}

#[cfg_attr(docsrs, doc(cfg(unix)))]
impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: c_int) -> crate::Socket {
        crate::Socket::from_raw(fd)
    }
}

#[test]
fn in_addr_convertion() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let raw = to_in_addr(&ip);
    // NOTE: `in_addr` is packed on NetBSD and it's unsafe to borrow.
    let a = raw.s_addr;
    assert_eq!(a, u32::from_ne_bytes([127, 0, 0, 1]));
    assert_eq!(from_in_addr(raw), ip);

    let ip = Ipv4Addr::new(127, 34, 4, 12);
    let raw = to_in_addr(&ip);
    let a = raw.s_addr;
    assert_eq!(a, u32::from_ne_bytes([127, 34, 4, 12]));
    assert_eq!(from_in_addr(raw), ip);
}

#[test]
fn in6_addr_convertion() {
    let ip = Ipv6Addr::new(0x2000, 1, 2, 3, 4, 5, 6, 7);
    let raw = to_in6_addr(&ip);
    let want = [32, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7];
    assert_eq!(raw.s6_addr, want);
    assert_eq!(from_in6_addr(raw), ip);
}
