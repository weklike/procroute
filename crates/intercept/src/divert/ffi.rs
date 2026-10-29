// SPDX-License-Identifier: GPL-3.0-or-later
//! WinDivert 2.2 的 FFI 封装（T-071）。本 crate 里只有这个模块允许 `unsafe`（C-CODE-01）。
//!
//! - `WinDivert.dll` 不在链接时依赖，而是在运行时按完整路径加载：加载前按编译进来的锁校验 DLL 与驱动的
//!   SHA-256（C-DRV-01），驱动文件在 [`WinDivert`] 存活期间一直以只读共享方式锁定，不能被删除或替换
//!   （C-DRV-02）。驱动由第一次 `WinDivertOpen` 安装并加载。
//! - [`Handle`] 拥有一个 WinDivert 句柄，丢弃时关闭；关闭句柄即撤销它装上的过滤器。服务退出时系统关闭全部
//!   句柄，过滤器随之撤销（C-NET-06）。
//! - 收发只使用调用方提供的缓冲区，不分配内存，可以用在逐包处理的热路径上（C-CODE-04）。收发是阻塞调用，
//!   必须放在专用 OS 线程里（C-CODE-05）。
//! - [`Address`] 与 C 的 `WINDIVERT_ADDRESS` 内存布局一致（80 字节），字段经安全的访问函数读写。
#![allow(unsafe_code)] // 调用 WinDivert.dll 的导出函数；每处 unsafe 都有 SAFETY 注释

use std::ffi::{CStr, CString, c_char, c_void};
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use procroute_platform_win::library::{LibraryError, LockedFile, VerifiedLibrary};
use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};

use super::lock::{DLL_FILE_NAME, DRIVER_FILE_NAME, LockError, locked_driver};

/// WinDivert 的层。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Layer {
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

/// 事件类型（`Address::event`）。
pub mod event {
    pub const NETWORK_PACKET: u8 = 0;
    pub const FLOW_ESTABLISHED: u8 = 1;
    pub const FLOW_DELETED: u8 = 2;
    pub const SOCKET_BIND: u8 = 3;
    pub const SOCKET_CONNECT: u8 = 4;
    pub const SOCKET_LISTEN: u8 = 5;
    pub const SOCKET_ACCEPT: u8 = 6;
    pub const SOCKET_CLOSE: u8 = 7;
}

/// `WinDivertOpen` 的标志。
pub mod flags {
    pub const SNIFF: u64 = 0x0001;
    pub const DROP: u64 = 0x0002;
    pub const RECV_ONLY: u64 = 0x0004;
    pub const SEND_ONLY: u64 = 0x0008;
    pub const NO_INSTALL: u64 = 0x0010;
    pub const FRAGMENTS: u64 = 0x0020;
}

/// 句柄参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Param {
    QueueLength = 0,
    QueueTime = 1,
    QueueSize = 2,
    VersionMajor = 3,
    VersionMinor = 4,
}

/// `WinDivertShutdown` 的方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Shutdown {
    Recv = 1,
    Send = 2,
    Both = 3,
}

/// 单个数据包的最大长度（`WINDIVERT_MTU_MAX`）。
pub const MTU_MAX: usize = 40 + 0xFFFF;

/// `WINDIVERT_ADDRESS`。字段按 C 布局排列，位域与联合体经访问函数读写。
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Address {
    pub timestamp: i64,
    /// Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 IPChecksum:1
    /// TCPChecksum:1 UDPChecksum:1 Reserved1:8（MSVC 位域从低位开始分配）。
    bits: u32,
    reserved2: u32,
    data: Payload,
}

/// 64 字节、8 字节对齐的联合体（Network / Flow / Socket / Reflect）。
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Payload([u8; 64]);

const _: () = assert!(size_of::<Address>() == 80);
const _: () = assert!(align_of::<Address>() == 8);

/// `WINDIVERT_DATA_NETWORK`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkData {
    pub if_idx: u32,
    pub sub_if_idx: u32,
}

/// `WINDIVERT_DATA_FLOW` 与 `WINDIVERT_DATA_SOCKET`（两者布局相同）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointData {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: IpAddr,
    pub remote_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved2: 0,
            data: Payload([0; 64]),
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("layer", &self.layer())
            .field("event", &self.event())
            .field("outbound", &self.outbound())
            .field("loopback", &self.loopback())
            .field("ipv6", &self.ipv6())
            .finish_non_exhaustive()
    }
}

impl Address {
    fn bit(&self, n: u32) -> bool {
        self.bits & (1 << n) != 0
    }

    fn set_bit(&mut self, n: u32, on: bool) {
        if on {
            self.bits |= 1 << n;
        } else {
            self.bits &= !(1 << n);
        }
    }

    pub fn layer(&self) -> u8 {
        (self.bits & 0xff) as u8
    }

    pub fn event(&self) -> u8 {
        ((self.bits >> 8) & 0xff) as u8
    }

    pub fn sniffed(&self) -> bool {
        self.bit(16)
    }

    pub fn outbound(&self) -> bool {
        self.bit(17)
    }

    pub fn set_outbound(&mut self, on: bool) {
        self.set_bit(17, on);
    }

    pub fn loopback(&self) -> bool {
        self.bit(18)
    }

    pub fn impostor(&self) -> bool {
        self.bit(19)
    }

    pub fn set_impostor(&mut self, on: bool) {
        self.set_bit(19, on);
    }

    pub fn ipv6(&self) -> bool {
        self.bit(20)
    }

    fn u32_at(&self, off: usize) -> u32 {
        let b = &self.data.0;
        u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    fn u64_at(&self, off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data.0[off..off + 8]);
        u64::from_ne_bytes(b)
    }

    fn u16_at(&self, off: usize) -> u16 {
        let b = &self.data.0;
        u16::from_ne_bytes([b[off], b[off + 1]])
    }

    /// WinDivert 把地址存成主机字节序的 `UINT32[4]`，`[0]` 是最低的 32 位；IPv4 是 IPv4 映射的 IPv6。
    fn addr_at(&self, off: usize) -> IpAddr {
        let words = [
            self.u32_at(off),
            self.u32_at(off + 4),
            self.u32_at(off + 8),
            self.u32_at(off + 12),
        ];
        words_to_ip(words)
    }

    /// 网络层的数据。
    pub fn network(&self) -> NetworkData {
        NetworkData {
            if_idx: self.u32_at(0),
            sub_if_idx: self.u32_at(4),
        }
    }

    /// FLOW 层与 SOCKET 层的数据。
    pub fn endpoint(&self) -> EndpointData {
        EndpointData {
            endpoint_id: self.u64_at(0),
            parent_endpoint_id: self.u64_at(8),
            process_id: self.u32_at(16),
            local_addr: self.addr_at(20),
            remote_addr: self.addr_at(36),
            local_port: self.u16_at(52),
            remote_port: self.u16_at(54),
            protocol: self.data.0[56],
        }
    }

    #[cfg(test)]
    pub(crate) fn from_parts(bits: u32, data: [u8; 64]) -> Self {
        Self {
            timestamp: 0,
            bits,
            reserved2: 0,
            data: Payload(data),
        }
    }
}

/// `UINT32[4]`（主机字节序，`[0]` 最低）→ IP 地址；IPv4 映射地址还原成 IPv4。
pub fn words_to_ip(words: [u32; 4]) -> IpAddr {
    let v = (u128::from(words[3]) << 96)
        | (u128::from(words[2]) << 64)
        | (u128::from(words[1]) << 32)
        | u128::from(words[0]);
    let v6 = Ipv6Addr::from(v);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

#[derive(Debug, Error)]
pub enum DivertError {
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(transparent)]
    Library(#[from] LibraryError),
    #[error("WinDivert.dll does not export {0}")]
    MissingExport(&'static str),
    #[error("filter text contains a NUL byte")]
    NulInFilter,
    #[error("WinDivertOpen failed with error {0}")]
    Open(u32),
}

/// 过滤器语法错误。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid filter at {position}: {message}")]
pub struct FilterError {
    pub message: String,
    pub position: u32,
}

type FnOpen = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> HANDLE;
type FnRecvEx = unsafe extern "C" fn(
    HANDLE,
    *mut c_void,
    u32,
    *mut u32,
    u64,
    *mut Address,
    *mut u32,
    *mut c_void,
) -> i32;
type FnSendEx = unsafe extern "C" fn(
    HANDLE,
    *const c_void,
    u32,
    *mut u32,
    u64,
    *const Address,
    u32,
    *mut c_void,
) -> i32;
type FnShutdown = unsafe extern "C" fn(HANDLE, i32) -> i32;
type FnClose = unsafe extern "C" fn(HANDLE) -> i32;
type FnSetParam = unsafe extern "C" fn(HANDLE, i32, u64) -> i32;
type FnGetParam = unsafe extern "C" fn(HANDLE, i32, *mut u64) -> i32;
type FnCalcChecksums = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;
type FnCompileFilter =
    unsafe extern "C" fn(*const c_char, i32, *mut c_char, u32, *mut *const c_char, *mut u32) -> i32;

/// 已加载、已校验的 WinDivert。克隆 `Arc` 共享。
pub struct WinDivert {
    open: FnOpen,
    recv_ex: FnRecvEx,
    send_ex: FnSendEx,
    shutdown: FnShutdown,
    close: FnClose,
    set_param: FnSetParam,
    get_param: FnGetParam,
    calc_checksums: FnCalcChecksums,
    compile_filter: FnCompileFilter,
    version: String,
    // 声明顺序即析构顺序：函数指针用不着析构；先卸载 DLL，最后放开驱动文件
    _library: VerifiedLibrary,
    _driver: LockedFile,
}

impl std::fmt::Debug for WinDivert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinDivert")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// 取一个导出函数并转成对应的函数指针类型。
macro_rules! export {
    ($lib:expr, $name:literal, $label:literal, $ty:ty) => {{
        let addr = $lib
            .symbol($name)
            .ok_or(DivertError::MissingExport($label))?;
        // SAFETY: 地址来自已校验版本（锁文件中的 SHA-256）的 WinDivert.dll 的同名导出；
        // 函数指针类型按该版本 windivert.h 的原型声明（x64 只有一种调用约定）。
        unsafe { std::mem::transmute::<*mut c_void, $ty>(addr.as_ptr()) }
    }};
}

impl WinDivert {
    /// 从 `dir`（安装目录）加载 WinDivert：校验驱动与 DLL 的 SHA-256，锁定驱动文件，再加载 DLL。
    pub fn load(dir: &Path) -> Result<Arc<Self>, DivertError> {
        let lock = locked_driver()?;
        let driver = LockedFile::open(&dir.join(DRIVER_FILE_NAME), &lock.driver_sha256)?;
        let library = VerifiedLibrary::load(&dir.join(DLL_FILE_NAME), &lock.dll_sha256)?;
        Ok(Arc::new(Self {
            open: export!(library, c"WinDivertOpen", "WinDivertOpen", FnOpen),
            recv_ex: export!(library, c"WinDivertRecvEx", "WinDivertRecvEx", FnRecvEx),
            send_ex: export!(library, c"WinDivertSendEx", "WinDivertSendEx", FnSendEx),
            shutdown: export!(
                library,
                c"WinDivertShutdown",
                "WinDivertShutdown",
                FnShutdown
            ),
            close: export!(library, c"WinDivertClose", "WinDivertClose", FnClose),
            set_param: export!(
                library,
                c"WinDivertSetParam",
                "WinDivertSetParam",
                FnSetParam
            ),
            get_param: export!(
                library,
                c"WinDivertGetParam",
                "WinDivertGetParam",
                FnGetParam
            ),
            calc_checksums: export!(
                library,
                c"WinDivertHelperCalcChecksums",
                "WinDivertHelperCalcChecksums",
                FnCalcChecksums
            ),
            compile_filter: export!(
                library,
                c"WinDivertHelperCompileFilter",
                "WinDivertHelperCompileFilter",
                FnCompileFilter
            ),
            version: lock.version,
            _library: library,
            _driver: driver,
        }))
    }

    /// 锁定的 WinDivert 版本。
    pub fn version(&self) -> &str {
        &self.version
    }

    /// 只检查过滤器语法（纯用户态，不加载驱动）。
    pub fn check_filter(&self, filter: &str, layer: Layer) -> Result<(), FilterError> {
        let text = CString::new(filter).map_err(|_| FilterError {
            message: "filter text contains a NUL byte".into(),
            position: 0,
        })?;
        let mut error: *const c_char = ptr::null();
        let mut position = 0u32;
        // SAFETY: `text` 以 NUL 结尾；不需要编译结果，输出缓冲区为空、长度 0；错误信息指针由 DLL 写入，
        // 指向 DLL 内的静态字符串。
        let ok = unsafe {
            (self.compile_filter)(
                text.as_ptr(),
                layer as i32,
                ptr::null_mut(),
                0,
                &mut error,
                &mut position,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let message = if error.is_null() {
            "invalid filter".to_owned()
        } else {
            // SAFETY: 失败时 `error` 指向 DLL 内以 NUL 结尾的静态字符串，DLL 在 `self` 存活期间不会卸载。
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        };
        Err(FilterError { message, position })
    }

    /// 打开一个句柄（第一次调用时安装并加载驱动，需要管理员权限）。
    pub fn open(
        self: &Arc<Self>,
        filter: &str,
        layer: Layer,
        priority: i16,
        flags: u64,
    ) -> Result<Handle, DivertError> {
        let text = CString::new(filter).map_err(|_| DivertError::NulInFilter)?;
        // SAFETY: `text` 以 NUL 结尾，调用期间有效；其余参数按值传递。
        let raw = unsafe { (self.open)(text.as_ptr(), layer as i32, priority, flags) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            // SAFETY: 无参数，读取本线程的最后错误码。
            return Err(DivertError::Open(unsafe { GetLastError() }));
        }
        Ok(Handle {
            api: Arc::clone(self),
            raw,
        })
    }

    /// 重新计算数据包的校验和（改写地址或端口之后调用）。
    pub fn calc_checksums(&self, packet: &mut [u8], addr: &mut Address) -> bool {
        let Ok(len) = u32::try_from(packet.len()) else {
            return false;
        };
        // SAFETY: `packet` 可写 `len` 字节；`addr` 是有效的 WINDIVERT_ADDRESS；标志 0 表示计算全部校验和。
        unsafe { (self.calc_checksums)(packet.as_mut_ptr().cast(), len, addr, 0) != 0 }
    }
}

/// 一个 WinDivert 句柄。丢弃时关闭，撤销它装上的过滤器。
///
/// WinDivert 允许不同线程同时在同一句柄上收发，因此 `Handle` 可以在线程间共享。
pub struct Handle {
    api: Arc<WinDivert>,
    raw: HANDLE,
}

// SAFETY: WinDivert 句柄是内核对象句柄，WinDivert 文档允许多个线程同时调用 Recv/Send；
// 关闭只在 Drop 里发生一次。
unsafe impl Send for Handle {}
// SAFETY: 同上。
unsafe impl Sync for Handle {}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle").finish_non_exhaustive()
    }
}

impl Handle {
    /// 收一个包（阻塞）。返回包长度；`addr` 填上它的地址信息。
    pub fn recv(&self, packet: &mut [u8], addr: &mut Address) -> io::Result<usize> {
        let cap = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        let mut len = 0u32;
        // SAFETY: 句柄有效；`packet` 可写 `cap` 字节；只收一个地址，地址长度指针为空；同步调用不用 OVERLAPPED。
        let ok = unsafe {
            (self.api.recv_ex)(
                self.raw,
                packet.as_mut_ptr().cast(),
                cap,
                &mut len,
                0,
                addr,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(len as usize)
    }

    /// 只收事件、不带包内容（SOCKET / FLOW 层）。
    pub fn recv_event(&self, addr: &mut Address) -> io::Result<()> {
        // SAFETY: 句柄有效；这些层没有包内容，缓冲区为空、长度 0；只收一个地址。
        let ok = unsafe {
            (self.api.recv_ex)(
                self.raw,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                addr,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// 注入一个包。返回实际写入的长度。
    pub fn send(&self, packet: &[u8], addr: &Address) -> io::Result<usize> {
        let len = u32::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
        let mut sent = 0u32;
        // SAFETY: 句柄有效；`packet` 可读 `len` 字节；单个地址，长度如实传入；同步调用。
        let ok = unsafe {
            (self.api.send_ex)(
                self.raw,
                packet.as_ptr().cast(),
                len,
                &mut sent,
                0,
                addr,
                size_of::<Address>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sent as usize)
    }

    pub fn set_param(&self, param: Param, value: u64) -> io::Result<()> {
        // SAFETY: 句柄有效；参数按值传递。
        if unsafe { (self.api.set_param)(self.raw, param as i32, value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn param(&self, param: Param) -> io::Result<u64> {
        let mut value = 0u64;
        // SAFETY: 句柄有效；`value` 可写。
        if unsafe { (self.api.get_param)(self.raw, param as i32, &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    /// 让阻塞在 `recv` 上的线程尽快返回（关闭前调用）。
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        // SAFETY: 句柄有效。
        if unsafe { (self.api.shutdown)(self.raw, how as i32) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: 句柄由 WinDivertOpen 返回且有效，只在这里关闭一次；关闭后不再使用。
        unsafe { (self.api.close)(self.raw) };
    }
}

#[cfg(test)]
mod tests;
