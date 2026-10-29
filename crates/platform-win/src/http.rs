// SPDX-License-Identifier: GPL-3.0-or-later
//! 最小的 HTTP(S) GET（WinHTTP），用于拉取订阅（`node.import`）。
//!
//! 用系统自带的 WinHTTP，TLS 由 Schannel 校验，不为此引入 HTTP / TLS 库（C-DEP-03）。只支持 `http://` 与
//! `https://`，不带用户名密码的 URL；不保存 Cookie；HTTPS 不会被重定向到 HTTP（WinHTTP 默认策略）；
//! 响应体超过上限即中止（C-SEC-07）。代理按 WinHTTP 的系统设置（`netsh winhttp`）自动选择。
//!
//! 订阅地址常含访问令牌：错误里只有调用名与错误码，从不包含 URL（C-SEC-04）。
//! 阻塞调用，异步代码应经 `spawn_blocking` 调用（C-CODE-05）。
#![allow(unsafe_code)] // 需要调用 WinHttp* 系列函数；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Networking::WinHttp::{
    URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_DISABLE_COOKIES,
    WINHTTP_FLAG_SECURE, WINHTTP_INTERNET_SCHEME_HTTP, WINHTTP_INTERNET_SCHEME_HTTPS,
    WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpSetOption, WinHttpSetTimeouts,
};

use crate::wide::to_wide;

/// 一次 GET 的参数。
#[derive(Debug, Clone)]
pub struct GetOptions {
    /// 解析、连接、发送、接收各自的超时。
    pub timeout: Duration,
    /// 响应体上限（字节）。
    pub max_body: usize,
    pub user_agent: String,
}

/// 响应：状态码与响应体（未解压、未转码）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("only http:// and https:// URLs without user info are supported")]
    UnsupportedUrl,
    #[error("{call} failed with error {code}")]
    WinHttp { call: &'static str, code: u32 },
    #[error("the response body exceeds {0} bytes")]
    TooLarge(usize),
}

/// WinHTTP 句柄，离开作用域时关闭。
struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: 句柄由 WinHttpOpen / Connect / OpenRequest 返回且非空，只在这里关闭一次。
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn check(call: &'static str, ok: i32) -> Result<(), HttpError> {
    if ok != 0 {
        Ok(())
    } else {
        Err(last_error(call))
    }
}

fn handle(call: &'static str, raw: *mut c_void) -> Result<Handle, HttpError> {
    if raw.is_null() {
        Err(last_error(call))
    } else {
        Ok(Handle(raw))
    }
}

fn last_error(call: &'static str) -> HttpError {
    // SAFETY: 无参数，读取本线程的最后错误码。
    let code = unsafe { GetLastError() };
    HttpError::WinHttp { call, code }
}

/// URL 的各部分（UTF-16，以 NUL 结尾）。
struct Target {
    secure: bool,
    host: Vec<u16>,
    port: u16,
    /// 路径加查询串。
    object: Vec<u16>,
}

fn crack(url: &str) -> Result<Target, HttpError> {
    let wide = to_wide(url);
    // 各指针为空、长度非零：WinHTTP 返回指向输入字符串内部的指针与长度，不复制
    let mut uc = URL_COMPONENTS {
        dwStructSize: size_of::<URL_COMPONENTS>() as u32,
        dwSchemeLength: u32::MAX,
        dwHostNameLength: u32::MAX,
        dwUserNameLength: u32::MAX,
        dwPasswordLength: u32::MAX,
        dwUrlPathLength: u32::MAX,
        dwExtraInfoLength: u32::MAX,
        ..Default::default()
    };
    // SAFETY: `wide` 以 NUL 结尾，长度传 0 表示按 NUL 结尾处理；`uc` 已按上面的约定初始化。
    let ok = unsafe { WinHttpCrackUrl(wide.as_ptr(), 0, 0, &mut uc) };
    if ok == 0 {
        return Err(HttpError::UnsupportedUrl);
    }
    let secure = match uc.nScheme {
        WINHTTP_INTERNET_SCHEME_HTTPS => true,
        WINHTTP_INTERNET_SCHEME_HTTP => false,
        _ => return Err(HttpError::UnsupportedUrl),
    };
    if uc.dwUserNameLength > 0 || uc.dwPasswordLength > 0 || uc.dwHostNameLength == 0 {
        return Err(HttpError::UnsupportedUrl);
    }
    let part = |p: *mut u16, len: u32| -> Vec<u16> {
        if p.is_null() || len == 0 {
            return Vec::new();
        }
        // SAFETY: WinHttpCrackUrl 成功时，非空指针指向 `wide` 内部、其后至少 `len` 个 u16；
        // `wide` 在本函数内一直存活。
        unsafe { std::slice::from_raw_parts(p, len as usize) }.to_vec()
    };
    let mut host = part(uc.lpszHostName, uc.dwHostNameLength);
    host.push(0);
    // 查询串紧跟在路径后面，拼起来就是请求行里的对象
    let mut object = part(uc.lpszUrlPath, uc.dwUrlPathLength);
    object.extend(part(uc.lpszExtraInfo, uc.dwExtraInfoLength));
    if object.is_empty() {
        object.push(u16::from(b'/'));
    }
    object.push(0);
    Ok(Target {
        secure,
        host,
        port: uc.nPort,
        object,
    })
}

/// 发一个 GET 请求。非 2xx 状态也算成功返回，由调用方判断。
pub fn get(url: &str, opts: &GetOptions) -> Result<Response, HttpError> {
    let target = crack(url)?;
    let agent = to_wide(&opts.user_agent);
    // SAFETY: `agent` 以 NUL 结尾；自动代理模式下代理名与绕过列表必须为空；同步模式（flags 为 0）。
    let session = handle("WinHttpOpen", unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        )
    })?;
    let ms = i32::try_from(opts.timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: 会话句柄有效。
    check("WinHttpSetTimeouts", unsafe {
        WinHttpSetTimeouts(session.0, ms, ms, ms, ms)
    })?;
    // SAFETY: 会话句柄有效；`host` 以 NUL 结尾；保留参数为 0。
    let connect = handle("WinHttpConnect", unsafe {
        WinHttpConnect(session.0, target.host.as_ptr(), target.port, 0)
    })?;
    let verb = to_wide("GET");
    let flags = if target.secure {
        WINHTTP_FLAG_SECURE
    } else {
        0
    };
    // SAFETY: 连接句柄有效；动词与对象以 NUL 结尾；版本、引用页、接受类型为空表示默认值。
    let request = handle("WinHttpOpenRequest", unsafe {
        WinHttpOpenRequest(
            connect.0,
            verb.as_ptr(),
            target.object.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            flags,
        )
    })?;
    let no_cookies: u32 = WINHTTP_DISABLE_COOKIES;
    // SAFETY: 请求句柄有效；选项值是一个 u32，大小如实传入。
    check("WinHttpSetOption", unsafe {
        WinHttpSetOption(
            request.0,
            WINHTTP_OPTION_DISABLE_FEATURE,
            (&raw const no_cookies).cast::<c_void>(),
            size_of::<u32>() as u32,
        )
    })?;
    // SAFETY: 请求句柄有效；没有附加头与请求体。
    check("WinHttpSendRequest", unsafe {
        WinHttpSendRequest(request.0, ptr::null(), 0, ptr::null(), 0, 0, 0)
    })?;
    // SAFETY: 请求句柄有效；保留参数必须为空。
    check("WinHttpReceiveResponse", unsafe {
        WinHttpReceiveResponse(request.0, ptr::null_mut())
    })?;
    let status = status_code(&request)?;
    let body = read_body(&request, opts.max_body)?;
    Ok(Response { status, body })
}

fn status_code(request: &Handle) -> Result<u16, HttpError> {
    let mut status = 0u32;
    let mut len = size_of::<u32>() as u32;
    // SAFETY: 请求句柄有效；按数字查询时输出缓冲区是一个 u32，长度如实传入；按序号查询，名称为空。
    check("WinHttpQueryHeaders", unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            (&raw mut status).cast::<c_void>(),
            &mut len,
            ptr::null_mut(),
        )
    })?;
    Ok(u16::try_from(status).unwrap_or(0))
}

fn read_body(request: &Handle, max: usize) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let mut read = 0u32;
        // SAFETY: 请求句柄有效；`chunk` 可写其长度个字节；`read` 接收实际读到的字节数。
        check("WinHttpReadData", unsafe {
            WinHttpReadData(
                request.0,
                chunk.as_mut_ptr().cast::<c_void>(),
                chunk.len() as u32,
                &mut read,
            )
        })?;
        if read == 0 {
            return Ok(body);
        }
        if body.len() + read as usize > max {
            return Err(HttpError::TooLarge(max));
        }
        body.extend_from_slice(&chunk[..read as usize]);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    fn opts(max_body: usize) -> GetOptions {
        GetOptions {
            timeout: Duration::from_secs(5),
            max_body,
            user_agent: "ProcRoute-test".into(),
        }
    }

    /// 回答一次请求的 HTTP 服务；把请求头交给测试检查。
    fn serve_once(status: &'static str, body: Vec<u8>) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            tx.send(String::from_utf8_lossy(&req).into_owned())
                .expect("send");
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
        });
        (port, rx)
    }

    #[test]
    fn fetches_the_body_and_sends_path_and_query() {
        let (port, rx) = serve_once("200 OK", b"ss://example".to_vec());
        let url = format!("http://127.0.0.1:{port}/api/sub?token=abc&flag=1");
        let resp = get(&url, &opts(1024)).expect("get");
        assert_eq!(
            resp,
            Response {
                status: 200,
                body: b"ss://example".to_vec()
            }
        );
        let req = rx.recv().expect("request");
        assert!(
            req.starts_with("GET /api/sub?token=abc&flag=1 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("User-Agent: ProcRoute-test\r\n"), "{req}");
        assert!(!req.to_ascii_lowercase().contains("cookie"), "{req}");
    }

    #[test]
    fn error_statuses_are_returned_to_the_caller() {
        let (port, _rx) = serve_once("404 Not Found", b"nope".to_vec());
        let resp = get(&format!("http://127.0.0.1:{port}/"), &opts(1024)).expect("get");
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn oversized_bodies_are_rejected() {
        let (port, _rx) = serve_once("200 OK", vec![b'x'; 300 * 1024]);
        assert_eq!(
            get(&format!("http://127.0.0.1:{port}/big"), &opts(100 * 1024)),
            Err(HttpError::TooLarge(100 * 1024))
        );
    }

    #[test]
    fn only_plain_http_and_https_urls_are_accepted() {
        for url in [
            "ftp://example.com/sub",
            "file:///C:/Windows/win.ini",
            "not a url",
            "http://user:secret@127.0.0.1:1/sub",
        ] {
            assert_eq!(
                get(url, &opts(1024)),
                Err(HttpError::UnsupportedUrl),
                "{url}"
            );
        }
    }

    #[test]
    fn unreachable_servers_report_a_winhttp_error_without_the_url() {
        let port = {
            let l = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            l.local_addr().expect("addr").port()
        };
        let err = get(
            &format!("http://127.0.0.1:{port}/sub?token=hunter2"),
            &opts(1024),
        )
        .expect_err("refused");
        assert!(matches!(err, HttpError::WinHttp { .. }), "{err:?}");
        assert!(!err.to_string().contains("hunter2"));
    }
}
