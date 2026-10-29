// SPDX-License-Identifier: GPL-3.0-or-later
//! 每次启动随机生成的运行参数（C-NET-08）：控制 API 的端口与密钥。

use std::io;
use std::net::{Ipv4Addr, TcpListener};

use procroute_platform_win::secret::Secret;

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// 小于它的字节按 62 取模才是均匀的（248 = 62 × 4），其余丢弃重抽。
const UNBIASED_LIMIT: u8 = 248;

/// 用 `fill` 提供的随机字节生成 `len` 个字母数字字符，各字符等概率（拒绝采样）。
pub fn alnum_secret<E>(
    len: usize,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), E>,
) -> Result<Secret<String>, E> {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        fill(&mut buf)?;
        for &b in &buf {
            if out.len() == len {
                break;
            }
            if b < UNBIASED_LIMIT {
                out.push(char::from(ALPHABET[usize::from(b) % ALPHABET.len()]));
            }
        }
    }
    Ok(Secret::new(out))
}

/// 新的控制 API 密钥，长度为 [`MIN_API_SECRET_LEN`](crate::config_gen::MIN_API_SECRET_LEN)，取自系统 CSPRNG。
#[cfg(windows)]
pub fn random_api_secret() -> Result<Secret<String>, procroute_platform_win::random::RandomError> {
    alnum_secret(
        crate::config_gen::MIN_API_SECRET_LEN,
        procroute_platform_win::random::fill_random,
    )
}

/// 一个当前空闲的回环端口。端口在交给 sing-box 之前可能被别人占用；那样 sing-box 会启动失败，
/// 按启动失败处理即可。
pub fn free_loopback_port() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_gen::MIN_API_SECRET_LEN;

    #[test]
    fn secret_has_the_requested_length_and_alphabet() {
        let mut counter = 0u8;
        let secret = alnum_secret::<()>(MIN_API_SECRET_LEN, |buf| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
            Ok(())
        })
        .expect("secret");
        let s = secret.expose();
        assert_eq!(s.len(), MIN_API_SECRET_LEN);
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric()), "{s}");
        assert!(s.starts_with("0123456789ABC"), "{s}");
    }

    #[test]
    fn biased_bytes_are_rejected() {
        // 前一轮全是会造成偏差的字节，必须全部丢弃，再从下一轮取
        let mut round = 0;
        let secret = alnum_secret::<()>(4, |buf| {
            buf.fill(if round == 0 { 250 } else { 61 });
            round += 1;
            Ok(())
        })
        .expect("secret");
        assert_eq!(secret.expose(), "zzzz");
        assert_eq!(round, 2);
    }

    #[test]
    fn fill_errors_propagate() {
        assert_eq!(
            alnum_secret(8, |_| Err("rng down")).map(|_| ()),
            Err("rng down")
        );
    }

    #[test]
    fn free_port_is_nonzero() {
        assert_ne!(free_loopback_port().expect("port"), 0);
    }

    #[cfg(windows)]
    #[test]
    fn random_secrets_differ() {
        let a = random_api_secret().expect("secret");
        let b = random_api_secret().expect("secret");
        assert_eq!(a.expose().len(), MIN_API_SECRET_LEN);
        assert_ne!(a.expose(), b.expose());
    }
}
