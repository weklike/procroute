// SPDX-License-Identifier: GPL-3.0-or-later
//! 控制管道客户端校验（C-SEC-02）：可执行文件必须位于安装目录，且 Authenticode 签名主体与服务一致。
//!
//! 安装目录就是服务自己所在的目录（安装器把服务与界面放在一起）。服务自身没有有效签名时
//! 无法完成比对，按 fail-closed 拒绝所有客户端；开发构建可用 `insecure-skip-client-auth`
//! 特性关闭校验，release 构建禁止（见 main.rs 的 `compile_error!`）。

use procroute_platform_win::authenticode::{SignatureError, verified_signer_subject};
use procroute_platform_win::path::{DosDeviceMap, normalize_process_path};
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_rules::path::is_within;

/// 客户端校验策略。
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// 正式校验。
    Enforce {
        /// 规范化后的安装目录。
        install_dir: String,
        /// 服务自身的签名主体；拿不到时为错误，所有客户端都会被拒绝。
        signer: Result<String, SignatureError>,
    },
    /// 不校验。只存在于测试与开启了 `insecure-skip-client-auth` 的开发构建中。
    #[cfg(any(test, feature = "insecure-skip-client-auth"))]
    Disabled,
}

impl ClientAuth {
    /// 以当前服务可执行文件为准：所在目录是安装目录，签名主体是期望的主体。
    pub fn for_current_service() -> Self {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let signer = verified_signer_subject(&exe);
        if let Err(e) = &signer {
            tracing::error!(error = %e, "service binary has no valid signature; every pipe client will be rejected");
        }
        Self::Enforce {
            install_dir: install_dir_of(&exe),
            signer,
        }
    }

    /// 校验客户端可执行文件；失败时返回 `ipc.unauthorized`。
    pub fn verify(&self, client_image: &str) -> Result<(), IpcError> {
        let (install_dir, signer) = match self {
            Self::Enforce {
                install_dir,
                signer,
            } => (install_dir, signer),
            #[cfg(any(test, feature = "insecure-skip-client-auth"))]
            Self::Disabled => return Ok(()),
        };
        let image = normalize_process_path(&DosDeviceMap::default(), client_image);
        if install_dir.is_empty() || !is_within(&image, install_dir) {
            return Err(unauthorized(
                "client executable is outside the install directory",
            ));
        }
        let expected = signer
            .as_ref()
            .map_err(|_| unauthorized("service binary is not signed"))?;
        match verified_signer_subject(client_image) {
            Ok(actual) if &actual == expected => Ok(()),
            Ok(_) => Err(unauthorized("client is signed by a different publisher")),
            Err(_) => Err(unauthorized("client executable has no valid signature")),
        }
    }
}

/// 可执行文件所在目录的规范形式；拿不到时为空串（[`ClientAuth::verify`] 会拒绝所有客户端）。
fn install_dir_of(exe: &str) -> String {
    let normalized = normalize_process_path(&DosDeviceMap::default(), exe);
    procroute_rules::path::parent_dir(&normalized).to_owned()
}

fn unauthorized(message: &str) -> IpcError {
    IpcError::new(ErrorCode::IpcUnauthorized, message)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn test_exe() -> String {
        std::env::current_exe()
            .expect("current exe")
            .to_string_lossy()
            .into_owned()
    }

    /// System32 里任意一个带内嵌签名的可执行文件及其签名主体。
    fn signed_system_exe() -> (PathBuf, String) {
        let sys32 = Path::new(&std::env::var("SystemRoot").expect("SystemRoot")).join("System32");
        std::fs::read_dir(&sys32)
            .expect("read System32")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
            .find_map(|p| {
                let s = verified_signer_subject(&p.to_string_lossy()).ok()?;
                Some((p, s))
            })
            .expect("a System32 executable with an embedded signature")
    }

    fn code(r: Result<(), IpcError>) -> ErrorCode {
        r.expect_err("must be rejected").code
    }

    #[test]
    fn signed_client_in_install_dir_with_matching_signer_is_accepted() {
        let (exe, signer) = signed_system_exe();
        let exe = exe.to_string_lossy().into_owned();
        let auth = ClientAuth::Enforce {
            install_dir: install_dir_of(&exe),
            signer: Ok(signer),
        };
        auth.verify(&exe).expect("accepted");
        // 大小写与分隔符不同的写法同样通过（路径先规范化）。
        auth.verify(&exe.to_uppercase()).expect("accepted");
    }

    #[test]
    fn different_signer_is_rejected() {
        let (exe, _) = signed_system_exe();
        let exe = exe.to_string_lossy().into_owned();
        let auth = ClientAuth::Enforce {
            install_dir: install_dir_of(&exe),
            signer: Ok("C=CN, O=Someone Else, CN=Someone Else".into()),
        };
        assert_eq!(code(auth.verify(&exe)), ErrorCode::IpcUnauthorized);
    }

    #[test]
    fn unsigned_client_is_rejected_even_inside_the_install_dir() {
        let exe = test_exe();
        let auth = ClientAuth::Enforce {
            install_dir: install_dir_of(&exe),
            signer: Ok("C=US, O=Microsoft Corporation, CN=Microsoft Windows".into()),
        };
        assert_eq!(code(auth.verify(&exe)), ErrorCode::IpcUnauthorized);
    }

    #[test]
    fn client_outside_the_install_dir_is_rejected() {
        let (exe, signer) = signed_system_exe();
        let auth = ClientAuth::Enforce {
            install_dir: install_dir_of(&test_exe()),
            signer: Ok(signer),
        };
        assert_eq!(
            code(auth.verify(&exe.to_string_lossy())),
            ErrorCode::IpcUnauthorized
        );
        // 同名前缀的兄弟目录不算在安装目录内。
        let auth = ClientAuth::Enforce {
            install_dir: r"c:\program files\procroute".into(),
            signer: Ok("x".into()),
        };
        assert_eq!(
            code(auth.verify(r"C:\Program Files\ProcRoute2\procroute-ui.exe")),
            ErrorCode::IpcUnauthorized
        );
    }

    #[test]
    fn unsigned_service_rejects_everyone() {
        let (exe, _) = signed_system_exe();
        let exe = exe.to_string_lossy().into_owned();
        let auth = ClientAuth::Enforce {
            install_dir: install_dir_of(&exe),
            signer: Err(SignatureError::NotSigned),
        };
        assert_eq!(code(auth.verify(&exe)), ErrorCode::IpcUnauthorized);
    }

    #[test]
    fn current_test_binary_as_service_is_unsigned() {
        // 测试二进制没有签名：按正式策略构造时必须处于「拒绝所有人」的状态。
        let ClientAuth::Enforce { signer, .. } = ClientAuth::for_current_service() else {
            unreachable!("for_current_service always enforces");
        };
        assert_eq!(signer, Err(SignatureError::NotSigned));
    }
}
