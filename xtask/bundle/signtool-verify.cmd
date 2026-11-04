@rem SPDX-License-Identifier: GPL-3.0-or-later
@rem Stand-in for "signtool verify" while `cargo xtask bundle` runs (TAURI_WINDOWS_SIGNTOOL_PATH).
@rem With a custom signCommand, Tauri's bundler only runs signtool to check whether a binary is already
@rem signed before signing it. This always answers "not signed", so every binary reaches sign.ps1, which
@rem holds the whole signing policy (it skips the hash-locked third-party binaries). Any other use of
@rem signtool also fails here, so it shows up instead of being skipped silently.
@exit /b 1
