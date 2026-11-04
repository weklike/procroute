; SPDX-License-Identifier: GPL-3.0-or-later
; ProcRoute installer hooks (T-110), passed to Tauri's NSIS bundler by `cargo xtask bundle`:
; register and remove the Windows service. Comments stay ASCII: makensis reads files without a BOM
; in the system code page.
;
; - Service name ProcRoute (same as SERVICE_NAME in procroute-svc), LocalSystem, automatic start,
;   restarted 5 s after an unexpected exit.
; - Before an upgrade the service is stopped (net stop waits for it) so its files can be replaced.
; - Before uninstalling, the service is stopped and deleted: the service exiting closes its WinDivert
;   handles and withdraws every filter (C-NET-06), and sing-box ends with its job object. The UI's
;   autostart entry is removed too. The configuration in %ProgramData%\ProcRoute is kept.
; The installer never changes certificate trust, and nothing needs it to: the service only requires the
; UI to be signed with its own certificate (ADR 0002).

!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'net.exe stop ProcRoute'
  Pop $0
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog 'sc.exe create ProcRoute binPath= "\"$INSTDIR\procroute-svc.exe\"" start= auto DisplayName= "ProcRoute"'
  Pop $0
  ${If} $0 != 0
    ; upgrade: the service is already registered, update its path and start type
    nsExec::ExecToLog 'sc.exe config ProcRoute binPath= "\"$INSTDIR\procroute-svc.exe\"" start= auto'
    Pop $0
  ${EndIf}
  nsExec::ExecToLog 'sc.exe description ProcRoute "ProcRoute process-level proxy service"'
  Pop $0
  nsExec::ExecToLog 'sc.exe failure ProcRoute reset= 86400 actions= restart/5000/restart/5000//'
  Pop $0
  nsExec::ExecToLog 'net.exe start ProcRoute'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'net.exe stop ProcRoute'
  Pop $0
  nsExec::ExecToLog 'sc.exe delete ProcRoute'
  Pop $0
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "ProcRoute"
!macroend
