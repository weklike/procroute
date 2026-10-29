// SPDX-License-Identifier: GPL-3.0-or-later
//! Tauri 外壳：命令、事件转发、主窗口与托盘（T-113 的外壳部分）。
//!
//! - `ipc_call`：前端的唯一服务入口，转给 [`Client`]；服务推送的通知按 `client.ts` 的规则改名后
//!   发成前端事件（`conn.subscribe` → `ipc:conn:subscribe`），连接变化发 [`CONNECTION_EVENT`]；
//! - 关闭主窗口只是隐藏到托盘，退出走托盘菜单；
//! - 托盘菜单由前端用 `tray_update` 下发：文案来自前端的 i18n 资源（C-UI-04），
//!   点击后外壳只处理「显示主窗口」「退出」，其余菜单项发 [`TRAY_EVENT`] 交给前端
//!   （启动 / 停止会话、切换方案都走前端已有的 IPC 调用）；
//! - `autostart_*`：开机自启写当前用户的 Run 键，自启时带 [`MINIMIZED_ARG`]，只进托盘不弹窗。

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use tauri::menu::{
    CheckMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime, State, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

use crate::ipc::{CallError, Client, Outbound, PIPE_NAME};

/// 主窗口标签，与 `tauri.conf.json` 一致。
const MAIN_WINDOW: &str = "main";
/// 托盘图标 id。
const TRAY_ID: &str = "main";
/// 开机自启时的命令行参数：启动后不显示主窗口。
const MINIMIZED_ARG: &str = "--minimized";

/// 与服务的连接建立或断开，负载为布尔值。
pub const CONNECTION_EVENT: &str = "shell:connection";
/// 托盘菜单项被点击，负载为菜单项 id。
pub const TRAY_EVENT: &str = "shell:tray";

/// 外壳自己处理的托盘菜单项。
const TRAY_SHOW: &str = "shell.show";
const TRAY_QUIT: &str = "shell.quit";

/// 托盘菜单的规模上限：菜单由前端下发，标签里有方案名等用户数据。
const MAX_TRAY_ENTRIES: usize = 64;
const MAX_TRAY_LABEL_CHARS: usize = 128;
const MAX_TRAY_ID_CHARS: usize = 64;

pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![MINIMIZED_ARG]),
        ))
        .invoke_handler(tauri::generate_handler![
            ipc_call,
            tray_update,
            autostart_get,
            autostart_set
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let client = Arc::new(Client::new(
                PIPE_NAME,
                Arc::new(move |out| forward(&handle, out)),
            ));
            app.manage(client.clone());
            tauri::async_runtime::spawn(client.keep_connected());
            create_tray(app.handle())?;
            if !std::env::args().any(|a| a == MINIMIZED_ARG) {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event
                && window.label() == MAIN_WINDOW
            {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!());
    if let Err(e) = result {
        // 发布构建没有控制台；错误码交给启动方
        eprintln!("procroute-ui failed: {e}");
        std::process::exit(1);
    }
}

/// 前端的唯一服务入口（C-CODE-09）。
#[tauri::command]
async fn ipc_call(
    client: State<'_, Arc<Client>>,
    method: String,
    params: Value,
) -> Result<Value, CallError> {
    client.call(&method, params).await
}

/// 服务推送的消息 → 前端事件。
fn forward<R: Runtime>(app: &AppHandle<R>, out: Outbound) {
    let _ = match out {
        Outbound::Notification { channel, payload } => app.emit(&event_name(&channel), payload),
        Outbound::Connection(up) => app.emit(CONNECTION_EVENT, up),
    };
}

/// 与 `app/src/api/client.ts` 的 `tauriEventName` 相同的规则。
fn event_name(channel: &str) -> String {
    format!("ipc:{}", channel.replace('.', ":"))
}

fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn create_tray(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("ProcRoute")
        .show_menu_on_left_click(false)
        .on_menu_event(on_tray_menu)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn on_tray_menu<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id().as_ref() {
        TRAY_SHOW => show_main(app),
        TRAY_QUIT => app.exit(0),
        other => {
            let _ = app.emit(TRAY_EVENT, other);
        }
    }
}

/// 前端下发的托盘菜单。
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrayModel {
    tooltip: String,
    items: Vec<TrayEntry>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TrayEntry {
    Action {
        id: String,
        label: String,
        enabled: bool,
    },
    Check {
        id: String,
        label: String,
        checked: bool,
        enabled: bool,
    },
    Separator,
    /// 只允许一层子菜单。
    Submenu {
        label: String,
        enabled: bool,
        items: Vec<TrayEntry>,
    },
}

impl TrayModel {
    /// 检查规模与内容：条目数、标签长度、id 长度、子菜单层数，标签不能含控制字符。
    fn validate(&self) -> Result<(), String> {
        check_label(&self.tooltip)?;
        let mut count = 0;
        check_entries(&self.items, 0, &mut count)
    }
}

fn check_entries(items: &[TrayEntry], depth: u8, count: &mut usize) -> Result<(), String> {
    for item in items {
        *count += 1;
        if *count > MAX_TRAY_ENTRIES {
            return Err(format!(
                "tray menu has more than {MAX_TRAY_ENTRIES} entries"
            ));
        }
        match item {
            TrayEntry::Action { id, label, .. } | TrayEntry::Check { id, label, .. } => {
                check_label(label)?;
                if id.is_empty() || id.chars().count() > MAX_TRAY_ID_CHARS {
                    return Err("tray menu id is empty or too long".to_owned());
                }
            }
            TrayEntry::Separator => {}
            TrayEntry::Submenu { label, items, .. } => {
                check_label(label)?;
                if depth > 0 {
                    return Err("tray submenus cannot be nested".to_owned());
                }
                check_entries(items, depth + 1, count)?;
            }
        }
    }
    Ok(())
}

fn check_label(label: &str) -> Result<(), String> {
    if label.chars().count() > MAX_TRAY_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err("tray label is too long or contains control characters".to_owned());
    }
    Ok(())
}

/// 用前端下发的模型替换托盘菜单与提示文字。
#[tauri::command]
fn tray_update(app: AppHandle, model: TrayModel) -> Result<(), String> {
    model.validate()?;
    let tray = app
        .tray_by_id(TRAY_ID)
        .ok_or_else(|| "the tray icon is not available".to_owned())?;
    let menu = Menu::new(&app).map_err(|e| e.to_string())?;
    for item in &model.items {
        let built = build_entry(&app, item).map_err(|e| e.to_string())?;
        menu.append(built.as_ref()).map_err(|e| e.to_string())?;
    }
    tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    tray.set_tooltip(Some(&model.tooltip))
        .map_err(|e| e.to_string())
}

fn build_entry<R: Runtime>(
    app: &AppHandle<R>,
    entry: &TrayEntry,
) -> tauri::Result<Box<dyn IsMenuItem<R>>> {
    Ok(match entry {
        TrayEntry::Action { id, label, enabled } => Box::new(MenuItem::with_id(
            app,
            id.as_str(),
            label,
            *enabled,
            None::<&str>,
        )?),
        TrayEntry::Check {
            id,
            label,
            checked,
            enabled,
        } => Box::new(CheckMenuItem::with_id(
            app,
            id.as_str(),
            label,
            *enabled,
            *checked,
            None::<&str>,
        )?),
        TrayEntry::Separator => Box::new(PredefinedMenuItem::separator(app)?),
        TrayEntry::Submenu {
            label,
            enabled,
            items,
        } => {
            let sub = Submenu::new(app, label, *enabled)?;
            for item in items {
                sub.append(build_entry(app, item)?.as_ref())?;
            }
            Box::new(sub)
        }
    })
}

/// 是否已开机自启。
#[tauri::command]
fn autostart_get(app: AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// 开启或关闭开机自启，返回之后的实际状态。
#[tauri::command]
fn autostart_set(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let launcher = app.autolaunch();
    let changed = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    changed.map_err(|e| e.to_string())?;
    launcher.is_enabled().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn event_names_follow_the_front_end_rule() {
        assert_eq!(event_name("conn.subscribe"), "ipc:conn:subscribe");
        assert_eq!(event_name("session.status"), "ipc:session:status");
    }

    fn model(items: Value) -> TrayModel {
        serde_json::from_value(json!({ "tooltip": "ProcRoute", "items": items })).expect("model")
    }

    #[test]
    fn tray_models_parse_and_validate() {
        let m = model(json!([
            { "kind": "action", "id": "shell.show", "label": "显示主窗口", "enabled": true },
            { "kind": "separator" },
            { "kind": "submenu", "label": "切换方案", "enabled": true, "items": [
                { "kind": "check", "id": "profile:p1", "label": "游戏加速", "checked": true, "enabled": true }
            ] },
            { "kind": "action", "id": "shell.quit", "label": "退出", "enabled": true }
        ]));
        assert_eq!(m.items.len(), 4);
        m.validate().expect("valid");
    }

    #[test]
    fn oversized_or_nested_tray_models_are_rejected() {
        let nested = model(
            json!([{ "kind": "submenu", "label": "a", "enabled": true, "items": [
            { "kind": "submenu", "label": "b", "enabled": true, "items": [] }
        ] }]),
        );
        assert!(nested.validate().is_err());

        let many: Vec<Value> = (0..=MAX_TRAY_ENTRIES)
            .map(|i| json!({ "kind": "action", "id": format!("x{i}"), "label": "x", "enabled": true }))
            .collect();
        assert!(model(Value::Array(many)).validate().is_err());

        let long = "长".repeat(MAX_TRAY_LABEL_CHARS + 1);
        let m = model(json!([{ "kind": "action", "id": "a", "label": long, "enabled": true }]));
        assert!(m.validate().is_err());

        let control =
            model(json!([{ "kind": "action", "id": "a", "label": "a\u{0}b", "enabled": true }]));
        assert!(control.validate().is_err());

        let empty_id =
            model(json!([{ "kind": "action", "id": "", "label": "a", "enabled": true }]));
        assert!(empty_id.validate().is_err());
    }

    #[test]
    fn unknown_entry_kinds_are_rejected() {
        let bad = serde_json::from_value::<TrayModel>(json!({
            "tooltip": "x", "items": [{ "kind": "html", "id": "a", "label": "<b>", "enabled": true }]
        }));
        assert!(bad.is_err());
    }
}
