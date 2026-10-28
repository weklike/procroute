// SPDX-License-Identifier: GPL-3.0-or-later
// 默认语言。新增文案先加在这里，再同步 en-US（C-UI-04）。
const zhCN = {
  app: {
    title: 'ProcRoute',
    tagline: '只让指定的进程走代理',
  },
  nav: {
    label: '主导航',
    profiles: '方案',
    nodes: '节点',
    connections: '连接',
    logs: '日志',
    settings: '设置',
    version: '版本 {{version}}',
  },
  common: {
    loading: '加载中…',
    retry: '重试',
    cancel: '取消',
    close: '关闭',
    all: '全部',
    loadFailed: '加载失败：{{message}}',
  },
  errors: {
    'ipc.transport': '无法连接到 ProcRoute 服务',
    'ipc.version_mismatch': '界面与服务版本不匹配，请重新安装',
    'ipc.invalid_request': '请求格式错误',
    'ipc.payload_too_large': '请求内容过大',
    'ipc.unauthorized': '没有权限调用服务',
    'ipc.unknown_method': '服务不支持该操作',
    'ipc.invalid_params': '参数不正确',
    'session.already_running': '会话已在运行',
    'session.not_running': '会话没有在运行',
    'profile.not_found': '方案不存在',
    'profile.invalid_schema': '方案中有字段未通过校验',
    'profile.in_use': '方案正在被会话使用',
    'node.not_found': '节点不存在',
    'node.import_failed': '导入失败',
    'driver.not_loaded': '驱动未加载',
    'driver.load_failed': '驱动加载失败',
    'driver.busy': '驱动正在使用中',
    'kernel.unavailable': '代理内核不可用',
    'internal.error': '服务内部错误',
  },
  pages: {
    profiles: { title: '方案', hint: '选择哪些进程走代理、走哪个出站' },
    nodes: { title: '节点', hint: '凭据加密保存在本机，界面不显示密码和密钥' },
    connections: { title: '连接', hint: '只列出被改道的连接；未命中规则的进程不会出现在这里' },
    logs: { title: '日志', hint: '只保存在本机；日志中不会出现密码、密钥等凭据' },
    settings: { title: '设置', hint: '界面偏好与运行环境' },
  },
  settings: {
    general: '常规',
    language: '界面语言',
    theme: '外观',
    themes: { system: '跟随系统', light: '浅色', dark: '深色' },
  },
}

export default zhCN
export type Messages = typeof zhCN
