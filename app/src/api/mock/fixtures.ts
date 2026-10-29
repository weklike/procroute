// SPDX-License-Identifier: GPL-3.0-or-later
// 模拟服务的示例数据，取自界面设计稿。
//
// 只在开发构建、且不在 Tauri 里运行时加载；生产构建不包含本文件（见 client.ts）。
// 地址全部使用文档保留段（RFC 2606 / RFC 5737），不是真实节点（C-SEC-09）。
import type { NodeInfo, OutboundInfo, ProcessInfo, Profile, SubscriptionInfo } from '../generated'

export const PROFILES: Profile[] = [
  {
    schema_version: 1,
    id: 'p-game',
    name: '游戏加速',
    mode: 'precise',
    fail_policy: 'block',
    dns: { strategy: 'sniff', hijack_port53: true, remote_server: null },
    udp: { enabled: true, block_quic: false },
    groups: [
      {
        tag: 'game',
        outbound: 'hk-auto',
        include_children: true,
        match: [
          { type: 'dir', value: 'D:\\Games\\MyGame', recursive: true },
          { type: 'name', value: 'launcher.exe', recursive: false },
        ],
      },
      {
        tag: 'browser',
        outbound: 'us-01',
        include_children: false,
        match: [
          {
            type: 'path',
            value: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
            recursive: false,
          },
        ],
      },
    ],
    exclude: [{ type: 'name', value: 'updater.exe', recursive: false }],
  },
  {
    schema_version: 1,
    id: 'p-browser',
    name: '浏览器分流',
    mode: 'precise',
    fail_policy: 'block',
    dns: { strategy: 'sniff', hijack_port53: true, remote_server: null },
    udp: { enabled: true, block_quic: true },
    groups: [
      {
        tag: 'browser',
        outbound: 'us-01',
        include_children: true,
        match: [{ type: 'name', value: 'chrome.exe', recursive: false }],
      },
    ],
    exclude: [],
  },
  {
    schema_version: 1,
    id: 'p-dev',
    name: '开发工具',
    mode: 'tun',
    fail_policy: 'block',
    dns: { strategy: 'sniff', hijack_port53: true, remote_server: null },
    udp: { enabled: true, block_quic: false },
    groups: [
      {
        tag: 'editor',
        outbound: 'jp-01',
        include_children: true,
        match: [{ type: 'name', value: 'Code.exe', recursive: false }],
      },
      {
        tag: 'git',
        outbound: 'jp-01',
        include_children: false,
        match: [{ type: 'glob', value: 'C:\\Program Files\\Git\\**\\*.exe', recursive: false }],
      },
      {
        tag: 'node',
        outbound: 'us-01',
        include_children: true,
        match: [{ type: 'regex', value: '^.*\\\\node(\\.exe)?$', recursive: false }],
      },
    ],
    exclude: [],
  },
]

export const NODES: NodeInfo[] = [
  {
    id: 'n-hk1',
    name: '香港 01',
    protocol: 'anytls',
    server: 'hk1.example.net:443',
    subscription_id: 's-1',
    credential: 'set',
  },
  {
    id: 'n-hk2',
    name: '香港 02',
    protocol: 'vless',
    server: 'hk2.example.net:443',
    subscription_id: 's-1',
    credential: 'set',
  },
  {
    id: 'n-hk3',
    name: '香港 03',
    protocol: 'hysteria2',
    server: 'hk3.example.net:8443',
    subscription_id: 's-1',
    credential: 'set',
  },
  {
    id: 'n-us1',
    name: '美国 01',
    protocol: 'trojan',
    server: 'us1.example.net:443',
    subscription_id: 's-1',
    credential: 'set',
  },
  {
    id: 'n-jp1',
    name: '日本 01',
    protocol: 'tuic',
    server: 'jp1.example.net:443',
    subscription_id: 's-1',
    credential: 'set',
  },
]

export const OUTBOUNDS: OutboundInfo[] = [
  { tag: 'hk-auto', kind: 'url_test', members: ['n-hk1', 'n-hk2', 'n-hk3'], current: 'n-hk1' },
  { tag: 'us-01', kind: 'single', members: ['n-us1'], current: 'n-us1' },
  { tag: 'jp-01', kind: 'single', members: ['n-jp1'], current: 'n-jp1' },
]

export const SUBSCRIPTIONS: SubscriptionInfo[] = [
  {
    id: 's-1',
    name: '我的订阅',
    url_display: 'https://sub.example.com',
    node_count: 5,
    updated_at_ms: Date.UTC(2026, 9, 28, 2, 0),
  },
]

export const PROCESSES: ProcessInfo[] = [
  {
    pid: 4120,
    name: 'MyGame.exe',
    path: 'D:\\Games\\MyGame\\MyGame.exe',
    matched_group: 'game',
  },
  {
    pid: 3388,
    name: 'launcher.exe',
    path: 'D:\\Games\\MyGame\\launcher.exe',
    matched_group: 'game',
  },
  {
    pid: 2216,
    name: 'steam.exe',
    path: 'C:\\Program Files (x86)\\Steam\\steam.exe',
    matched_group: null,
  },
  {
    pid: 6604,
    name: 'Discord.exe',
    path: 'C:\\Users\\dev\\AppData\\Local\\Discord\\app-1.0\\Discord.exe',
    matched_group: null,
  },
  {
    pid: 9012,
    name: 'chrome.exe',
    path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    matched_group: null,
  },
  {
    pid: 7720,
    name: 'firefox.exe',
    path: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
    matched_group: 'browser',
  },
]

/** 模拟连接：进程、目标、协议、组、出站。 */
export const CONNECTIONS = [
  ['MyGame.exe', 4120, '203.0.113.24:27015', 'udp', 'game', 'hk-auto'],
  ['MyGame.exe', 4120, 'login.game.example:443', 'tcp', 'game', 'hk-auto'],
  ['MyGame.exe', 4120, '203.0.113.80:3478', 'udp', 'game', 'hk-auto'],
  ['launcher.exe', 3388, 'cdn.game.example:443', 'tcp', 'game', 'hk-auto'],
  ['launcher.exe', 3388, 'api.game.example:443', 'tcp', 'game', 'hk-auto'],
  ['CrashReporter.exe', 5012, 'report.game.example:443', 'tcp', 'game', 'hk-auto'],
  ['firefox.exe', 7720, 'www.example.com:443', 'tcp', 'browser', 'us-01'],
  ['firefox.exe', 7720, 'video.example.net:443', 'udp', 'browser', 'us-01'],
] as const

/** 模拟日志：级别、模块、消息、字段。不含任何凭据（C-SEC-04）。 */
export const LOGS = [
  ['info', 'svc', '会话已启动', { mode: 'precise' }],
  ['info', 'core-mgr', 'sing-box 已启动，SHA256 校验通过', { pid: '6120' }],
  ['info', 'intercept', 'WinDivert 过滤器已打开', { layers: 'socket,network' }],
  ['info', 'procwatch', '已为运行中的进程补登', { matched: '3', group: 'game' }],
  ['debug', 'intercept', '首个 SYN 暂存后归属成功', { pid: '4120', held_ms: '12' }],
  ['info', 'relay', '流已改道', { pid: '4120', rule: 'game', outbound: 'hk-auto' }],
  ['info', 'procwatch', '子进程已纳入', { pid: '5012', parent: '4120', group: 'game' }],
  ['warn', 'intercept', '流未能归属，按非目标放行', { local_port: '52114' }],
  ['warn', 'core-mgr', 'sing-box 异常退出，正在重启', { attempt: '1/3' }],
  ['error', 'relay', '本地 SOCKS 入口不可达，按阻断策略拒绝新连接', { policy: 'block' }],
] as const
