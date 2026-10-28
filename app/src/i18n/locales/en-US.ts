// SPDX-License-Identifier: GPL-3.0-or-later
import type { Messages } from './zh-CN'

// 类型约束保证与 zh-CN 的键完全一致
const enUS: Messages = {
  app: {
    title: 'ProcRoute',
    tagline: 'Proxy only the processes you choose',
  },
  nav: {
    label: 'Main navigation',
    profiles: 'Profiles',
    nodes: 'Nodes',
    connections: 'Connections',
    logs: 'Logs',
    settings: 'Settings',
    version: 'Version {{version}}',
  },
  common: {
    loading: 'Loading…',
    retry: 'Retry',
    cancel: 'Cancel',
    close: 'Close',
    all: 'All',
    loadFailed: 'Failed to load: {{message}}',
  },
  errors: {
    'ipc.transport': 'Cannot reach the ProcRoute service',
    'ipc.version_mismatch': 'The app and the service versions do not match; please reinstall',
    'ipc.invalid_request': 'Malformed request',
    'ipc.payload_too_large': 'Request is too large',
    'ipc.unauthorized': 'Not allowed to call the service',
    'ipc.unknown_method': 'The service does not support this action',
    'ipc.invalid_params': 'Invalid parameters',
    'session.already_running': 'A session is already running',
    'session.not_running': 'No session is running',
    'profile.not_found': 'Profile not found',
    'profile.invalid_schema': 'Some fields in the profile are invalid',
    'profile.in_use': 'The profile is used by the running session',
    'node.not_found': 'Node not found',
    'node.import_failed': 'Import failed',
    'driver.not_loaded': 'Driver is not loaded',
    'driver.load_failed': 'Driver failed to load',
    'driver.busy': 'Driver is in use',
    'kernel.unavailable': 'Proxy core is unavailable',
    'internal.error': 'Internal service error',
  },
  pages: {
    profiles: {
      title: 'Profiles',
      hint: 'Choose which processes use the proxy and through which outbound',
    },
    nodes: {
      title: 'Nodes',
      hint: 'Credentials stay encrypted on this computer and are never shown',
    },
    connections: {
      title: 'Connections',
      hint: 'Only redirected connections are listed; processes without a matching rule never appear',
    },
    logs: {
      title: 'Logs',
      hint: 'Stored on this computer only; logs never contain passwords or keys',
    },
    settings: { title: 'Settings', hint: 'Interface preferences and runtime environment' },
  },
  settings: {
    general: 'General',
    language: 'Language',
    theme: 'Appearance',
    themes: { system: 'System', light: 'Light', dark: 'Dark' },
  },
}

export default enUS
