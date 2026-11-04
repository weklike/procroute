// SPDX-License-Identifier: GPL-3.0-or-later
// 方案领域的 Query / Mutation hook（设计文档 13.2）。组件只能通过这里访问服务（C-CODE-09）。
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { call, IpcError } from '@/api/client'
import type { FieldIssue, Profile } from '@/api/generated'
import { inShell, pickFolder } from '@/api/shell'

export const profileKeys = {
  all: ['profile'] as const,
  detail: (id: string) => ['profile', id] as const,
  processes: ['process', 'list'] as const,
}

export function useProfiles() {
  return useQuery({ queryKey: profileKeys.all, queryFn: () => call('profile.list', {}) })
}

/** 读取单个方案；`id` 为空时不请求。 */
export function useProfile(id: string | null) {
  return useQuery({
    queryKey: profileKeys.detail(id ?? ''),
    queryFn: () => call('profile.get', { id: id ?? '' }),
    enabled: id !== null,
  })
}

export function useSaveProfile() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (p: Profile) => call('profile.save', p),
    onSuccess: () => qc.invalidateQueries({ queryKey: profileKeys.all }),
  })
}

export function useDeleteProfile() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => call('profile.delete', { id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: profileKeys.all }),
  })
}

/** 运行中的进程，用于「添加进程」对话框。 */
export function useProcesses(enabled: boolean) {
  return useQuery({
    queryKey: profileKeys.processes,
    queryFn: () => call('process.list', {}),
    enabled,
  })
}

/** 系统的文件夹选择对话框；`available` 为 false 时（不在桌面外壳里）界面不显示入口。 */
export function useFolderPicker() {
  const mutation = useMutation({ mutationFn: (title: string) => pickFolder(title) })
  return {
    available: inShell(),
    isPending: mutation.isPending,
    pick: (title: string, onPicked: (path: string | null) => void) =>
      mutation.mutate(title, { onSuccess: onPicked }),
  }
}

/** 取出服务端返回的逐字段校验问题；不是校验错误时为空。 */
export function fieldIssues(e: unknown): readonly FieldIssue[] {
  return e instanceof IpcError ? e.fields : []
}
