// SPDX-License-Identifier: GPL-3.0-or-later
// 节点领域的 Query / Mutation hook（设计文档 13.2）。组件只能通过这里访问服务（C-CODE-09）。
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { call } from '@/api/client'
import type { NodeImportParams, NodeTestParams } from '@/api/generated'

export const nodeKeys = {
  all: ['node'] as const,
}

/** 节点、出站与订阅。返回值里没有任何凭据（C-SEC-04）。 */
export function useNodes() {
  return useQuery({ queryKey: nodeKeys.all, queryFn: () => call('node.list', {}) })
}

/** 导入分享链接或添加订阅。 */
export function useImportNodes() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (p: NodeImportParams) => call('node.import', p),
    onSuccess: () => qc.invalidateQueries({ queryKey: nodeKeys.all }),
  })
}

/** 测延迟；结果保存在 mutation 状态里，由页面传给列表。 */
export function useTestNodes() {
  return useMutation({ mutationFn: (p: NodeTestParams) => call('node.test', p) })
}
