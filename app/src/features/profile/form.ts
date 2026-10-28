// SPDX-License-Identifier: GPL-3.0-or-later
// 方案表单的 Zod 模式。前端校验只为体验，保存后以服务端返回的错误为准（AGENTS 5.2）；
// 规则与 procroute-config 的校验保持一致，错误消息是 i18n 键。
import { z } from 'zod'

import type { MatchRule, MatchType, Profile } from '@/api/generated'

export const MAX_NAME = 64
const TAG = /^[a-z0-9_-]{1,32}$/

export const MATCH_TYPES = ['name', 'path', 'dir', 'glob', 'regex'] as const satisfies MatchType[]

const ruleSchema = z.object({
  type: z.enum(MATCH_TYPES),
  value: z.string().trim().min(1, 'profile.validation.empty'),
  recursive: z.boolean(),
})

const groupSchema = z.object({
  tag: z.string().regex(TAG, 'profile.validation.invalidTag'),
  outbound: z.string().trim().min(1, 'profile.validation.empty'),
  include_children: z.boolean(),
  match: z.array(ruleSchema).min(1, 'profile.validation.noRules'),
})

export const profileSchema = z
  .object({
    schema_version: z.number(),
    id: z.string(),
    name: z
      .string()
      .trim()
      .min(1, 'profile.validation.empty')
      .max(MAX_NAME, 'profile.validation.tooLong'),
    mode: z.enum(['precise', 'tun']),
    fail_policy: z.enum(['block', 'allow']),
    dns: z.object({
      strategy: z.enum(['sniff', 'system_takeover']),
      hijack_port53: z.boolean(),
    }),
    udp: z.object({ enabled: z.boolean(), block_quic: z.boolean() }),
    groups: z.array(groupSchema),
    exclude: z.array(ruleSchema),
  })
  .superRefine((p, ctx) => {
    const seen = new Set<string>()
    p.groups.forEach((g, i) => {
      if (seen.has(g.tag)) {
        ctx.addIssue({
          code: 'custom',
          path: ['groups', i, 'tag'],
          message: 'profile.validation.duplicateTag',
        })
      }
      seen.add(g.tag)
    })
  })

export type ProfileForm = z.input<typeof profileSchema>
export type ProfileValues = z.output<typeof profileSchema>

// 编译期检查：表单值与线上的 Profile 结构一致
const sameShape: Profile = {} as ProfileValues
void sameShape

/** 新方案：所有安全相关的选项取默认值（fail-closed、DNS 嗅探，C-NET-03、C-NET-09）。 */
export function newProfile(name: string): Profile {
  return {
    schema_version: 1,
    id: '',
    name,
    mode: 'precise',
    fail_policy: 'block',
    dns: { strategy: 'sniff', hijack_port53: true },
    udp: { enabled: true, block_quic: false },
    groups: [],
    exclude: [],
  }
}

/** 服务端字段路径 `groups[1].match[0].value` → 表单路径 `groups.1.match.0.value`。 */
export function formPath(serverPath: string): string {
  return serverPath.replace(/\[(\d+)\]/g, '.$1')
}

/** 进程路径所在目录（Windows 路径）。 */
export function parentDir(path: string): string {
  const i = Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/'))
  return i > 0 ? path.slice(0, i) : path
}

export function makeRule(type: MatchType, value: string): MatchRule {
  return { type, value, recursive: type === 'dir' }
}
