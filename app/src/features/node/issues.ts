// SPDX-License-Identifier: GPL-3.0-or-later
// 导入问题的原因代码 → 界面文案。代码来自服务（procroute-core-mgr::link 与 svc 的去重），
// 只含固定代码，不含输入内容；未知代码原样显示，不丢信息。
import type { TFunction } from 'i18next'

import type { ImportIssue } from '@/api/generated'

export function importIssueText(t: TFunction, issue: ImportIssue): string {
  const reason = t(`node.import.reasons.${issue.reason}`, { defaultValue: issue.reason })
  // 行号 0 表示针对整段输入（例如 clash_yaml_unsupported）
  return issue.line > 0 ? t('node.import.issue', { line: issue.line, reason }) : reason
}
