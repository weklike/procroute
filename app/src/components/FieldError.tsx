// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

type Props = {
  id: string
  /** i18n 键（前端校验或服务端问题码映射而来）。 */
  message: string | undefined
  values?: Record<string, unknown>
}

/** 字段下方的错误提示；输入框用 `aria-describedby` 指向它。 */
export default function FieldError({ id, message, values }: Props) {
  const { t } = useTranslation()
  if (!message) return null
  return (
    <p id={id} className="text-destructive text-[13px]">
      {t(message, values)}
    </p>
  )
}
