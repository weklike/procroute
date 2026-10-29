// SPDX-License-Identifier: GPL-3.0-or-later
// 节点测速地址。软件不内置任何地址，由用户填写（C-SEC-08、C-SEC-09）；只保存在界面偏好里，
// 测速时随 `node.test` 交给服务，服务会再校验一次。
import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { z } from 'zod'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useUiStore } from '@/stores/ui'

const schema = z.object({
  url: z
    .string()
    .trim()
    .max(2048, 'settings.latencyUrlInvalid')
    // 只接受 https：锁定版本的 sing-box 会把 http:// 测速地址换成它内置的默认地址（C-SEC-09）
    .refine((v) => v === '' || /^https:\/\/[^\s/?#]+\S*$/.test(v), 'settings.latencyUrlInvalid'),
})
type Values = z.infer<typeof schema>

export default function LatencyUrlForm() {
  const { t } = useTranslation()
  const url = useUiStore((s) => s.latencyTestUrl)
  const setUrl = useUiStore((s) => s.setLatencyTestUrl)
  const [saved, setSaved] = useState(false)
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { url } })
  const { errors } = form.formState

  const submit = form.handleSubmit((values) => {
    setUrl(values.url)
    form.reset(values)
    setSaved(true)
  })

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-2">
      <Label htmlFor="settings-latency-url">{t('settings.latencyUrl')}</Label>
      <p id="settings-latency-url-hint" className="text-muted-foreground text-[13px]">
        {t('settings.latencyUrlHint')}
      </p>
      <div className="flex gap-2">
        <Input
          id="settings-latency-url"
          type="url"
          autoComplete="off"
          spellCheck={false}
          aria-describedby="settings-latency-url-hint"
          aria-invalid={errors.url ? true : undefined}
          {...form.register('url', { onChange: () => setSaved(false) })}
        />
        <Button type="submit" variant="outline">
          {t('settings.save')}
        </Button>
      </div>
      {errors.url?.message ? (
        <p className="text-destructive text-[13px]">{t(errors.url.message)}</p>
      ) : null}
      {saved ? (
        <p role="status" className="text-muted-foreground text-[13px]">
          {t('settings.saved')}
        </p>
      ) : null}
    </form>
  )
}
