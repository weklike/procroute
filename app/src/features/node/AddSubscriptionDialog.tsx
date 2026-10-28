// SPDX-License-Identifier: GPL-3.0-or-later
// 添加订阅。订阅地址常含令牌，视同凭据：提交后清空，之后只显示 scheme://host（C-SEC-04）。
import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { z } from 'zod'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { errorText } from '@/lib/errors'

import { useImportNodes } from './api'

const schema = z.object({
  name: z.string().trim().min(1, 'profile.validation.empty').max(64, 'profile.validation.tooLong'),
  url: z
    .string()
    .trim()
    .regex(/^https?:\/\/\S+$/i, 'node.subscription.invalidUrl'),
})
type Values = z.infer<typeof schema>
const EMPTY: Values = { name: '', url: '' }

export default function AddSubscriptionDialog() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const importNodes = useImportNodes()
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: EMPTY })
  const { errors } = form.formState

  const submit = form.handleSubmit((values) => {
    form.reset(EMPTY)
    importNodes.mutate(
      { kind: 'subscription', name: values.name, url: values.url },
      { onSuccess: () => setOpen(false) },
    )
  })

  const onOpenChange = (next: boolean) => {
    setOpen(next)
    if (!next) {
      form.reset(EMPTY)
      importNodes.reset()
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button>{t('node.addSubscription')}</Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>{t('node.subscription.title')}</DialogTitle>
            <DialogDescription>{t('node.subscription.hint')}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            <Label htmlFor="sub-name">{t('node.subscription.name')}</Label>
            <Input
              id="sub-name"
              aria-invalid={errors.name ? true : undefined}
              {...form.register('name')}
            />
            {errors.name?.message ? (
              <p className="text-destructive text-[13px]">{t(errors.name.message, { max: 64 })}</p>
            ) : null}
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="sub-url">{t('node.subscription.url')}</Label>
            <Input
              id="sub-url"
              type="url"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={errors.url ? true : undefined}
              {...form.register('url')}
            />
            {errors.url?.message ? (
              <p className="text-destructive text-[13px]">{t(errors.url.message)}</p>
            ) : null}
          </div>
          {importNodes.isError ? (
            <Alert variant="destructive">
              <AlertDescription>{errorText(t, importNodes.error)}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="submit" disabled={importNodes.isPending}>
              {t('node.subscription.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
