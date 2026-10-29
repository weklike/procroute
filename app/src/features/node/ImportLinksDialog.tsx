// SPDX-License-Identifier: GPL-3.0-or-later
// 导入分享链接。链接里含凭据：只写不读，提交后立即清空输入框，结果只显示数量和行号（C-SEC-04、C-UI-03）。
import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { z } from 'zod'

import type { NodeImportResult } from '@/api/generated'
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
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { errorText } from '@/lib/errors'

import { useImportNodes } from './api'
import { importIssueText } from './issues'

const schema = z.object({ text: z.string().trim().min(1, 'node.import.required') })
type Values = z.infer<typeof schema>

export default function ImportLinksDialog() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [result, setResult] = useState<NodeImportResult | null>(null)
  const importNodes = useImportNodes()
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { text: '' } })
  const error = form.formState.errors.text?.message

  const submit = form.handleSubmit((values) => {
    // 先清空再等待结果：链接不在界面上多停留一刻
    form.reset({ text: '' })
    setResult(null)
    importNodes.mutate({ kind: 'share_links', text: values.text }, { onSuccess: setResult })
  })

  const onOpenChange = (next: boolean) => {
    setOpen(next)
    if (!next) {
      form.reset({ text: '' })
      setResult(null)
      importNodes.reset()
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline">{t('node.importLinks')}</Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>{t('node.import.title')}</DialogTitle>
            <DialogDescription>{t('node.import.hint')}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            <Label htmlFor="import-links">{t('node.import.label')}</Label>
            <Textarea
              id="import-links"
              rows={6}
              autoComplete="off"
              spellCheck={false}
              className="font-mono text-xs"
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? 'import-links-error' : undefined}
              {...form.register('text')}
            />
            {error ? (
              <p id="import-links-error" className="text-destructive text-[13px]">
                {t(error)}
              </p>
            ) : null}
          </div>
          {importNodes.isError ? (
            <Alert variant="destructive">
              <AlertDescription>{errorText(t, importNodes.error)}</AlertDescription>
            </Alert>
          ) : null}
          {result ? (
            <div role="status" className="flex flex-col gap-1 text-[13px]">
              <span className="font-medium">
                {t('node.import.result', { added: result.added, skipped: result.skipped })}
              </span>
              <ul className="text-muted-foreground">
                {result.issues.map((i) => (
                  <li key={`${i.line}:${i.reason}`}>{importIssueText(t, i)}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <DialogFooter>
            <Button type="submit" disabled={importNodes.isPending}>
              {t('node.import.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
