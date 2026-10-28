// SPDX-License-Identifier: GPL-3.0-or-later
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

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
import { errorText } from '@/lib/errors'

import { useDeleteProfile } from './api'

type Props = { id: string; name: string; onDeleted: () => void }

export default function DeleteProfileDialog({ id, name, onDeleted }: Props) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const del = useDeleteProfile()
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) del.reset()
      }}
    >
      <DialogTrigger asChild>
        <Button type="button" variant="ghost" className="text-destructive mr-auto">
          {t('profile.delete')}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('profile.deleteTitle', { name })}</DialogTitle>
          <DialogDescription>{t('profile.deleteBody')}</DialogDescription>
        </DialogHeader>
        {del.isError ? (
          <Alert variant="destructive">
            <AlertDescription>{errorText(t, del.error)}</AlertDescription>
          </Alert>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="destructive"
            disabled={del.isPending}
            onClick={() =>
              del.mutate(id, {
                onSuccess: () => {
                  setOpen(false)
                  onDeleted()
                },
              })
            }
          >
            {t('profile.delete')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
