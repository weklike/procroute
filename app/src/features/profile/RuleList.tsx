// SPDX-License-Identifier: GPL-3.0-or-later
import { Plus, X } from 'lucide-react'
import { useState } from 'react'
import { useFieldArray, useFormContext } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import FieldError from '@/components/FieldError'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

import AddRuleDialog from './AddRuleDialog'
import type { ProfileForm } from './form'

type Props = {
  name: 'exclude' | `groups.${number}.match`
  addLabel: string
  dialogTitle: string
  dialogHint?: string
}

/** 一组匹配规则（进程组的规则或排除规则）：列出、删除、通过对话框添加。 */
export default function RuleList({ name, addLabel, dialogTitle, dialogHint }: Props) {
  const { t } = useTranslation()
  const { control, getFieldState, formState } = useFormContext<ProfileForm>()
  const { fields, append, remove } = useFieldArray({ control, name })
  const [adding, setAdding] = useState(false)
  const listError = getFieldState(name, formState).error
  const errorId = `${name}-error`

  return (
    <div className="flex flex-col gap-2">
      {fields.length === 0 ? (
        <p className="text-muted-foreground text-[13px]">{t('profile.noRules')}</p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {fields.map((f, i) => {
            const valueError = getFieldState(`${name}.${i}.value`, formState).error
            return (
              <li key={f.id} className="flex flex-col gap-1">
                <div className="bg-background flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[13px]">
                  <Badge variant="secondary">{t(`profile.ruleTypes.${f.type}`)}</Badge>
                  <span className="min-w-0 flex-1 truncate font-mono">{f.value}</span>
                  {f.type === 'dir' && f.recursive ? (
                    <span className="text-muted-foreground text-xs">{t('profile.recursive')}</span>
                  ) : null}
                  <Button
                    type="button"
                    size="icon-xs"
                    variant="ghost"
                    aria-label={t('profile.removeRule', { value: f.value })}
                    onClick={() => remove(i)}
                  >
                    <X aria-hidden="true" />
                  </Button>
                </div>
                <FieldError id={`${name}-${i}-error`} message={valueError?.message} />
              </li>
            )
          })}
        </ul>
      )}
      <FieldError id={errorId} message={listError?.message ?? listError?.root?.message} />
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="self-start"
        onClick={() => setAdding(true)}
      >
        <Plus aria-hidden="true" />
        {addLabel}
      </Button>
      <AddRuleDialog
        open={adding}
        onOpenChange={setAdding}
        title={dialogTitle}
        hint={dialogHint}
        onAdd={(rules) => append(rules)}
      />
    </div>
  )
}
