// SPDX-License-Identifier: GPL-3.0-or-later
import { Trash2 } from 'lucide-react'
import { useFormContext, useWatch } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import FieldError from '@/components/FieldError'
import NativeSelect from '@/components/NativeSelect'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

import type { ProfileForm } from './form'
import RuleList from './RuleList'

type Props = {
  index: number
  /** 可选的出站标签（来自节点页）。 */
  outbounds: readonly string[]
  onRemove: () => void
}

/** 一个进程组：标签、出站、是否包含子进程，以及组内规则。 */
export default function GroupCard({ index, outbounds, onRemove }: Props) {
  const { t } = useTranslation()
  const { register, control, getFieldState, formState } = useFormContext<ProfileForm>()
  const [tag, outbound, includeChildren] = useWatch({
    control,
    name: [`groups.${index}.tag`, `groups.${index}.outbound`, `groups.${index}.include_children`],
  })
  const tagError = getFieldState(`groups.${index}.tag`, formState).error
  const outboundError = getFieldState(`groups.${index}.outbound`, formState).error
  const choices = outbound && !outbounds.includes(outbound) ? [outbound, ...outbounds] : outbounds
  const base = `group-${index}`

  return (
    <div className="bg-background flex flex-col gap-3 rounded-xl border p-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex flex-col gap-1">
          <Label htmlFor={`${base}-tag`}>{t('profile.groupTag')}</Label>
          <Input
            id={`${base}-tag`}
            className="w-40 font-mono"
            placeholder={t('profile.groupTagHint')}
            aria-invalid={tagError ? true : undefined}
            aria-describedby={tagError ? `${base}-tag-error` : undefined}
            {...register(`groups.${index}.tag`)}
          />
          <FieldError id={`${base}-tag-error`} message={tagError?.message} />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor={`${base}-outbound`}>{t('profile.outbound')}</Label>
          <NativeSelect
            id={`${base}-outbound`}
            className="w-40 font-mono"
            aria-invalid={outboundError ? true : undefined}
            {...register(`groups.${index}.outbound`)}
          >
            <option value="" disabled>
              —
            </option>
            {choices.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </NativeSelect>
          <FieldError id={`${base}-outbound-error`} message={outboundError?.message} />
        </div>
        <label className="mt-6 flex items-center gap-2 text-[13px]">
          <input
            type="checkbox"
            className="accent-brand size-4"
            {...register(`groups.${index}.include_children`)}
          />
          {t('profile.includeChildren')}
        </label>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          className="mt-5 ml-auto"
          aria-label={t('profile.removeGroup', { tag: tag || index + 1 })}
          onClick={onRemove}
        >
          <Trash2 aria-hidden="true" />
        </Button>
      </div>
      <RuleList
        name={`groups.${index}.match`}
        addLabel={t('profile.addProcess')}
        dialogTitle={t('profile.add.title', { tag: tag || '—' })}
        dialogHint={includeChildren ? t('profile.add.childrenHint') : undefined}
      />
    </div>
  )
}
