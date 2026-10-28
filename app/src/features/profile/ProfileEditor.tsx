// SPDX-License-Identifier: GPL-3.0-or-later
// 方案编辑器（设计稿 Main）。React Hook Form + Zod；保存后以服务端返回的逐字段错误为准（AGENTS 5.2）。
import { zodResolver } from '@hookform/resolvers/zod'
import { Plus } from 'lucide-react'
import { useState } from 'react'
import { FormProvider, useFieldArray, useForm, useWatch, type Path } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import type { Profile } from '@/api/generated'
import FieldError from '@/components/FieldError'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useNodes } from '@/features/node/api'
import { errorText } from '@/lib/errors'
import { cn } from '@/lib/utils'

import { fieldIssues, useSaveProfile } from './api'
import DeleteProfileDialog from './DeleteProfileDialog'
import { formPath, MAX_NAME, profileSchema, type ProfileForm, type ProfileValues } from './form'
import GroupCard from './GroupCard'
import NetworkSettings from './NetworkSettings'
import RuleList from './RuleList'

type Props = {
  profile: Profile
  isNew: boolean
  onSaved: (id: string) => void
  onDeleted: () => void
}

export default function ProfileEditor({ profile, isNew, onSaved, onDeleted }: Props) {
  const { t } = useTranslation()
  const form = useForm<ProfileForm, unknown, ProfileValues>({
    resolver: zodResolver(profileSchema),
    defaultValues: profile,
  })
  const { register, control, handleSubmit, reset, setError, formState } = form
  const groups = useFieldArray({ control, name: 'groups' })
  const mode = useWatch({ control, name: 'mode' })
  const save = useSaveProfile()
  const nodes = useNodes()
  const [serverRejected, setServerRejected] = useState(false)
  const outbounds = (nodes.data?.outbounds ?? []).map((o) => o.tag)
  const nameError = formState.errors.name?.message

  const submit = handleSubmit((values) => {
    setServerRejected(false)
    const body: Profile = { ...values, id: values.id === '' ? crypto.randomUUID() : values.id }
    save.mutate(body, {
      onSuccess: ({ id }) => {
        reset({ ...body, id })
        onSaved(id)
      },
      onError: (e) => {
        const issues = fieldIssues(e)
        for (const issue of issues) {
          setError(formPath(issue.path) as Path<ProfileForm>, {
            type: 'server',
            message: `profile.issues.${issue.code}`,
          })
        }
        setServerRejected(issues.length > 0)
      },
    })
  })

  return (
    <FormProvider {...form}>
      <form
        aria-labelledby="editor-title"
        noValidate
        onSubmit={(e) => void submit(e)}
        className="bg-card flex min-w-0 flex-1 flex-col gap-5 rounded-xl border p-5"
      >
        <h2 id="editor-title" className="text-[15px] font-semibold">
          {t('profile.editTitle')}
        </h2>
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex min-w-60 flex-1 flex-col gap-1.5">
            <Label htmlFor="profile-name">{t('profile.name')}</Label>
            <Input
              id="profile-name"
              aria-invalid={nameError ? true : undefined}
              aria-describedby={nameError ? 'profile-name-error' : undefined}
              {...register('name')}
            />
            <FieldError id="profile-name-error" message={nameError} values={{ max: MAX_NAME }} />
          </div>
          <fieldset className="flex flex-col gap-1.5">
            <legend className="mb-1.5 text-sm font-medium">{t('profile.modeLegend')}</legend>
            <div className="bg-muted inline-flex gap-0.5 rounded-lg p-1">
              {(['precise', 'tun'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  aria-pressed={mode === m}
                  onClick={() => form.setValue('mode', m, { shouldDirty: true })}
                  className={cn(
                    'h-8 rounded-md px-3 text-[13px] font-medium',
                    mode === m ? 'bg-card shadow-xs' : 'text-muted-foreground',
                  )}
                >
                  {t(`profile.modes.${m}`)}
                </button>
              ))}
            </div>
          </fieldset>
        </div>
        {mode === 'tun' ? (
          <Alert className="border-warning bg-warning-muted">
            <AlertDescription>{t('profile.tunWarning')}</AlertDescription>
          </Alert>
        ) : null}

        <section aria-labelledby="groups-title" className="flex flex-col gap-3">
          <div className="flex flex-col">
            <h3 id="groups-title" className="text-sm font-semibold">
              {t('profile.groupsTitle')}
            </h3>
            <span className="text-muted-foreground text-[13px]">{t('profile.groupsHint')}</span>
          </div>
          {groups.fields.map((g, i) => (
            <GroupCard
              key={g.id}
              index={i}
              outbounds={outbounds}
              onRemove={() => groups.remove(i)}
            />
          ))}
          <Button
            type="button"
            variant="outline"
            className="self-start"
            onClick={() =>
              groups.append({
                tag: '',
                outbound: outbounds[0] ?? '',
                include_children: true,
                match: [],
              })
            }
          >
            <Plus aria-hidden="true" />
            {t('profile.addGroup')}
          </Button>
        </section>

        <section aria-labelledby="exclude-title" className="flex flex-col gap-3">
          <div className="flex flex-col">
            <h3 id="exclude-title" className="text-sm font-semibold">
              {t('profile.excludeTitle')}
            </h3>
            <span className="text-muted-foreground text-[13px]">{t('profile.excludeHint')}</span>
          </div>
          <RuleList
            name="exclude"
            addLabel={t('profile.addExclude')}
            dialogTitle={t('profile.add.excludeTitle')}
          />
        </section>

        <NetworkSettings />

        {serverRejected ? (
          <Alert variant="destructive">
            <AlertDescription>{t('profile.serverIssues')}</AlertDescription>
          </Alert>
        ) : save.isError ? (
          <Alert variant="destructive">
            <AlertDescription>{errorText(t, save.error)}</AlertDescription>
          </Alert>
        ) : null}

        <div className="flex flex-wrap items-center justify-end gap-3 border-t pt-4">
          {isNew ? null : (
            <DeleteProfileDialog id={profile.id} name={profile.name} onDeleted={onDeleted} />
          )}
          {save.isSuccess && !formState.isDirty ? (
            <span role="status" className="text-brand text-[13px]">
              {t('profile.saved')}
            </span>
          ) : null}
          <Button
            type="button"
            variant="outline"
            disabled={!formState.isDirty}
            onClick={() => {
              reset(profile)
              setServerRejected(false)
              save.reset()
            }}
          >
            {t('profile.discard')}
          </Button>
          <Button type="submit" disabled={save.isPending}>
            {save.isPending ? t('profile.saving') : t('profile.save')}
          </Button>
        </div>
      </form>
    </FormProvider>
  )
}
