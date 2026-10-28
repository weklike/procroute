// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import PageHeader from '@/components/PageHeader'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { useProfile, useProfiles } from '@/features/profile/api'
import { newProfile } from '@/features/profile/form'
import ProfileEditor from '@/features/profile/ProfileEditor'
import ProfileList from '@/features/profile/ProfileList'
import { errorText } from '@/lib/errors'
import { useUiStore } from '@/stores/ui'

/** 选中「新建方案」时的占位 id。 */
const NEW = '__new__'

export default function ProfilesPage() {
  const { t } = useTranslation()
  const profiles = useProfiles()
  const selected = useUiStore((s) => s.selectedProfileId)
  const select = useUiStore((s) => s.selectProfile)
  const list = profiles.data?.profiles ?? []
  const current =
    selected === NEW || list.some((p) => p.id === selected) ? selected : (list[0]?.id ?? null)
  const detail = useProfile(current !== NEW ? current : null)

  return (
    <>
      <PageHeader title={t('pages.profiles.title')} hint={t('pages.profiles.hint')} />
      {profiles.isError ? (
        <Alert variant="destructive">
          <AlertDescription>{errorText(t, profiles.error)}</AlertDescription>
        </Alert>
      ) : null}
      <div className="flex flex-wrap items-start gap-5">
        <ProfileList
          profiles={list}
          selectedId={current}
          onSelect={select}
          onCreate={() => select(NEW)}
        />
        {current === NEW ? (
          <ProfileEditor
            key={NEW}
            profile={newProfile(t('profile.newName'))}
            isNew
            onSaved={select}
            onDeleted={() => select(null)}
          />
        ) : detail.data ? (
          <ProfileEditor
            key={detail.data.id}
            profile={detail.data}
            isNew={false}
            onSaved={select}
            onDeleted={() => select(null)}
          />
        ) : detail.isError ? (
          <Alert variant="destructive" className="flex-1">
            <AlertDescription>{errorText(t, detail.error)}</AlertDescription>
          </Alert>
        ) : current !== null ? (
          <p className="text-muted-foreground">{t('common.loading')}</p>
        ) : null}
      </div>
    </>
  )
}
