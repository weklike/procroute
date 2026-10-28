// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import PageHeader from '@/components/PageHeader'

export default function ProfilesPage() {
  const { t } = useTranslation()
  return <PageHeader title={t('pages.profiles.title')} hint={t('pages.profiles.hint')} />
}
