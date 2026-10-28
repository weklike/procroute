// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import PageHeader from '@/components/PageHeader'

export default function ConnectionsPage() {
  const { t } = useTranslation()
  return <PageHeader title={t('pages.connections.title')} hint={t('pages.connections.hint')} />
}
