// SPDX-License-Identifier: GPL-3.0-or-later
import { Link } from '@tanstack/react-router'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import PageHeader from '@/components/PageHeader'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import AddSubscriptionDialog from '@/features/node/AddSubscriptionDialog'
import { useNodes, useTestNodes } from '@/features/node/api'
import ImportLinksDialog from '@/features/node/ImportLinksDialog'
import NodeTable from '@/features/node/NodeTable'
import OutboundCards from '@/features/node/OutboundCards'
import SubscriptionList from '@/features/node/SubscriptionList'
import { errorText } from '@/lib/errors'
import { useUiStore } from '@/stores/ui'

export default function NodesPage() {
  const { t } = useTranslation()
  const nodes = useNodes()
  const test = useTestNodes()
  const testUrl = useUiStore((s) => s.latencyTestUrl)
  const latencies = useMemo(
    () => new Map((test.data?.results ?? []).map((r) => [r.id, r])),
    [test.data],
  )

  return (
    <>
      <PageHeader
        title={t('pages.nodes.title')}
        hint={t('pages.nodes.hint')}
        actions={
          <>
            <ImportLinksDialog />
            <Button
              variant="outline"
              disabled={test.isPending || !nodes.data || nodes.data.nodes.length === 0 || !testUrl}
              onClick={() => {
                if (nodes.data) {
                  test.mutate({ ids: nodes.data.nodes.map((n) => n.id), url: testUrl })
                }
              }}
            >
              {test.isPending ? t('node.testing') : t('node.testAll')}
            </Button>
            <AddSubscriptionDialog />
          </>
        }
      />
      {nodes.isPending ? <p className="text-muted-foreground">{t('common.loading')}</p> : null}
      {nodes.isError ? (
        <Alert variant="destructive">
          <AlertDescription>{errorText(t, nodes.error)}</AlertDescription>
        </Alert>
      ) : null}
      {!testUrl && nodes.data && nodes.data.nodes.length > 0 ? (
        <p className="text-muted-foreground text-[13px]">
          {t('node.testNeedsUrl')}{' '}
          <Link to="/settings" className="text-primary underline-offset-4 hover:underline">
            {t('node.goToSettings')}
          </Link>
        </p>
      ) : null}
      {test.isError ? (
        <Alert variant="destructive">
          <AlertDescription>{errorText(t, test.error)}</AlertDescription>
        </Alert>
      ) : null}
      {nodes.data ? (
        <>
          <section aria-labelledby="subs-title" className="flex flex-col gap-3">
            <h2 id="subs-title" className="text-[15px] font-semibold">
              {t('node.subscriptionsTitle')}
            </h2>
            <SubscriptionList subscriptions={nodes.data.subscriptions} />
          </section>
          <section aria-labelledby="outbounds-title" className="flex flex-col gap-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 id="outbounds-title" className="text-[15px] font-semibold">
                {t('node.outboundsTitle')}
              </h2>
              <span className="text-muted-foreground text-[13px]">{t('node.outboundsHint')}</span>
            </div>
            <OutboundCards outbounds={nodes.data.outbounds} nodes={nodes.data.nodes} />
          </section>
          <section aria-labelledby="nodes-title" className="flex flex-col gap-3">
            <h2 id="nodes-title" className="text-[15px] font-semibold">
              {t('node.nodesTitle')}
            </h2>
            <NodeTable
              nodes={nodes.data.nodes}
              outbounds={nodes.data.outbounds}
              latencies={latencies}
            />
          </section>
        </>
      ) : null}
    </>
  )
}
