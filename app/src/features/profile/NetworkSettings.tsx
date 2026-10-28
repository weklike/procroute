// SPDX-License-Identifier: GPL-3.0-or-later
// 网络行为：出错时策略、DNS、UDP。
// fail_policy 默认阻断，放行只能由用户在这里显式选择（C-NET-03）；
// 接管系统 DNS 影响全局，选中前必须再次确认（C-NET-09）。
import { useState, type ReactNode } from 'react'
import { useFormContext, useWatch } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

import type { ProfileForm } from './form'

type OptionProps = { label: string; hint: string; children: ReactNode }

function Option({ label, hint, children }: OptionProps) {
  return (
    <label className="flex items-start gap-2.5 text-[13px]">
      {children}
      <span className="flex flex-col">
        <span className="font-medium">{label}</span>
        <span className="text-muted-foreground">{hint}</span>
      </span>
    </label>
  )
}

export default function NetworkSettings() {
  const { t } = useTranslation()
  const { register, control, setValue } = useFormContext<ProfileForm>()
  const dns = useWatch({ control, name: 'dns.strategy' })
  const [confirming, setConfirming] = useState(false)
  const radio = 'accent-brand mt-0.5 size-4'

  return (
    <section aria-labelledby="network-title" className="flex flex-col gap-3">
      <h3 id="network-title" className="text-sm font-semibold">
        {t('profile.networkTitle')}
      </h3>
      <div className="grid gap-4 md:grid-cols-3">
        <fieldset className="flex flex-col gap-2.5">
          <legend className="mb-1 text-[13px] font-semibold">{t('profile.failLegend')}</legend>
          <Option label={t('profile.fail.block')} hint={t('profile.fail.blockHint')}>
            <input type="radio" value="block" className={radio} {...register('fail_policy')} />
          </Option>
          <Option label={t('profile.fail.allow')} hint={t('profile.fail.allowHint')}>
            <input type="radio" value="allow" className={radio} {...register('fail_policy')} />
          </Option>
        </fieldset>
        <fieldset className="flex flex-col gap-2.5">
          <legend className="mb-1 text-[13px] font-semibold">{t('profile.dnsLegend')}</legend>
          <Option label={t('profile.dns.sniff')} hint={t('profile.dns.sniffHint')}>
            <input
              type="radio"
              name="dns-strategy"
              className={radio}
              checked={dns === 'sniff'}
              onChange={() => setValue('dns.strategy', 'sniff', { shouldDirty: true })}
            />
          </Option>
          <Option label={t('profile.dns.takeover')} hint={t('profile.dns.takeoverHint')}>
            <input
              type="radio"
              name="dns-strategy"
              className={radio}
              checked={dns === 'system_takeover'}
              onChange={() => setConfirming(true)}
            />
          </Option>
        </fieldset>
        <fieldset className="flex flex-col gap-2.5">
          <legend className="mb-1 text-[13px] font-semibold">{t('profile.udpLegend')}</legend>
          <Option label={t('profile.udp.enabled')} hint={t('profile.udp.enabledHint')}>
            <input type="checkbox" className={radio} {...register('udp.enabled')} />
          </Option>
          <Option label={t('profile.udp.blockQuic')} hint={t('profile.udp.blockQuicHint')}>
            <input type="checkbox" className={radio} {...register('udp.block_quic')} />
          </Option>
        </fieldset>
      </div>
      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('profile.dns.confirmTitle')}</DialogTitle>
            <DialogDescription>{t('profile.dns.confirmBody')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirming(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() => {
                setValue('dns.strategy', 'system_takeover', { shouldDirty: true })
                setConfirming(false)
              }}
            >
              {t('profile.dns.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
