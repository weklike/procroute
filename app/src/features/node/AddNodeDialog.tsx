// SPDX-License-Identifier: GPL-3.0-or-later
// 手动添加节点。表单拼成分享链接后走 `node.import`（见 ./manualNode.ts）。
// 凭据只写不读：输入框都是密码框，对话框关闭或添加成功后清空（C-SEC-04、C-UI-03）。
import { zodResolver } from '@hookform/resolvers/zod'
import { useId, useState, type ReactNode } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import FieldError from '@/components/FieldError'
import NativeSelect from '@/components/NativeSelect'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { errorText } from '@/lib/errors'

import { useImportNodes } from './api'
import { importIssueText } from './issues'
import {
  defaultSecurity,
  fieldsOf,
  FINGERPRINTS,
  MANUAL_NODE_DEFAULTS,
  manualNodeSchema,
  PROTOCOLS,
  SS_METHODS,
  toShareLink,
  TRANSPORTS,
  TUIC_CONGESTION,
  TUIC_UDP_RELAY,
  VMESS_CIPHERS,
  type ManualNodeForm,
  type ManualNodeValues,
} from './manualNode'

type FieldProps = {
  label: string
  error?: string
  /** 占满两列。 */
  wide?: boolean
  children: (props: { id: string; 'aria-invalid'?: true; 'aria-describedby'?: string }) => ReactNode
}

function Field({ label, error, wide, children }: FieldProps) {
  const id = useId()
  const errorId = `${id}-error`
  return (
    <div className={wide ? 'flex flex-col gap-1.5 sm:col-span-2' : 'flex flex-col gap-1.5'}>
      <Label htmlFor={id}>{label}</Label>
      {children({
        id,
        ...(error ? { 'aria-invalid': true as const, 'aria-describedby': errorId } : {}),
      })}
      <FieldError id={errorId} message={error} />
    </div>
  )
}

export default function AddNodeDialog() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [skipped, setSkipped] = useState<string | null>(null)
  const importNodes = useImportNodes()
  const form = useForm<ManualNodeForm, unknown, ManualNodeValues>({
    resolver: zodResolver(manualNodeSchema),
    defaultValues: MANUAL_NODE_DEFAULTS,
  })
  const { register, control, setValue, formState } = form
  const { errors } = formState
  const protocol = useWatch({ control, name: 'protocol' })
  const security = useWatch({ control, name: 'security' })
  const transport = useWatch({ control, name: 'transport' })
  const f = fieldsOf(protocol, security)
  const m = (key: string) => t(`node.manual.${key}`)

  const reset = () => {
    form.reset(MANUAL_NODE_DEFAULTS)
    setSkipped(null)
    importNodes.reset()
  }

  const onOpenChange = (next: boolean) => {
    setOpen(next)
    if (!next) reset()
  }

  const submit = form.handleSubmit((values) => {
    setSkipped(null)
    importNodes.mutate(
      { kind: 'share_links', text: toShareLink(values) },
      {
        onSuccess: (result) => {
          if (result.added > 0) {
            onOpenChange(false)
            return
          }
          // 只有一条链接，行号没有意义；原因是固定代码，不含输入内容
          const issue = result.issues[0]
          setSkipped(
            issue ? importIssueText(t, { ...issue, line: 0 }) : t('node.manual.errors.notAdded'),
          )
        },
      },
    )
  })

  const webLike = transport === 'ws' || transport === 'h2' || transport === 'httpupgrade'
  const noAutofill = { autoComplete: 'off', spellCheck: false } as const
  const secret = { type: 'password', autoComplete: 'new-password' } as const

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline">{t('node.addNode')}</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <form onSubmit={(e) => void submit(e)} noValidate className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>{m('title')}</DialogTitle>
            <DialogDescription>{m('hint')}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={m('protocol')}>
              {(p) => (
                <NativeSelect
                  {...p}
                  {...register('protocol', {
                    onChange: (e: { target: { value: ManualNodeForm['protocol'] } }) =>
                      setValue('security', defaultSecurity(e.target.value)),
                  })}
                >
                  {PROTOCOLS.map((id) => (
                    <option key={id} value={id}>
                      {t(`node.protocols.${id}`)}
                    </option>
                  ))}
                </NativeSelect>
              )}
            </Field>
            <Field label={m('name')}>
              {(p) => (
                <Input
                  {...p}
                  {...noAutofill}
                  placeholder={m('namePlaceholder')}
                  {...register('name')}
                />
              )}
            </Field>
            <Field label={m('server')} error={errors.server?.message}>
              {(p) => (
                <Input
                  {...p}
                  {...noAutofill}
                  className="font-mono"
                  placeholder={m('serverPlaceholder')}
                  {...register('server')}
                />
              )}
            </Field>
            <Field label={m('port')} error={errors.port?.message}>
              {(p) => (
                <Input
                  {...p}
                  {...noAutofill}
                  className="font-mono"
                  inputMode="numeric"
                  placeholder="443"
                  {...register('port')}
                />
              )}
            </Field>

            {f.method ? (
              <Field label={m('method')} wide>
                {(p) => (
                  <NativeSelect {...p} {...register('method')}>
                    {SS_METHODS.map((id) => (
                      <option key={id} value={id}>
                        {id}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            ) : null}
            {f.uuid ? (
              <Field label={m('uuid')} error={errors.uuid?.message} wide={!f.password}>
                {(p) => <Input {...p} {...secret} className="font-mono" {...register('uuid')} />}
              </Field>
            ) : null}
            {f.auth ? (
              <Field label={m('username')} error={errors.username?.message}>
                {(p) => <Input {...p} {...noAutofill} {...register('username')} />}
              </Field>
            ) : null}
            {f.password || f.auth ? (
              <Field
                label={f.auth ? m('passwordOptional') : m('password')}
                error={errors.password?.message}
                wide={f.method}
              >
                {(p) => <Input {...p} {...secret} {...register('password')} />}
              </Field>
            ) : null}
            {f.vmessCipher ? (
              <Field label={m('cipher')}>
                {(p) => (
                  <NativeSelect {...p} {...register('vmessCipher')}>
                    {VMESS_CIPHERS.map((id) => (
                      <option key={id} value={id}>
                        {id}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            ) : null}
            {f.securityChoices.length > 0 ? (
              <Field label={m('security')}>
                {(p) => (
                  <NativeSelect {...p} {...register('security')}>
                    {f.securityChoices.map((id) => (
                      <option key={id} value={id}>
                        {m(`securities.${id}`)}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            ) : null}

            {f.sni ? (
              <Field label={m('sni')}>
                {(p) => <Input {...p} {...noAutofill} className="font-mono" {...register('sni')} />}
              </Field>
            ) : null}
            {f.fingerprint ? (
              <Field label={m('fingerprint')}>
                {(p) => (
                  <NativeSelect {...p} {...register('fingerprint')}>
                    <option value="">{m('none')}</option>
                    {FINGERPRINTS.map((id) => (
                      <option key={id} value={id}>
                        {id}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            ) : null}
            {f.alpn ? (
              <Field label={m('alpn')}>
                {(p) => (
                  <Input
                    {...p}
                    {...noAutofill}
                    className="font-mono"
                    placeholder="h2,http/1.1"
                    {...register('alpn')}
                  />
                )}
              </Field>
            ) : null}
            {f.reality ? (
              <>
                <Field label={m('publicKey')} error={errors.publicKey?.message}>
                  {(p) => (
                    <Input
                      {...p}
                      {...noAutofill}
                      className="font-mono"
                      {...register('publicKey')}
                    />
                  )}
                </Field>
                <Field label={m('shortId')} error={errors.shortId?.message}>
                  {(p) => (
                    <Input {...p} {...noAutofill} className="font-mono" {...register('shortId')} />
                  )}
                </Field>
              </>
            ) : null}

            {f.transport ? (
              <Field label={m('transport')}>
                {(p) => (
                  <NativeSelect {...p} {...register('transport')}>
                    {TRANSPORTS.map((id) => (
                      <option key={id} value={id}>
                        {m(`transports.${id}`)}
                      </option>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            ) : null}
            {f.transport && webLike ? (
              <>
                <Field label={m('path')}>
                  {(p) => (
                    <Input {...p} {...noAutofill} className="font-mono" {...register('path')} />
                  )}
                </Field>
                <Field label={m('host')}>
                  {(p) => (
                    <Input {...p} {...noAutofill} className="font-mono" {...register('host')} />
                  )}
                </Field>
              </>
            ) : null}
            {f.transport && transport === 'grpc' ? (
              <Field label={m('serviceName')}>
                {(p) => (
                  <Input
                    {...p}
                    {...noAutofill}
                    className="font-mono"
                    {...register('serviceName')}
                  />
                )}
              </Field>
            ) : null}

            {f.obfs ? (
              <Field label={m('obfsPassword')}>
                {(p) => <Input {...p} {...secret} {...register('obfsPassword')} />}
              </Field>
            ) : null}
            {f.tuic ? (
              <>
                <Field label={m('congestion')}>
                  {(p) => (
                    <NativeSelect {...p} {...register('congestion')}>
                      <option value="">{m('default')}</option>
                      {TUIC_CONGESTION.map((id) => (
                        <option key={id} value={id}>
                          {id}
                        </option>
                      ))}
                    </NativeSelect>
                  )}
                </Field>
                <Field label={m('udpRelay')}>
                  {(p) => (
                    <NativeSelect {...p} {...register('udpRelay')}>
                      <option value="">{m('default')}</option>
                      {TUIC_UDP_RELAY.map((id) => (
                        <option key={id} value={id}>
                          {id}
                        </option>
                      ))}
                    </NativeSelect>
                  )}
                </Field>
              </>
            ) : null}
          </div>

          {f.flow ? (
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" className="accent-brand size-4" {...register('vision')} />
              {m('vision')}
            </label>
          ) : null}
          {f.insecure ? (
            <label className="flex items-start gap-2 text-[13px]">
              <input
                type="checkbox"
                className="accent-brand mt-0.5 size-4"
                {...register('insecure')}
              />
              <span className="flex flex-col">
                <span>{m('insecure')}</span>
                <span className="text-muted-foreground">{m('insecureHint')}</span>
              </span>
            </label>
          ) : null}

          {importNodes.isError ? (
            <Alert variant="destructive">
              <AlertDescription>{errorText(t, importNodes.error)}</AlertDescription>
            </Alert>
          ) : null}
          {skipped ? (
            <Alert variant="destructive">
              <AlertDescription>{skipped}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={importNodes.isPending}>
              {m('submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
