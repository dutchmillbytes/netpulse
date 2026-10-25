import { useState } from 'react'
import { ChevronDown, KeyRound, Laptop, Network, Smartphone, Tablet } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { relTime } from '@/i18n'
import type { PeerType, WGPeer } from '@/data/mock'
import type { WireGuardInstance, WireGuardStats } from '@/data/types'
import { StatusPill } from '@/components/StatusPill'
import { wgPeerExtras } from '@/components/routers/routerExtras'
import { cn } from '@/lib/utils'

const PEER_ICONS: Record<PeerType, LucideIcon> = {
  movil: Smartphone,
  portatil: Laptop,
  tablet: Tablet,
  sitio: Network,
  desconocido: Network,
}

function PeerRow({ peer, index }: { peer: WGPeer; index: number }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const reduce = useReducedMotion()
  const Icon = PEER_ICONS[peer.type] ?? Smartphone
  const extra = wgPeerExtras[peer.id]

  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3, ease: 'easeOut', delay: 0.1 + index * 0.07 }}
      className={cn(!peer.active && 'opacity-65')}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 rounded-xl px-2.5 py-2.5 text-left transition-colors hover:bg-hover"
      >
        {/* Avatar con inicial + icono de tipo superpuesto */}
        <span className="relative shrink-0">
          <span
            className={cn(
              'flex h-10 w-10 items-center justify-center rounded-full font-display text-sm font-bold',
              peer.active ? 'bg-gradient-to-br from-tunnel to-accent text-canvas' : 'bg-elevated text-text-muted',
            )}
          >
            {peer.name.charAt(0)}
          </span>
          <span className="absolute -bottom-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full border border-surface bg-elevated text-text-secondary">
            <Icon className="h-2.5 w-2.5" strokeWidth={1.75} />
          </span>
        </span>

        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-text-primary">{peer.name}</span>
          <span className="flex items-center gap-1.5">
            <span className="relative flex h-1.5 w-1.5">
              {peer.active && (
                <span className="absolute inline-flex h-full w-full rounded-full bg-ok opacity-75 animate-ping-soft" />
              )}
              <span className={cn('relative inline-flex h-1.5 w-1.5 rounded-full', peer.active ? 'bg-ok' : 'bg-text-muted')} />
            </span>
            <span className="font-mono text-caption text-text-muted">
              {peer.tunnelIp} · {relTime(peer.lastHandshake)}
            </span>
          </span>
        </span>

        <span className="shrink-0 text-right font-mono text-caption text-text-secondary">
          ↓ {peer.rx} ↑ {peer.tx}
        </span>
        <ChevronDown className={cn('h-4 w-4 shrink-0 text-text-muted transition-transform', open && 'rotate-180')} strokeWidth={1.75} />
      </button>

      <AnimatePresence initial={false}>
        {open && extra && (
          <motion.div
            initial={reduce ? false : { height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={reduce ? { opacity: 0 } : { height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: 'easeOut' }}
            className="overflow-hidden"
          >
            <dl className="mx-2.5 mb-2 grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-lg bg-elevated/60 px-3.5 py-3 sm:grid-cols-3">
              {[
                ['Endpoint', extra.endpoint],
                ['Allowed IPs', extra.allowedIps],
                [t('routerDetail.wireguard.lastIp'), extra.lastIp],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt className="text-[10px] font-medium uppercase tracking-[0.06em] text-text-muted">{k}</dt>
                  <dd className="font-mono text-mono-sm text-text-primary">{v}</dd>
                </div>
              ))}
            </dl>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

/** ⑥ WireGuard panel (router-detail.md §⑥) — id="wireguard". */
export function WireGuardPanel({ stats }: { stats?: WireGuardStats }) {
  const { t } = useTranslation()
  const wireguard = stats ?? { interface: '', subnet: '', status: 'inactive', peers: [] }
  const instances: WireGuardInstance[] = wireguard.instances ?? (wireguard.interface
    ? [{ interface: wireguard.interface, status: wireguard.status, role: 'unknown', peers: wireguard.peers }]
    : [])

  return (
    <section id="wireguard" className="scroll-mt-4 rounded-2xl border border-border bg-surface p-5 transition-shadow duration-500 md:p-6 lg:col-span-5">
      {/* Cabecera */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-tunnel/10 text-tunnel">
            <KeyRound className="h-[18px] w-[18px]" strokeWidth={1.75} />
          </div>
          <h3 className="font-display text-h2 text-text-primary">WireGuard</h3>
        </div>
        <StatusPill tone={wireguard.status === 'active' ? 'tunnel' : 'warn'} label={wireguard.status === 'active' ? t('common.active') : t('common.status.offline')} />
      </div>
      {wireguard.subnet && <p className="mt-1.5 font-mono text-caption text-text-muted">{wireguard.subnet}</p>}

      <div className="mt-4 space-y-3">
        {instances.length === 0 && <p className="text-sm text-text-muted">{t('routerDetail.wireguard.noInstances')}</p>}
        {instances.map((instance) => {
          const peers = [...instance.peers].sort((a, b) => Number(b.active) - Number(a.active))
          const connected = peers.filter((p) => p.active).length
          const roleKey = instance.role === 'client' ? 'clientInstance'
            : instance.role === 'server' ? 'serverInstance'
              : instance.role === 'mixed' ? 'mixedInstance' : 'unknownInstance'
          return (
            <div key={instance.interface} className="rounded-xl border border-border bg-elevated/40 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-sm font-semibold text-text-primary">{instance.interface}</span>
                <StatusPill tone={instance.status === 'active' ? 'tunnel' : 'muted'} label={t(`home.services.${roleKey}`)} />
              </div>
              <div className="mt-3 text-caption text-text-muted">
                {t('routerDetail.wireguard.peersConnected')} <span className="font-mono text-text-primary">{connected}/{peers.length}</span>
              </div>
              <div className="mt-2 divide-y divide-border/50">
                {peers.map((peer, i) => <PeerRow key={`${instance.interface}-${peer.id}`} peer={peer} index={i} />)}
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}
