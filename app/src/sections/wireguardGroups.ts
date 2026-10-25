import type { Router, RouterWireGuard, WGPeer, WireGuardInstance } from '@/data/types'

export interface WireGuardMember {
  routerId: string
  routerName: string
  interface: string
  peer: WGPeer
}

export interface WireGuardGroup {
  id: string
  role: 'client' | 'server' | 'unknown'
  /** Remote server for a client group; local router for a server group. */
  title: string
  routerId: string
  interface: string
  members: WireGuardMember[]
}

/** One local server card per interface, one remote-server card per public key. */
export function groupWireGuardInstances(wireguards: RouterWireGuard[], routers: Router[]): WireGuardGroup[] {
  const groups = new Map<string, WireGuardGroup>()
  const routerNames = new Map(routers.map((router) => [router.id, router.name]))
  for (const { routerId, stats } of wireguards) {
    // An old server has only the aggregate fields. Its role is unknown.
    const instances: WireGuardInstance[] = stats.instances === undefined
      ? [{ interface: stats.interface, status: stats.status, role: 'unknown', peers: stats.peers }]
      : stats.instances ?? []
    for (const instance of instances) {
      const routerName = routerNames.get(routerId) ?? routerId
      const add = (id: string, role: WireGuardGroup['role'], title: string, peer?: WGPeer) => {
        let group = groups.get(id)
        if (!group) {
          group = { id, role, title, routerId, interface: instance.interface, members: [] }
          groups.set(id, group)
        }
        if (peer) group.members.push({ routerId, routerName, interface: instance.interface, peer })
      }
      if (instance.peers.length === 0) {
        add(`instance:${routerId}:${instance.interface}`, instance.role === 'server' ? 'server' : instance.role === 'client' ? 'client' : 'unknown', routerName)
      }
      for (const peer of instance.peers) {
        const role = peer.localRole ?? (instance.role === 'mixed' ? 'unknown' : instance.role)
        if (role === 'client') {
          // Fingerprints are opaque hashes of public keys. Names, tunnel IPs,
          // and router-local peer IDs cannot safely identify a shared server.
          const id = peer.keyFingerprint
            ? `remote:${peer.keyFingerprint}`
            : `remote-local:${routerId}:${instance.interface}:${peer.id}`
          add(id, 'client', peer.name, peer)
        } else {
          const groupRole = role === 'server' ? 'server' : 'unknown'
          add(`${groupRole}:${routerId}:${instance.interface}`, groupRole, routerName, peer)
        }
      }
    }
  }
  return [...groups.values()]
}
