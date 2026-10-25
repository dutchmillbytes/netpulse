import assert from 'node:assert/strict'
import test from 'node:test'
import { groupWireGuardInstances } from './wireguardGroups.ts'

const routers = [{ id: 'router-a', name: 'router-A' }, { id: 'router-b', name: 'router-B' }]
const peer = (keyFingerprint, localRole, name = 'VPS WireGuard Hub') => ({
  id: 'peer-1', keyFingerprint, localRole, name, active: true,
})
const entry = (routerId, instances) => ({
  routerId, stats: { interface: instances.map((i) => i.interface).join(', '), status: 'active', peers: instances.flatMap((i) => i.peers), instances },
})

test('two client instances sharing one remote key yield one server card with two local peers', () => {
  const wireguards = [
    entry('router-a', [{ interface: 'wg0', role: 'client', status: 'active', peers: [peer('shared-key', 'client')] }]),
    entry('router-b', [{ interface: 'wg0', role: 'client', status: 'active', peers: [peer('shared-key', 'client')] }]),
  ]
  const groups = groupWireGuardInstances(wireguards, routers)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].role, 'client')
  assert.equal(groups[0].title, 'VPS WireGuard Hub')
  assert.deepEqual(groups[0].members.map((m) => m.routerName), ['router-A', 'router-B'])
})

test('server instances keep their clients together and separate interfaces stay separate', () => {
  const groups = groupWireGuardInstances([
    entry('router-a', [
      { interface: 'wg0', role: 'server', status: 'active', peers: [peer('key-1', 'server', 'Phone'), peer('key-2', 'server', 'Laptop')] },
      { interface: 'wg1', role: 'client', status: 'active', peers: [peer('remote-key', 'client')] },
    ]),
  ], routers)
  assert.equal(groups.length, 2)
  assert.equal(groups[0].role, 'server')
  assert.equal(groups[0].members.length, 2)
  assert.equal(groups[0].interface, 'wg0')
  assert.equal(groups[1].role, 'client')
  assert.equal(groups[1].interface, 'wg1')
})

test('missing key or role never invents a shared remote server', () => {
  const groups = groupWireGuardInstances([
    entry('router-a', [{ interface: 'wg0', role: 'client', status: 'active', peers: [peer('', 'client')] }]),
    entry('router-b', [{ interface: 'wg0', role: 'client', status: 'active', peers: [peer('', 'client')] }]),
  ], routers)
  assert.equal(groups.length, 2)
  const legacy = groupWireGuardInstances([{ routerId: 'router-a', stats: { interface: 'wg0', status: 'active', peers: [peer('', undefined)] } }], routers)
  assert.equal(legacy[0].role, 'unknown')
})
