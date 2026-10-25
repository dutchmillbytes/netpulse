import assert from 'node:assert/strict'
import test from 'node:test'
import { buildTopologyModel } from './model.ts'

const router = (id, name, roleBadge) => ({
  id, name, ip: name, roleBadge, status: 'online', modelShort: 'Router',
  sparkline: [0, 1], clients: 0, health: 100,
})
const device = (id, routerId) => ({
  id, name: id, type: 'desconocido', manufacturer: '', ip: '', mac: id,
  routerId, band: 'cable', signalDbm: null, trafficMbps: 0, online: true,
  sparkline: [0, 0],
})
const routers = [
  { ...router('router-a', 'router.nl.example.home', 'Principal'), ip: '10.49.1.254' },
  router('router-b', 'router.th.example.home', 'Secondary'),
  router('ap-a', 'ap-2.nl.example.home', 'AP'),
  router('ap-b', 'ap-2.th.example.home', 'AP'),
]
const devices = [device('client-a', 'router-a'), device('client-b', 'router-b')]
const wan = { plan: '1 Gbps', latencyMs: 4, isp: 'ISP', publicIp: '198.51.100.1', lossPct: 0 }
const stats = (active, keyFingerprint = 'shared-key') => ({
  interface: 'wg0', subnet: '10.200.0.0/24', status: 'active',
  peers: [{ id: 'peer-1', name: 'VPS', type: 'sitio', tunnelIp: '10.200.0.0/24',
    keyFingerprint, interface: 'wg0', active, lastHandshake: 'now', rx: '0', tx: '0' }],
})
const wireguards = [
  { routerId: 'router-a', stats: stats(true) },
  { routerId: 'router-b', stats: stats(false) },
]

test('two routing roots retain their APs, clients, WANs and separate tunnels to one peer', () => {
  const model = buildTopologyModel({
    routers, devices, wan, routerWans: { 'router-b': { latencyMs: 12, publicIp: '203.0.113.2' } },
    wireguard: stats(true), wireguards,
    topology: {
      routerParents: { 'ap-a': 'router-a', 'ap-b': 'router-b' },
      rings: { 'router-a': ['client-a'], 'router-b': ['client-b'] },
      links: [
        { kind: 'wan', from: 'internet-router-a', to: 'router-a' },
        { kind: 'wan', from: 'internet-router-b', to: 'router-b' },
        { kind: 'uplink', from: 'router-a', to: 'ap-a' },
        { kind: 'uplink', from: 'router-b', to: 'ap-b' },
        { kind: 'wired', from: 'router-a', to: 'client-a' },
        { kind: 'wired', from: 'router-b', to: 'client-b' },
        { kind: 'wg', from: 'router-a', to: 'peer-key-shared-key', interface: 'wg0' },
        { kind: 'wg', from: 'router-b', to: 'peer-key-shared-key', interface: 'wg0' },
      ],
    },
    seedPositions: { 'router-b': { x: 800, y: 240 } },
  })
  const has = (kind, from, to) => model.links.some((link) => link.kind === kind && link.from === from && link.to === to)
  assert.equal(has('uplink', 'router-a', 'router-b'), false)
  assert.equal(has('uplink', 'router-b', 'ap-b'), true)
  assert.equal(has('wired', 'router-b', 'client-b'), true)
  assert.equal(has('wan', 'internet-router-a', 'router-a'), true)
  assert.equal(has('wan', 'internet-router-b', 'router-b'), true)
  assert.equal(model.internetNodes.length, 2)
  assert.notEqual(model.internetNodes[0].id, model.internetNodes[1].id)
  assert.equal(model.internetNodes[0].wan.publicIp, wan.publicIp)
  assert.equal(model.internetNodes[1].wan.publicIp, '203.0.113.2')
  assert.equal(model.peerNodes.length, 1)
  assert.equal(has('wg', 'router-a', model.peerNodes[0].id), true)
  assert.equal(has('wg', 'router-b', model.peerNodes[0].id), true)
  assert.equal(model.links.find((link) => link.kind === 'wg' && link.from === 'router-a')?.d.endsWith('482 105'), true)
  assert.equal(model.links.find((link) => link.kind === 'wg' && link.from === 'router-b')?.d.endsWith('518 105'), true)
  assert.equal(model.links.find((link) => link.from === 'router-a' && link.kind === 'wg')?.active, true)
  assert.equal(model.links.find((link) => link.from === 'router-b' && link.kind === 'wg')?.active, false)
  assert.equal(model.secondaryNodes[0].x, 800)
  assert.deepEqual(model.secondaryNodes[0].label, { x: 800, y: 302, anchor: 'middle' })
  assert.equal(model.backhauls.filter((row) => row.kind === 'wg').length, 2)
})

test('legacy WAN semantics are mapped to distinct Internet endpoints', () => {
  const model = buildTopologyModel({
    routers: routers.slice(0, 2), devices: [], wan, wireguard: stats(true), wireguards,
    topology: { rings: {}, links: [
      { kind: 'wan', from: 'internet', to: 'router-a' },
      { kind: 'wan', from: 'internet', to: 'router-b' },
    ] },
  })
  assert.deepEqual(model.links.filter((link) => link.kind === 'wan').map((link) => link.from),
    ['internet-router-a', 'internet-router-b'])
})

test('a single router keeps its original Internet endpoint', () => {
  const model = buildTopologyModel({ routers: routers.slice(0, 1), devices: [], wan, wireguard: stats(true) })
  assert.deepEqual(model.internetNodes.map((node) => node.id), ['internet'])
  assert.equal(model.links.find((link) => link.kind === 'wan')?.from, 'internet')
})

test('saved routing-root positions keep labels below the nodes', () => {
  const model = buildTopologyModel({
    routers: routers.slice(0, 3), devices: [], wan, wireguard: stats(true),
    seedPositions: { 'router-a': { x: 240, y: 280 }, 'router-b': { x: 760, y: 280 }, 'ap-a': { x: 360, y: 470 } },
  })
  assert.deepEqual(model.gatewayNode.label, { x: 240, y: 342, anchor: 'middle' })
  assert.deepEqual(model.secondaryNodes[0].label, { x: 760, y: 342, anchor: 'middle' })
  assert.deepEqual(model.apNodes[0].label, { x: 360, y: 524, anchor: 'middle' })
  assert.equal(model.apNodes[0].displayName, 'ap-2.nl')
})

test('same local peer ID without a key fingerprint does not merge endpoints', () => {
  const model = buildTopologyModel({
    routers: routers.slice(0, 2), devices: [], wan, wireguard: stats(true),
    wireguards: [
      { routerId: 'router-a', stats: stats(true, '') },
      { routerId: 'router-b', stats: stats(true, '') },
    ],
  })
  assert.equal(model.peerNodes.length, 2)
  assert.notEqual(model.peerNodes[0].id, model.peerNodes[1].id)
})

test('two interfaces on one router keep separate edges to a shared remote key', () => {
  const first = stats(true).peers[0]
  const model = buildTopologyModel({
    routers: routers.slice(0, 2), devices: [], wan, wireguard: stats(true),
    wireguards: [
      { routerId: 'router-a', stats: { ...stats(true), peers: [first, { ...first, interface: 'wg1' }] } },
      { routerId: 'router-b', stats: stats(true) },
    ],
  })
  const wgLinks = model.links.filter((link) => link.kind === 'wg')
  assert.equal(model.peerNodes.length, 1)
  assert.equal(wgLinks.length, 3)
  assert.equal(new Set(wgLinks.map((link) => link.id)).size, 3)
})

test('an older server graph cannot reattach a secondary router to the primary', () => {
  const model = buildTopologyModel({
    routers, devices, wan, wireguard: stats(true), wireguards,
    topology: {
      rings: { 'router-a': ['client-a', 'client-b'] },
      links: [
        { kind: 'wan', from: 'internet', to: 'router-a' },
        { kind: 'uplink', from: 'router-a', to: 'router-b' },
        { kind: 'wg', from: 'peer-peer-1', to: 'internet' },
      ],
    },
  })
  assert.equal(model.links.some((link) => link.kind === 'uplink' && link.to === 'router-b'), false)
  assert.equal(model.links.some((link) => link.kind === 'wan' && link.from === 'internet-router-b' && link.to === 'router-b'), true)
  assert.equal(model.chips.find((chip) => chip.id === 'client-b')?.hubId, 'router-b')
})

test('site-qualified AP wins over a same-named client on another router', () => {
  const ap = router('ap-3-nl', 'ap-3.nl.example.home', 'AP')
  const model = buildTopologyModel({
    routers: [...routers.slice(0, 2), ap],
    devices: [{ ...device('observed-ap3', 'router-b'), name: 'ap-3' }],
    wan, wireguard: stats(true), wireguards,
  })
  assert.equal(model.links.some((link) => link.kind === 'uplink' && link.from === 'router-a' && link.to === ap.id), true)
  assert.equal(model.links.some((link) => link.kind === 'uplink' && link.from === 'router-b' && link.to === ap.id), false)
})
