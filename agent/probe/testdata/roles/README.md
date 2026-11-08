# Operational role configuration fixtures

Captured read-only on 2026-11-06 from OpenWrt 25.12.6:

- `mt7621-router.txt`: MT7621 router with inter-network forwarding and a wired bridge.
- `ipq40xx-ap.txt`: IPQ40xx AP with AP/mesh interfaces and two bridged Ethernet ports.
- `gs108t-switch.txt`: refreshed switch-3 (GS108T v3) configuration: eight
  Ethernet ports in a bridge, no registered wireless devices, one management
  network, no firewall forwarding rules, and IPv4/IPv6 forwarding disabled.
  Derived operational role: switch only.
- `gs108t-routed.txt`: earlier configuration of the same device, with enabled
  lan-to-things forwarding between two configured VLAN interfaces and kernel
  forwarding enabled. Retained to verify the Router label takes precedence over standalone Switch
  classification while bridge evidence remains visible, and that roles change
  with configuration rather than hardware identity.

Retained facts: interface identifiers/devices and up state, default route targets,
firewall zone membership/forwardings, kernel forwarding flags, wireless modes and
kernel inventory, bridge membership, and physical Ethernet inventory. Addresses,
MACs, SSIDs, credentials, hostnames, counters and unrelated settings are omitted.
Tests mutate these real formats to cover absence, unavailable sources, renamed
interfaces, and changes in operational configuration.
