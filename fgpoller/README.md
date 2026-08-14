# fgpoller

Poller standalone de métricas FortiGate (GET em `api/v2/monitor`, por VDOM) →
InfluxDB central, bucket `fw_migration`. Alimenta o lado FG do dashboard
**Migração PA → FG — TECE1**. Descartável no pós-projeto (docs/RUNBOOK.md §9).

```bash
python3 fgpoller.py --selftest                  # valida parsers sem rede
sudo ./install.sh                               # dev-redes (RHEL): instala + enable
python3 fgpoller.py --config fgpoller.conf --once --dry-run   # 1 ciclo, imprime line protocol
```

Ciclos: fast 60s (recursos, interfaces, HA, túneis) · slow 300s (sessões por
VDOM, rotas, ARP) · hourly (hit counts, licença). ~250 séries por firewall.

Measurements (tags `hostname`, `site`, `vdom` onde couber):
`fg_system_resources` · `fg_sessions` · `fg_interface_stats` · `fg_ha` ·
`fg_vpn_tunnel` (por phase1) · `fg_vpn_summary` · `fg_route_count` ·
`fg_arp_count` · `fg_policy_hits` · `fg_license` · `fg_collector_health`.

Segredos só no `/opt/fw-migration/.env` (0600): `FG_TECE1_FW05_TOKEN`,
`FG_TECE1_FW06_TOKEN`, `INFLUX_TOKEN`. Token FG viaja apenas em header
`Authorization: Bearer`.
