# paloaltotofortigate — auditoria e observabilidade da migração PA → FortiGate

Ferramentas da migração dos firewalls de borda Palo Alto → FortiGate (TOTVS Cloud).
Primeiro site: **TECE1** — FW01/02TECE01 (PA) → **2 clusters FortiGate**: CLIENTE
(VIP 172.18.252.142, ex-vsys2) e INFRABASE (VIP 172.18.252.144, ex-vsys1). Desenhado para ser
reutilizado no TESP4 trocando configuração, não código.

⛔ **Somente leitura em equipamento.** Toda consulta a firewall passa por uma trava
mecânica (`audit/palib/readonly.py`): no Palo Alto só `<show>`/`config get|show`/`log`;
no FortiGate só `GET` em `api/v2/monitor|cmdb`. Qualquer coisa fora disso aborta o
processo. Correção é sempre proposta escrita — nunca comando executado.

## As três entregas

| Pasta | O quê | Onde roda |
|---|---|---|
| `audit/` | Auditoria em 3 fases: **offline** (snapshot XML do PA, sem tocar equipamento), **baseline/snapshot online read-only** (PA XML API + FG REST) e **comparação PA↔FG** (`gaps.md` + métricas `mig_audit`) | laptop (offline) e dev-redes do site (online) |
| `fgpoller/` | Poller de métricas do FortiGate (GET nos endpoints `monitor`, por VDOM) → InfluxDB central, bucket `fw_migration` | dev-redes do site (systemd) |
| `dashboards/` | Dashboard Grafana **Migração PA→FG TECE1** — PA vs FG lado a lado, espelhando os critérios de aceite do Plano de Virada | Grafana central |

O lado Palo Alto do dashboard vem do `palo-collector` que já roda na dev-redes
(buckets `paloalto`, `paloalto_capacity`, `paloalto_audit`). Este repo só adiciona o
lado FortiGate e a paridade de configuração.

## Quickstart na dev-redes (resumo — o passo a passo completo é `docs/RUNBOOK.md`)

```bash
git clone https://github.com/totvs-cloud/paloaltotofortigate.git
cd paloaltotofortigate
cp .env.example .env && chmod 600 .env   # preencher chaves/token
python3 -m unittest discover -s audit/tests -v

# Fase A — offline (não toca equipamento; snapshot fica FORA do repo)
python3 audit/fwaudit.py offline --snapshot /dados/migracao/snapshot_v1.xml --out out/

# Fase B — baseline PA (evidências "antes" da aba 09 do Plano de Virada)
python3 audit/fwaudit.py pa-baseline --host 172.18.252.23 --key-env PA_TECE1_FW01_KEY --out out/

# Fase B — snapshot FG (read-only, paginado, com throttle)
python3 audit/fwaudit.py fg-snapshot --host 172.18.252.144 --user max.ferreira --pass-env FG_TECE1_PASS --hostname FGT-TECE1-INFRABASE --vdoms root --out out/
python3 audit/fwaudit.py fg-snapshot --host 172.18.252.142 --user max.ferreira --pass-env FG_TECE1_PASS --hostname FGT-TECE1-CLIENTE --vdoms root --out out/

# Fase C — paridade PA↔FG
python3 audit/fwaudit.py compare --inventory out/<data>/inventario.json \
    --fg vsys1=out/<data>/fg-FGT-TECE1-INFRABASE --fg vsys2=out/<data>/fg-FGT-TECE1-CLIENTE --out out/

# Poller FG (systemd)
sudo fgpoller/install.sh
```

## Segurança

- Segredos só em `.env` (0600) ou variáveis de ambiente — nunca em argv, unit ou git.
- PSK, community SNMP e hashes de senha são **redigidos no parse** — não existem em
  nenhum JSON/relatório gerado.
- `.gitignore` bloqueia snapshots (`*.xml`), configs de firewall, evidências e `.env`.
- Token FortiGate vai **apenas** no header `Authorization: Bearer` (nunca query string).

## Pós-projeto

Ferramenta descartável (precedente `lbaudit`): congelar o `gaps.md` final como
evidência de aceite, desligar o fgpoller, dropar o bucket `fw_migration` e abrir
follow-up para evoluir o `forti-collector` permanente.
