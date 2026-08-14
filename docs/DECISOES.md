# Decisões de arquitetura

| # | Decisão | Racional |
|---|---|---|
| D1 | `audit/` é pacote (CLI `fwaudit.py` + `palib/`); `fgpoller.py` é **arquivo único standalone** com ~100 linhas duplicadas de cliente/line-protocol | systemd + RHEL + PYTHONPATH quebram fácil; o poller precisa sobreviver sozinho em /opt. Duplicação aceita e documentada (precedente lbaudit: ferramenta descartável por projeto) |
| D2 | Guard-rail `assert_read_only()` **copiado literalmente** do pa-forense + trava FG (GET-only, prefixo `api/v2/{monitor,cmdb}`) | A garantia da regra "somente leitura em equipamento" é mecânica, não documental; herdamos a versão já testada pelo time |
| D3 | Token FG **só** em header `Authorization: Bearer` | O forti-collector atual manda `?access_token=` na URL — vaza em log de httpd/proxy. Não repetir |
| D4 | Snapshot XML e `out/` (evidências) **fora do repo**; `.gitignore` bloqueia `*.xml`/`*.conf`/`out/`/`.env` | PSK, hashes e IPs de cliente não vão ao GitHub. Redação acontece na origem do parse (nunca entram nas estruturas) |
| D5 | Bucket novo `fw_migration` (org TOTVS, 90d) para `fg_*`, `mig_audit`, `mig_pa_baseline`; lado PA segue nos buckets existentes | Isola o descartável — pós-projeto é `drop bucket`, como no lbaudit. Dashboard cruza buckets com queries separadas por painel |
| D6 | Tags espelhadas do palo-collector: `hostname` + `site` (+ `vdom` no FG) | Simetria PA↔FG barata nos painéis; convenção já usada em todos os measurements do parque |
| D7 | Python piso 3.6, formatação `%`, sem walrus/f-string/dataclasses; `subnet_of` reimplementado (é 3.7+) | dev-redes são RHEL com Python 3.6 possível; testes rodam em 3.11 mas não usam nada pós-3.6 |
| D8 | Fase A (offline) primeiro e independente | Licenças PA do TECE1 vencem 20/08; o relatório de risco alimenta as propostas antes de qualquer acesso a equipamento |

## Limitações conhecidas

- **User-ID/LDAP fora do escopo do projeto** (charter): o check A05 lista as
  regras impactadas, mas a decisão (trocar por IP / aceitar perda) é por regra,
  com os donos.
- **Snapshot ≠ running-config**: a Fase A audita o export que receber. A
  auditoria de 14/08/2026 provou defasagem (VPN-TKS_GCP_PRD, dada como UP no
  Plano de Virada, não existe no snapshot de fevereiro). Pedir export novo antes
  do compare final; o painel de config-change (Row 6) cobre o drift do freeze.
- **`monitor/system/resource/usage` muda formato entre builds 7.4**: parser
  defensivo (escalar, lista histórica ou dict `current`) + `--selftest`.
- **Multi-VDOM do destino é hipótese** (root+vsys2, padrão da conversão TESP4):
  a lista de vdoms é config (`fgpoller.conf` / `--vdoms`), não código.
- **Limites de capacidade da VM (A18) são referência de datasheet**: confirmar
  no destino com `monitor/system/vdom-resource`.
- **C09 compara address por nome com tolerância a sufixo `_1`/`-1`**: serviços e
  grupos ficam para conferência por amostragem do revisor (custo × benefício).
