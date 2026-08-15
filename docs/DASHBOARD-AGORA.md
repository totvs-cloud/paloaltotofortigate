# DASHBOARD AGORA — subir o Migração PA→FG TECE1 em ~10 minutos

> Objetivo único: dashboard funcionando. Auditoria/compare ficam para depois.
> Rodar na dev-redes do TECE. Tudo aqui é leitura em equipamento (GET); as
> únicas escritas são no Influx (bucket novo) e nesta própria box.

## 0. Atualizar o repo (30s)

```bash
cd /opt/fw-migration/src 2>/dev/null || sudo git clone https://github.com/totvs-cloud/paloaltotofortigate.git /opt/fw-migration/src
cd /opt/fw-migration/src && git pull
```

## 1. Bucket + token no Influx central (2 min — precisa de um token admin do Influx)

No Influx `http://10.114.35.75:8086` (org TOTVS). Pela UI: **Load Data →
Buckets → Create bucket** `fw_migration` (retenção 90d) e **API Tokens →
Custom token** com WRITE em `fw_migration` (READ opcional). Ou por CLI, se
houver `influx` configurado na box:

```bash
influx bucket create -n fw_migration -o TOTVS -r 90d
influx auth create -o TOTVS --write-bucket $(influx bucket list -n fw_migration --hide-headers | awk '{print $1}') -d "fgpoller fw_migration"
```

Smoke test da escrita (espera **204**):

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -XPOST "http://10.114.35.75:8086/api/v2/write?org=TOTVS&bucket=fw_migration&precision=s" \
  -H "Authorization: Token SEU_TOKEN_AQUI" \
  --data-binary "smoke,site=TECE01 ok=1i $(date +%s)"
```

## 2. Instalar e ligar o fgpoller (3 min)

```bash
cd /opt/fw-migration/src
sudo fgpoller/install.sh          # valida, instala em /opt/fw-migration, systemctl enable
```

Preencher **`/opt/fw-migration/.env`** (0600) — só estas duas linhas importam:

```bash
sudo tee -a /opt/fw-migration/.env >/dev/null <<'EOF'
FG_TECE1_PASS=COLOQUE_A_SENHA_DO_max.ferreira_AQUI
INFLUX_TOKEN=COLOQUE_O_TOKEN_DO_PASSO_1_AQUI
EOF
sudo chmod 600 /opt/fw-migration/.env && sudo chown fgpoller: /opt/fw-migration/.env
```

Conferir **`/opt/fw-migration/fgpoller.conf`** (o exemplo já vem certo):
- `[fw:FGT-TECE1-CLIENTE]` host `172.18.252.142` e `[fw:FGT-TECE1-INFRABASE]`
  host `172.18.252.144` — **VIPs** (nó ativo), `vdoms = root`, `user = max.ferreira`.
- ⚠️ **`site` tem que ser IGUAL à tag do palo-collector desta box**, senão os
  painéis FG ficam vazios (PA e FG usam a mesma variável $site no dashboard):

```bash
grep -B1 -A4 'tags' /opt/palo-collector/configs/firewalls.yaml | grep site
# se sair "site: TECE01" está ok (é o default do conf). Se for outro valor:
sudo sed -i 's/^site = .*/site = VALOR_QUE_SAIU/' /opt/fw-migration/fgpoller.conf
```

Ligar e conferir:

```bash
sudo systemctl restart fgpoller
journalctl -u fgpoller -f --no-pager
# esperado em ~1 min: "FGT-TECE1-CLIENTE: tiers=fast+slow+hourly lines=NN failed_endpoints=0 influx=ok"
# e o mesmo para FGT-TECE1-INFRABASE
```

| Sintoma no journal | Causa/ação |
|---|---|
| `login recusado ... credencial/trusthost` | O admin `max.ferreira` tem trusted hosts que não incluem esta dev-redes → pedir inclusão do IP (ou faixa 172.18.158.64/26) no admin, nos DOIS clusters |
| timeout/`URLError` no host | Sem rota até o VIP → validar `curl -sk https://172.18.252.142/...` (401 = rede ok) |
| `influx HTTP 403/404` | Token sem write no bucket ou bucket não criado (passo 1) |
| `failed_endpoints=N` > 0 | Algum endpoint monitor recusado p/ este admin — os painéis correspondentes ficam vazios; me traga o journal que eu ajusto |

## 3. Importar o dashboard no Grafana (2 min)

No Grafana central (`network-grafana.cloudtotvs.com.br:3000`):
**Dashboards → New → Import → Upload JSON** →
`dashboards/Migracao-PA-FG-TECE1/dashboard.json` do repo. O datasource já vai
resolvido (uid `efcqeppjazvgga`, o InfluxDB central de todos os dashboards).

Depois de importar, no topo do dashboard: selecionar **Site** (deve aparecer o
mesmo valor do passo 2), deixar PA/FG/VDOM em All.

Validação rápida sem esperar painel: **Explore** → datasource InfluxDB →
```
from(bucket: "fw_migration") |> range(start: -15m) |> filter(fn: (r) => r._measurement == "fg_collector_health") |> count()
```
Retornando linhas = coleta chegando.

## 4. O que acende quando (não estranhe painel vazio)

| Painéis | Acendem quando |
|---|---|
| Rows 1/3/4 lado **PA** (HA, sessões, CPS, WAN, CPU, mem, rotas, ARP) + "Último ponto PA" | **Imediato** — palo-collector já roda nesta box |
| Séries **FG** (laranja) em todas as rows + "HA FortiGate" + Row 2 (túneis, tabelas VPN) + "Último ponto FG" | ~2 min após o fgpoller subir (passo 2) |
| Stat "Baseline PA (pa-baseline)" | Opcional, 1 comando (abaixo) |
| Row 5 inteira (Gaps, VIPs Check_MK, % log) | Só quando rodarmos o compare — **fica vazia por enquanto, é esperado** |

Opcional (1 min, só leitura no PA, popula o stat de baseline e serve de
evidência "antes"): copie o NOME da env var da chave do FW01 no
`/opt/palo-collector/.env` e rode:

```bash
set -a && . /opt/palo-collector/.env && set +a
INFLUX_URL=http://10.114.35.75:8086 INFLUX_ORG=TOTVS INFLUX_BUCKET=fw_migration INFLUX_TOKEN=SEU_TOKEN \
python3 audit/fwaudit.py pa-baseline --host 172.18.252.23 --key-env NOME_DA_VAR_DA_CHAVE --influx --out out/
```

## 5. Ajustes finos prováveis (2 min, depois que os dados chegarem)

1. **Tabela "7 VPNs InfraBase" vazia com túneis UP no stat?** Os nomes phase1
   reais dos clusters diferem do de-para do Plano. Descubra os nomes:
   Explore → `from(bucket:"fw_migration") |> range(start:-15m) |> filter(fn:(r)=>r._measurement=="fg_vpn_tunnel") |> keep(columns:["phase1"]) |> distinct(column:"phase1")`
   e me mande a lista — eu corrijo o regex do painel e o vpnmap num commit.
2. **Painel "Tráfego WAN — FG"**: a variável `$fg_wan` (topo) vem `.*` (todas
   as interfaces). Quando souber o nome da interface WAN dos clusters, digite o
   nome/regex nela para o painel comparar só WAN×WAN.
3. **Duas linhas laranja** nos gráficos (uma por cluster) é o comportamento
   esperado — CLIENTE e INFRABASE aparecem separados; somas (túneis, rotas,
   ARP) já agregam os dois sem dupla contagem (coleta via VIP).

## Depois (quando a poeira baixar)

- Trocar a senha do `max.ferreira` (circulou fora do cofre) e criar o api-user
  read-only por cluster (RUNBOOK §2), trocando `user/pass_env` por `token_env`
  no fgpoller.conf.
- Rodar a Fase B/C (`fg-snapshot` + `compare --influx`) para acender a Row 5 —
  comandos prontos no HANDOFF-DEV-REDES.md, Passo 2.
