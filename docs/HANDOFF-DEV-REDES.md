# HANDOFF — validação pré-virada PA→FG no TECE1 (rodar na dev-redes do TECE)

> Abra este arquivo no Claude Code da dev-redes e siga na ordem. Ele contém o
> contexto inteiro: o que já foi feito, o que executar aqui, como ler o
> resultado e o que NÃO fazer.

## Missão

O FortiGate de destino **já está configurado**. Vamos **somente validar a
virada**: ler o FGT real (somente leitura), comparar com o Palo Alto e produzir
o relatório de gaps que diz o que falta/diverge antes da janela.

| Papel | Equipamento | Gerência |
|---|---|---|
| Origem (sai) | FW01TECE01 / FW02TECE01 — PA-3250, PAN-OS 10.2.9, HA a/p | 172.18.252.23 / .24 |
| Destino (entra) | FW05TECE01-FORTINET / FW06TECE01-FORTINET — FortiGate VM, FortiOS 7.4, multi-VDOM `root`+`vsys2` | 172.18.252.43 / .44 |

Janela de virada: 05/06→31/08/2026 (REDES-1639). **Licenças PA do TECE1 vencem
20/08/2026.** vsys1=Infrabase→VDOM root; vsys2=External-Clients→VDOM vsys2.

## Regras invioláveis (leia antes de qualquer comando)

1. **Somente leitura em equipamento.** A ferramenta tem trava mecânica
   (`audit/palib/readonly.py`): PA só `<show>`/`config get|show`; FG só `GET`
   em `api/v2/{monitor,cmdb}`. Se algo pedir escrita, a resposta é **proposta
   escrita para o dono executar via RDM** — nunca comando no equipamento.
2. **Segredo nunca em argv, arquivo versionado ou log.** Senha/token só via
   variável de ambiente carregada com `read -s` ou `.env` 0600. O `.gitignore`
   já bloqueia `out/`, `*.xml`, `.env` — não forçar `git add` disso.
3. **Não instalar nada via pip.** Tudo é Python 3.6+ stdlib.
4. Os artefatos (`out/`) contêm nomes de regra e IPs de clientes — ficam na
   box, não sobem para lugar nenhum.

## Estado atual (o que já foi feito no laptop, 14/08/2026)

- Repo `totvs-cloud/paloaltotofortigate` pronto: `audit/fwaudit.py` (offline
  A01–A22, pa-baseline, fg-snapshot, compare C01–C12), `fgpoller/` (métricas FG
  → bucket Influx `fw_migration`), `dashboards/Migracao-PA-FG-TECE1/`
  (25 painéis), docs. 52 testes unitários passando em clone limpo.
- **Auditoria offline do snapshot TECE1 já executada** (4 CRÍTICOS / 7 ALTOS):
  - **46 DNATs do Check_MK** (172.27.53.x → gerência do site) precisam existir
    como VIP no FGT — 2 deles publicam a própria gerência dos FG (.43/.44);
  - **254 regras App-ID** (129 `application-default`) — conversor solta
    `service ALL`;
  - **17 regras ativas dependem de EDLs** no topo da rulebase (feeds `panw-*`
    morrem com a licença em 20/08);
  - **125 rotas específicas vazam pela default se faltarem** + 25 shadow reais;
  - 389 regras sem log, 5 com User-ID (fora de escopo), 63 PSKs a reinserir.
- **O snapshot de fevereiro está DEFASADO**: `VPN-TKS_GCP_PRD` (VPN nº 1 do
  Plano de Virada, UP em produção) não existe nele. Antes do compare oficial,
  **pedir/obter um `export configuration` novo do FW01TECE01** e usá-lo no
  passo 2. Se ainda não houver export novo, rode com o que tiver e marque o
  resultado como preliminar.

## Passo 0 — obter o repo nesta box

```bash
git clone https://github.com/totvs-cloud/paloaltotofortigate.git /opt/fw-migration/src
cd /opt/fw-migration/src
```

Se o clone vier vazio (push ainda pendente do laptop), o fallback é copiar do
laptop: `scp -r <laptop>:~/Documents/monitoramento12/paloaltotofortigate /opt/fw-migration/src`.

## Passo 1 — pré-checagens (1 min)

```bash
python3 --version                                   # >= 3.6
python3 -m unittest discover -s audit/tests | tail -2   # tem que terminar em OK
ip route get 172.18.252.43
curl -sk -o /dev/null -w '%{http_code}\n' https://172.18.252.43/api/v2/monitor/system/status
```

Leitura do curl: **401 = rede OK** (falta só autenticar). `000`/timeout = sem
rota até a gerência do FG — **pare aqui** e trate a liberação (hoje esse acesso
é publicado via DNAT no próprio PA para o Check_MK; a coleta precisa de caminho
direto da dev-redes). Não siga com o resto enquanto isso não resolver.

## Passo 2 — execução completa (o comando único)

A senha do admin do FG será pedida no prompt (sem eco — não fica em histórico
nem em `ps`). Ajuste só o caminho do `--snapshot` (export XML do PA nesta box).

```bash
cd /opt/fw-migration/src \
&& read -r -s -p "senha do admin FG: " FG_PASS && export FG_PASS && echo \
&& python3 audit/fwaudit.py offline --snapshot /dados/migracao/snapshot_v1.xml --out out/ \
&& python3 audit/fwaudit.py fg-snapshot --host 172.18.252.43 --user admin --pass-env FG_PASS \
      --hostname FW05TECE01-FORTINET --vdoms root,vsys2 --out out/ \
&& INV=$(ls -t out/*/inventario.json | head -1) \
&& FGD=$(ls -td out/*/fg-FW05TECE01-FORTINET | head -1) \
&& python3 audit/fwaudit.py compare --inventory "$INV" --fg-dir "$FGD" --out out/ \
&& unset FG_PASS \
&& echo "=== RELATÓRIO: $(ls -t out/*/gaps.md | head -1) ==="
```

Notas:
- O `fg-snapshot` faz ~40 GETs por VDOM com throttle 0,3s (2–3 min). Sessão é
  encerrada com logout ao final.
- Login recusado? Causa nº 1 é **trusthost** do admin não incluir o IP desta
  dev-redes. Causa nº 2: senha/admin bloqueado. A mensagem de erro distingue.
- Com token de API (desenho definitivo), troque `--user admin --pass-env FG_PASS`
  por `--token-env FG_TECE1_FW05_TOKEN`.
- Depois, rode o mesmo `fg-snapshot`+`compare` no **FW06** (`--host 172.18.252.44
  --hostname FW06TECE01-FORTINET`) uma vez, para confirmar que o cluster está
  idêntico.

## Passo 3 — baseline operacional do PA (evidências "antes", aba 09 do Plano)

Usa a chave de API do palo-collector que já existe nesta box
(`/opt/palo-collector/.env` — copie o NOME da variável):

```bash
python3 audit/fwaudit.py pa-baseline --host 172.18.252.23 \
    --key-env PA_TECE1_FW01_KEY --out out/
```

Imprime ike_sa / ipsec_sa_up / sessões / rotas / ARP / estado HA e grava os XML
crus. O `ipsec_sa_up` deve conversar com o baseline do Plano de Virada (57).
Com `--influx` (exige `INFLUX_URL/INFLUX_TOKEN` no ambiente e o bucket
`fw_migration` criado) o resumo vira `mig_pa_baseline` para o dashboard.

## Passo 4 — ler e entregar o resultado

O `gaps.md` tem uma tabela-resumo (ID, categoria, PA, FG, OK, Faltando) e uma
seção por check com a lista nominal do que falta. Como tratar:

| Check | Se houver "Faltando" |
|---|---|
| C01 rotas / C02 VIPs Check_MK / C03 VPNs | **Bloqueante de janela** — listar item a item com dono e prazo |
| C04 interfaces/VLANs / C05 zonas / C10 EDLs / C11 SNAT | Resolver antes do compare final |
| C07 logtraffic <100% / C12 gerência | Cegueira operacional — exigir correção (FC-1 do FortiConverter) |
| C08 UTM = 0 | Downgrade de postura — acionar SegInfo (matriz de profiles) |
| C06 / C09 | Conferir se a diferença é descarte intencional documentado |

Entregável: transformar o `gaps.md` em checklist de pendências por dono (texto,
não mudança em equipamento). Guardar `out/<ts>/` como evidência da RDM. Nada de
anexar esses arquivos em lugar público — contêm topologia e nomes de cliente.

## Passo 5 (opcional, recomendado) — dashboard ao vivo

1. Criar bucket `fw_migration` (org TOTVS, 90d) + token no Influx central
   `10.114.35.75:8086`; smoke test no RUNBOOK §4.
2. `sudo fgpoller/install.sh` e preencher `/opt/fw-migration/.env` e
   `fgpoller.conf` (FW05/FW06, vdoms root,vsys2) → `systemctl restart fgpoller`.
3. Importar `dashboards/Migracao-PA-FG-TECE1/dashboard.json` no Grafana central
   (datasource já é o `efcqeppjazvgga`).
4. Re-rodar o `compare` com `--influx` diariamente até a janela (Row 5 mostra o
   gap caindo); de hora em hora no dia.

## Depois da janela

- Trocar a senha do admin usada na coleta (circulou fora do cofre) e migrar
  para token de API read-only (`api-monitor`, RUNBOOK §2).
- Congelar o último `gaps.md` + `pa-baseline` como evidência de aceite.
- `systemctl disable --now fgpoller`, dropar o bucket `fw_migration`, revogar
  tokens (RUNBOOK §9).
