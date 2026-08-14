# RUNBOOK — dev-redes do TECE

Ordem de execução da auditoria e da observabilidade da migração PA→FG no TECE1.
Tudo aqui é **somente leitura em equipamento**; o que exigir mudança (liberação
de acesso, criação de admin, bucket) é proposta para o dono da mudança executar
via RDM — nunca a ferramenta.

## 1. Pré-requisito de rede — validar ANTES de tudo

A gerência dos FortiGates (`172.18.252.43/.44`) é hoje publicada para o Check_MK
**via DNAT no próprio Palo Alto** (`DNAT-FW05TECE01_Trad-1` / `DNAT-FW06TECE01_Trad-1`,
destino `172.27.53.21/.22`). Se a coleta depender desse caminho, ela morre exatamente
no passo "shutdown interfaces PA" da virada (aba 05).

Da dev-redes TECE (172.18.158.70–.73), valide rota direta:

```bash
ip route get 172.18.252.43
curl -sk -o /dev/null -w '%{http_code}\n' https://172.18.252.43/api/v2/monitor/system/status
# 401 = rede OK (falta token). 000/timeout = tratar rota/liberação ANTES de seguir.
```

Se não alcançar: propor liberação L3 direta dev-redes→252.0/24 (e trusted host,
ver §2). Não seguir adiante sem isso resolvido.

## 2. Credencial FortiGate (proposta escrita — executa quem opera o FG)

Criar admin de API **somente leitura** com trusted host restrito à dev-redes:

```text
config system accprofile
    edit "monitor-ro"
        set scope vdom
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
config system api-user
    edit "api-monitor"
        set accprofile "monitor-ro"
        set vdom "root" "vsys2"
        config trusthost
            edit 1
                set ipv4-trusthost 172.18.158.64 255.255.255.192
            next
        end
    next
end
execute api-user generate-key api-monitor
```

Guardar o token no `.env` (0600) — `FG_TECE1_FW05_TOKEN=` / `FG_TECE1_FW06_TOKEN=`.
O token viaja **só** em header `Authorization: Bearer` (decisão D3).

## 3. Credencial Palo Alto

Reusar o padrão do palo-collector da própria box: as chaves já existem no
`/opt/palo-collector/.env` local. Copie os NOMES das variáveis para o `.env`
deste projeto ou exporte no shell (`PA_TECE1_FW01_KEY=...`). Perfil da chave:
o mesmo read-only já usado pelo coletor.

## 4. InfluxDB — bucket e token (uma vez)

No Influx central (`http://10.114.35.75:8086`, org TOTVS):
- criar bucket **`fw_migration`** com retenção **90d** (descartável no pós-projeto);
- criar token **write-only** para esse bucket (fgpoller/compare) e um read para o
  Grafana se o datasource central ainda não enxergar o bucket.

Smoke test da escrita (espera HTTP 204):

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -XPOST "http://10.114.35.75:8086/api/v2/write?org=TOTVS&bucket=fw_migration&precision=s" \
  -H "Authorization: Token $INFLUX_TOKEN" \
  --data-binary "smoke,site=TECE1 ok=1i $(date +%s)"
```

## 5. Deploy na dev-redes

```bash
git clone https://github.com/totvs-cloud/paloaltotofortigate.git /opt/fw-migration/src
cd /opt/fw-migration/src
python3 -m unittest discover -s audit/tests          # tem que passar
cp .env.example .env && chmod 600 .env               # preencher
sudo fgpoller/install.sh                             # valida, instala, ENABLE
```

Lições herdadas do parque (DEPLOY-CONFIGLOG-EDGES): `systemctl enable` é
obrigatório (coletor sem enable não volta de reboot); `ProtectSystem=strict`
silencia erro de escrita fora de `ReadWritePaths` — se criar diretório novo de
escrita, inclua no unit; config local da box vence a do repo.

## 6. Ordem de execução

| # | Comando | O quê |
|---|---|---|
| a | `python3 audit/fwaudit.py offline --snapshot <export.xml> --out out/` | Fase A — relatório de risco (não toca equipamento) |
| b | — | Revisar relatório; transformar CRÍTICO/ALTO em propostas/pendências com os donos |
| c | `python3 audit/fwaudit.py pa-baseline --host 172.18.252.23 --key-env PA_TECE1_FW01_KEY --influx --out out/` | Evidências "antes" (aba 09) + `mig_pa_baseline` |
| d | `systemctl start fgpoller` | Lado FG do dashboard no ar |
| e | Importar `dashboards/Migracao-PA-FG-TECE1/dashboard.json` no Grafana central | Dashboard |
| f | `python3 audit/fwaudit.py fg-snapshot --host 172.18.252.43 --token-env FG_TECE1_FW05_TOKEN --vdoms root,vsys2 --out out/` | Dump read-only do FG |
| g | `python3 audit/fwaudit.py compare --inventory out/<ts>/inventario.json --fg-dir out/<ts>/fg-<host> --influx --out out/` | Paridade C01–C12 → gaps.md + painel "Gaps" |

Repetir (f)+(g) **diariamente** até a virada e **de hora em hora no dia**; repetir
(c) imediatamente antes da janela (baseline oficial).

⚠️ O snapshot XML usado na Fase A pode estar defasado (a auditoria de 14/08
encontrou VPN do Plano ausente do snapshot). Antes do compare final, pedir ao
time um `export configuration` novo do FW01TECE01 e rodar (a) de novo.

## 7. Dia da virada — painel × critério de aceite (aba 08)

| Critério (aba 08) | Onde olhar |
|---|---|
| Interfaces | Row 3 (tráfego WAN, erros) + Row 4 ARP subindo no FG |
| Roteamento | Row 4 "Rotas estáticas PA × FG" (FG deve alcançar 130) |
| PBF | Manual (aba 03: disable → rota 172.22.66.176 → enable) — evidência no pa-baseline |
| VPNs / Phase 1-2 | Row 2 inteira (7 InfraBase nominais + CBL3SH + DOWN agora) |
| Tráfego | Row 1 "Sessões PA × FG" cruzando + CPS |
| ARP | Row 4 |
| DNS / Aplicações / Acesso | Manuais (cadernos de teste por squad) |
| Monitoramento | Row 5 "VIPs Check_MK" = 100% + Row 6 prova de vida verde |
| Aceite | Row 5 "Gaps por categoria" sem CRÍTICO pendente |

## 8. Rollback

O plano de rollback é o do Plano de Virada (aba 07). No dashboard, rollback
saudável = sessões voltando ao PA (Row 1), SAs re-estabelecendo no PA (Row 2 —
PSK padronizada permite retorno sem troca de senha), ARP voltando (Row 4).
Depois de rollback, rodar (c) de novo para re-baseline.

## 9. Pós-projeto (precedente lbaudit)

1. Congelar o último `gaps.md` + relatório como evidência de aceite (anexar à RDM).
2. `systemctl disable --now fgpoller`.
3. Dropar o bucket `fw_migration` e revogar tokens (FG e Influx).
4. Abrir follow-up: evoluir o `forti-collector` Go permanente com o que o
   fgpoller provou (endpoints, vdom, tags) — este repo então se arquiva.

## 10. Limites de segurança

- Trava mecânica dos dois lados: PA só `<show>`/`config get|show`/`log`
  (`audit/palib/readonly.py`, testada); FG só `GET` em `api/v2/{monitor,cmdb}`.
- Segredos: nunca em argv/unit/git; só `.env` 0600 e variáveis de ambiente.
- PSK, community SNMP e hashes **não existem** nos artefatos gerados (redação na
  origem do parse, com teste garantindo).
- Snapshots XML e saídas (`out/`) ficam FORA do repo (`.gitignore`) — contêm
  nomes de regra/IPs de cliente.
