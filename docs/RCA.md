# RCA da 1ª tentativa de virada — auditoria completa (rodar na dev-redes)

> Rollback executado. Objetivo: provar POR QUE falhou e chegar na próxima
> janela com cada causa fechada. Tudo somente leitura; correção = proposta.

## O que a ferramenta coleta agora (novidades pós-incidente)

| Comando | O quê | Serve para |
|---|---|---|
| `fg-logs` | Logs de evento do FortiOS (system/HA/VPN/user/router) + **revisões de config** (quem salvou o quê, quando) | O que aconteceu nos clusters durante a janela |
| `pa-logs` | Config log + system log do PA na janela (job assíncrono) | O que mudou/alarmou no PA durante a janela e o rollback |
| `rca` | **Linha do tempo unificada** PA+FG da janela | O documento-base do RCA |
| `offline` (A23 novo) | Interfaces do PA com clamp de **TCP-MSS** e o valor a replicar | O "sessão abre e trava" — TECE1 tem clamp nas DUAS WANs (ae1.2906/2910 → tcp-mss 1292) |
| `compare` (C13–C17 novos) | MSS, **trânsito entre os 2 clusters**, TODOS os DNATs→VIP, **default route/gateway por lado**, PBF→policy routes | As 5 causas prováveis do sintoma da janela |

## Execução (bloco único — ajuste a janela da virada em START/END)

```bash
cd /opt/fw-migration/src && git pull \
&& export INFLUX_URL=http://10.114.35.75:8086 INFLUX_ORG=TOTVS INFLUX_BUCKET=fw_migration \
&& START='2026/08/14 22:00:00' END='2026/08/15 03:00:00' \
&& SNAP=/dados/migracao/snapshot_v1.xml \
&& python3 audit/fwaudit.py --env-file /opt/fw-migration/.env offline --snapshot "$SNAP" --out out/ \
&& python3 audit/fwaudit.py --env-file /opt/fw-migration/.env pa-logs --host 172.18.252.23 \
      --key-env PA_TECE1_FW01_KEY --start "$START" --end "$END" --out out/ \
&& for FG in "172.18.252.144 FW0201TECE01-INFRABASE" "172.18.252.142 FW0101TECE01-CLIENTE"; do \
     set -- $FG; \
     python3 audit/fwaudit.py --env-file /opt/fw-migration/.env fg-logs --host $1 \
        --user max.ferreira --pass-env FG_TECE1_PASS --hostname $2 --out out/; \
     python3 audit/fwaudit.py --env-file /opt/fw-migration/.env fg-snapshot --host $1 \
        --user max.ferreira --pass-env FG_TECE1_PASS --hostname $2 --vdoms root --out out/; \
   done \
&& INV=$(ls -t out/*/inventario.json | head -1) \
&& FGI=$(ls -td out/*/fg-FW0201TECE01-INFRABASE | head -1) \
&& FGC=$(ls -td out/*/fg-FW0101TECE01-CLIENTE | head -1) \
&& python3 audit/fwaudit.py --env-file /opt/fw-migration/.env compare --inventory "$INV" \
      --fg vsys1="$FGI" --fg vsys2="$FGC" --influx --out out/ \
&& python3 audit/fwaudit.py rca --dir out --start "$START" --end "$END" \
      --nota "1ª tentativa de virada: pouco tráfego de retorno + sessões em timeout; rollback executado" \
&& echo "=== RCA: $(ls -t out/*/rca-timeline.md | head -1) ===" \
&& echo "=== GAPS: $(ls -t out/*/gaps.md | head -1) ==="
```

⚠️ O fg-snapshot pós-rollback captura a config "como ficou" — se alguém já
mexeu nos clusters depois da janela, as **revisões de config** (fg-logs) contam
essa história.

## Como montar o RCA a partir dos artefatos

1. **`rca-timeline.md`** — a espinha dorsal: shutdown das interfaces do PA,
   eventos de HA/link/VPN nos FG, mudanças de config durante a janela, rollback.
2. **`gaps.md` C13–C17** — as hipóteses técnicas do sintoma, em ordem de
   probabilidade para "pouco retorno + timeout":
   - **C16 default route/gateway** divergente → retorno sai pelo lugar errado;
   - **C14 trânsito entre clusters** ausente → todo fluxo CLIENTE↔INFRA half-open;
   - **C13 TCP-MSS** ausente nas WANs → sessão abre e trava (PA clampava nas 2 WANs);
   - **C01 rotas específicas** faltando → retorno vaza pela default;
   - **C11/C15 SNAT/DNAT** → saída com IP errado / serviço publicado morto.
3. **A23** dá o valor exato de `tcp-mss` a propor por interface.
4. Cruze com o dashboard da janela (Rows 1/3/4: sessões, erros de interface,
   ARP/rotas no tempo) — os gráficos do horário são evidência de RCA.
5. Cada causa confirmada vira **proposta escrita** (RDM) com dono; a próxima
   janela só se agenda com C13/C14/C16 zerados e C01 explicado item a item.

## Segurança

Mesmas travas de sempre: PA só `<show>`/`config get|show`/`log`; FG só GET em
`api/v2/{monitor,cmdb,log}`. Logs coletados podem conter IPs/usuários — ficam
em `out/` (fora do git), como todo artefato.
