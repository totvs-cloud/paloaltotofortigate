# audit — fwaudit

Auditoria read-only da migração PA→FG. Python 3.6+, só stdlib.

```bash
# Fase A — offline (não toca equipamento). Snapshot fica FORA do repo.
python3 fwaudit.py offline --snapshot /dados/migracao/snapshot_v1.xml --out out/

# Fase B1 — baseline operacional do PA (evidências "antes", aba 09 do Plano)
python3 fwaudit.py pa-baseline --host 172.18.252.23 --key-env PA_TECE1_FW01_KEY --influx --out out/

# Fase B2 — dump read-only do FortiGate (paginado, com throttle)
python3 fwaudit.py fg-snapshot --host 172.18.252.43 --token-env FG_TECE1_FW05_TOKEN --vdoms root,vsys2 --out out/

# Fase C — paridade PA↔FG → gaps.md (+ mig_audit no Influx com --influx)
python3 fwaudit.py compare --inventory out/<ts>/inventario.json --fg-dir out/<ts>/fg-<host> --influx --out out/

# testes
python3 -m unittest discover -s tests
```

- `--dry-run` (pa-baseline/fg-snapshot) imprime as URLs sem chamar nada.
- Credenciais SEMPRE via variável de ambiente (`--key-env`/`--token-env` recebem
  o NOME da variável); `--env-file .env` carrega um dotenv simples.
- A trava de leitura (`palib/readonly.py`) aborta o processo diante de qualquer
  requisição que não seja GET/show — é herdada do pa-forense e coberta por teste.
- Checks: A01–A22 (offline) em `palib/checks.py`; C01–C12 (paridade) em
  `palib/compare.py`; de-para de VPNs em `palib/vpnmap.py` (fonte: Plano de
  Virada — atualizar lá quando o plano mudar).
