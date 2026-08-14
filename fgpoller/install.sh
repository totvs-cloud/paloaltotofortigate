#!/usr/bin/env bash
# install.sh — instala o fgpoller na dev-redes (RHEL). Idempotente.
# Uso: sudo ./install.sh            (a partir do checkout do repo)
#      DRY_RUN=1 ./install.sh       (só mostra o que faria)
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/fw-migration}"
SERVICE_USER="${SERVICE_USER:-fgpoller}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN() { if [ "${DRY_RUN:-0}" = "1" ]; then echo "[dry-run] $*"; else "$@"; fi; }

echo "== fgpoller install =="
command -v python3 >/dev/null || { echo "ERRO: python3 não encontrado"; exit 1; }
python3 - <<'EOF'
import sys
if sys.version_info < (3, 6):
    sys.exit("ERRO: python3 >= 3.6 requerido, encontrado %s" % sys.version)
EOF

echo "-- validando sintaxe"
python3 -m py_compile "$SRC_DIR/fgpoller.py"
python3 "$SRC_DIR/fgpoller.py" --selftest >/dev/null
echo "   selftest OK"

echo "-- usuário e diretórios"
id -u "$SERVICE_USER" >/dev/null 2>&1 || RUN useradd -r -s /sbin/nologin "$SERVICE_USER"
RUN install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$INSTALL_DIR" "$INSTALL_DIR/logs"

echo "-- arquivos"
RUN install -m 0755 "$SRC_DIR/fgpoller.py" "$INSTALL_DIR/fgpoller.py"
if [ ! -f "$INSTALL_DIR/fgpoller.conf" ]; then
  RUN install -m 0644 "$SRC_DIR/fgpoller.conf.example" "$INSTALL_DIR/fgpoller.conf"
  echo "   >>> edite $INSTALL_DIR/fgpoller.conf (hosts/vdoms/site)"
fi
if [ ! -f "$INSTALL_DIR/.env" ]; then
  RUN touch "$INSTALL_DIR/.env"
  RUN chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.env"
  RUN chmod 0600 "$INSTALL_DIR/.env"
  echo "   >>> preencha $INSTALL_DIR/.env: FG_TECE1_FW05_TOKEN=, FG_TECE1_FW06_TOKEN=, INFLUX_TOKEN="
fi

echo "-- teste de 1 ciclo (dry-run, precisa de tokens no .env para falar com os FG)"
if [ "${SKIP_ONCE:-0}" != "1" ] && [ "${DRY_RUN:-0}" != "1" ]; then
  sudo -u "$SERVICE_USER" python3 "$INSTALL_DIR/fgpoller.py" \
    --config "$INSTALL_DIR/fgpoller.conf" --env-file "$INSTALL_DIR/.env" \
    --once --dry-run | tail -5 || {
      echo "   AVISO: ciclo de teste falhou (tokens vazios? FG inalcançável?)."
      echo "   Siga docs/RUNBOOK.md §1 (rota) e §2 (credenciais) antes do enable."
    }
fi

echo "-- systemd"
RUN install -m 0644 "$SRC_DIR/fgpoller.service" /etc/systemd/system/fgpoller.service
RUN systemctl daemon-reload
# enable é OBRIGATÓRIO: já houve coletor no parque que não voltou de reboot.
RUN systemctl enable fgpoller
echo
echo "Pronto. Depois de preencher .env e fgpoller.conf:"
echo "  systemctl restart fgpoller && journalctl -u fgpoller -f"
