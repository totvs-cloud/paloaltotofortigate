# -*- coding: utf-8 -*-
"""palib — biblioteca da auditoria de migração Palo Alto → FortiGate.

Python 3.6+, só stdlib (dev-redes são RHEL sem pip garantido).
Formatação com %% por decisão de projeto (docs/DECISOES.md, D7).
"""

VERSION = "1.0.0"

# Site alvo desta onda. TESP4 reutiliza trocando estas constantes/CLI, não código.
SITE = "TECE1"

# vsys do Palo Alto → VDOM do FortiGate (padrão observado na conversão de referência)
VDOM_MAP = {
    "vsys1": "root",    # Infrabase
    "vsys2": "vsys2",   # External-Clients
}

# Texto que substitui qualquer segredo NO PARSE (nunca chega às estruturas).
REDACTED = "<REDIGIDO>"
