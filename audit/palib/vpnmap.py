# -*- coding: utf-8 -*-
"""De-para de VPNs PA → FG e constantes de validação da virada.

Fonte: Plano_de_Virada_Palo_Alto_FortiGate.xlsx (abas 00–04), TECE1.
Atualizar aqui quando o plano mudar — o compare e o dashboard leem daqui.
"""

# fg_phase1_name: (pa_ike_gateway, status_baseline_no_plano)
INFRABASE = {
    "VPN-TKS_GCP_Prod": ("VPN-TKS_GCP_PRD", "UP"),
    "VPN_TESP03_P1":    ("VPN-TECE1_to_TESP03_Phase1", "UNKNOWN"),
    "VPN_TESP05_P1":    ("VPN-TECE1_to_TESP05_Phase1", "UP"),
    "VPN_TESP1_CLD":    ("VPN-TECE1_to_TESP1-Cloud_Phase1", "UNKNOWN"),
    "VPN_TESP1_TRD":    ("VPN-TECE1_to_TESP1-Trad_Phase1", "UNKNOWN"),
    "VPN_TESP6":        ("VPN-S2S-TECE01-TO-TESP6-P1", "UP"),
    "VPN_TESP7":        ("VPN-TECO1_to_TESP7", "UP"),
}
# Correção de digitação do xlsx: o gateway real no snapshot é VPN-TECE01_to_TESP7.
INFRABASE["VPN_TESP7"] = ("VPN-TECE01_to_TESP7", "UP")

# Túneis de clientes validados no plano (abas 03/04) — casados por substring.
CBL3SH_PATTERN = "CBL3SH"

# Pings link-local da validação de clientes (aba 03): (origem, destino).
LINKLOCAL_PINGS = [
    ("169.254.10.1", "169.254.10.2"),
    ("169.254.11.1", "169.254.11.2"),
    ("169.254.12.1", "169.254.12.2"),
]

# Rota usada na validação de PBF (aba 03).
PBF_VALIDATION_ROUTE = "172.22.66.176"

# Baseline VPN registrado na aba 00 (números do PA antes da virada).
PLANO_BASELINE = {
    "ike_gateways": 73,
    "ipsec_configured": 98,
    "ipsec_sa_up": 57,
    "vpns_infrabase_total": 7,
    "vpns_infrabase_up": 4,
}


def pa_to_fg():
    """Índice invertido: nome do gateway PA → nome phase1 FG."""
    out = {}
    for fg_name, pair in INFRABASE.items():
        out[pair[0]] = fg_name
    return out
