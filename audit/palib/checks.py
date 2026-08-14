# -*- coding: utf-8 -*-
"""Checks A01–A22 da auditoria offline (Fase A).

Cada check recebe o inventário (inventory.build_inventory) e devolve:
    {"id", "titulo", "severidade", "resumo", "itens": [...], "classe_fc"}
`itens` é a evidência tabular (vira JSON próprio no out/). `classe_fc` aponta a
classe de falha observada na conversão FortiConverter do TESP4 que o check
cobre ("-" quando o risco não vem do conversor).

Severidades em ordem: CRITICO > ALTO > MEDIO > BAIXO > INFO.
"""

import ipaddress
import re

from .vpnmap import INFRABASE, PLANO_BASELINE

CRITICO, ALTO, MEDIO, BAIXO, INFO = "CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO"
SEV_ORDER = {CRITICO: 0, ALTO: 1, MEDIO: 2, BAIXO: 3, INFO: 4}

VSYS_LIST = ("vsys1", "vsys2")

# EDLs predefinidas do PAN-OS: referenciáveis em regra sem objeto explícito.
PANW_BUILTIN_EDLS = (
    "panw-bulletproof-ip-list", "panw-highrisk-ip-list",
    "panw-known-ip-list", "panw-torexit-ip-list",
)

# Códigos de região/país embutidos do PAN-OS usados direto em regra (a conversão
# do TESP4 os deixou como objetos indefinidos: A1, A2, AP, CE, DN, EU, LN…).
GEO_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]$")

# Caracteres aceitos em nome de objeto FortiOS sem risco de rename silencioso.
FG_SAFE_NAME_RE = re.compile(r"^[0-9A-Za-z._/ -]+$")
FG_NAME_MAX = 79  # limite prático de nome em FortiOS 7.x

# Limites de referência p/ FortiGate-VM (confirmar no destino com
# monitor/system/vdom-resource — variam por licença/vCPU). Fonte: datasheet VM v7.4.
FG_VM_REFERENCE_LIMITS = {
    "sessions": 8000000,       # VM08 com 16 GB+ de RAM
    "policies": 100000,
    "static_routes": 50000,
    "phase1_tunnels": 20000,
}
PA_OBSERVED_PEAKS = {  # aba Geral do estudo de sizing (picos reais TECE1)
    "sessions_vsys1": 99530, "sessions_vsys2": 154021,
    "cps_vsys1": 8000, "cps_vsys2": 15000,
}


def _enabled_rules(inv, vsys):
    return [r for r in inv[vsys]["security_rules"] if not r["disabled"]]


def _all_address_names(inv):
    names = set()
    for scope in ("shared", "vsys1", "vsys2"):
        objs = inv[scope]["objects"] if scope != "shared" else inv["shared"]["objects"]
        names.update(objs["address"].keys())
        names.update(objs["address_group"].keys())
    return names


def _rule_ref(vsys, rule):
    return {"vsys": vsys, "pos": rule["position"], "regra": rule["name"],
            "action": rule.get("action", "")}


# ---------------------------------------------------------------------------

def check_a01_edl_rules(inv):
    edl_names = set(e["name"] for e in inv["edls"]) | set(PANW_BUILTIN_EDLS)
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            used = sorted(edl_names.intersection(r["source"] + r["destination"]))
            if used:
                item = _rule_ref(vsys, r)
                item["edls"] = used
                itens.append(item)
    return {
        "id": "A01", "titulo": "Regras ativas que dependem de EDL/feed de reputação",
        "severidade": CRITICO, "classe_fc": "FC-4 (objeto indefinido)",
        "resumo": ("%d regras ativas referenciam EDLs. O FortiConverter não converte "
                   "EDL: cada uma vira objeto indefinido e a policy falha ou carrega "
                   "furada. Recriar como system/external-resource + threat feed ANTES "
                   "da virada; feeds panw-* morrem junto com a licença PA (20/08)."
                   % len(itens)),
        "itens": itens,
    }


def check_a02_geo_codes(inv):
    defined = _all_address_names(inv)
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            codes = sorted(set(m for m in r["source"] + r["destination"]
                               if GEO_CODE_RE.match(m) and m not in defined
                               and m != "any"))
            if codes:
                item = _rule_ref(vsys, r)
                item["codigos"] = codes
                itens.append(item)
    return {
        "id": "A02", "titulo": "Regras com código de país/região embutido do PAN-OS",
        "severidade": ALTO, "classe_fc": "FC-5 (geo indefinido)",
        "resumo": ("%d regras usam códigos geo do PAN (ex.: BR, EU, AP). No FG viram "
                   "objeto indefinido. Remediação pronta: pacote OBJETOS GEO BLOCK "
                   "(245 address type geography + 8 addrgrp R_*), mas o de-para "
                   "código→grupo precisa ser feito regra a regra." % len(itens)),
        "itens": itens,
    }


def check_a03_appid(inv):
    itens = []
    worst = 0
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            apps = [a for a in r["application"] if a != "any"]
            if not apps:
                continue
            app_default = "application-default" in r["service"]
            if app_default:
                worst += 1
            item = _rule_ref(vsys, r)
            item["applications"] = apps[:8]
            item["service"] = r["service"]
            item["application_default"] = app_default
            itens.append(item)
    return {
        "id": "A03", "titulo": "Regras baseadas em App-ID (sem equivalente direto no FG)",
        "severidade": CRITICO, "classe_fc": "FC-3 (App-ID cru / service ALL)",
        "resumo": ("%d regras ativas usam application específica; %d delas com "
                   "service=application-default. 'set application' não existe em "
                   "firewall policy FortiOS — o conversor solta service ALL, abrindo "
                   "portas hoje fechadas. Cada uma precisa de decisão: service "
                   "explícito ou Application Control." % (len(itens), worst)),
        "itens": itens,
    }


def check_a04_any_any_service(inv):
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            if r["action"] != "allow":
                continue
            if r["service"] == ["any"] and r["application"] == ["any"]:
                item = _rule_ref(vsys, r)
                item["source"] = r["source"][:4]
                item["destination"] = r["destination"][:4]
                itens.append(item)
    return {
        "id": "A04", "titulo": "Allows com service=any E application=any",
        "severidade": ALTO, "classe_fc": "-",
        "resumo": ("%d allows são any/any de serviço e aplicação. No PA o App-ID "
                   "ainda limitava alguma coisa; no FG viram ALL verdadeiro. Revisar "
                   "se cabem service explícito antes de migrar." % len(itens)),
        "itens": itens,
    }


def check_a05_userid(inv):
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            users = [u for u in r["source_user"] if u != "any"]
            if users:
                item = _rule_ref(vsys, r)
                item["source_user"] = users
                itens.append(item)
    return {
        "id": "A05", "titulo": "Regras com User-ID/grupo LDAP",
        "severidade": ALTO, "classe_fc": "FC-6 (grupo não resolvido)",
        "resumo": ("%d regras ativas casam por usuário/grupo. Integração de "
                   "autenticação (AD/FSSO/LDAP) está FORA do escopo do projeto: sem "
                   "decisão por regra (trocar por origem IP ou aceitar perda), a "
                   "regra nunca casa no FG e o fluxo cai." % len(itens)),
        "itens": itens,
    }


def check_a06_no_log(inv):
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            if not r["log_setting"]:
                itens.append(_rule_ref(vsys, r))
    return {
        "id": "A06", "titulo": "Regras ativas sem log-setting (e aviso do conversor)",
        "severidade": ALTO, "classe_fc": "FC-1 (logtraffic disable em 100%)",
        "resumo": ("%d regras ativas já não logam no PA. Pior: a conversão de "
                   "referência saiu com set logtraffic disable em ~100%% das policies "
                   "— aplicada como está, ELK/SIEM e FortiAnalyzer ficam cegos no dia "
                   "1. Exigir pass de logtraffic all + syslogd apontado para o ELK "
                   "(ver A15) antes do aceite." % len(itens)),
        "itens": itens,
    }


def check_a07_no_profile(inv):
    itens = []
    used_profiles = {}
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            if r["profile_type"] == "none":
                itens.append(_rule_ref(vsys, r))
            else:
                key = "%s:%s" % (r["profile_type"], ",".join(r["profiles"]))
                used_profiles[key] = used_profiles.get(key, 0) + 1
    return {
        "id": "A07", "titulo": "Regras sem security profile + inventário de profiles em uso",
        "severidade": MEDIO, "classe_fc": "FC-2 (zero UTM convertido)",
        "resumo": ("%d regras ativas sem nenhum profile. E o conversor não gera UTM "
                   "algum: todos os attachments precisam ser recriados a partir da "
                   "matriz SEGINFO (Draft - Security profiles PA→FG). Uso atual: %s"
                   % (len(itens),
                      "; ".join("%s=%d" % kv for kv in sorted(used_profiles.items())))),
        "itens": itens,
    }


def check_a08_disabled(inv):
    itens = []
    for vsys in VSYS_LIST:
        for r in inv[vsys]["security_rules"]:
            if r["disabled"]:
                itens.append(_rule_ref(vsys, r))
    return {
        "id": "A08", "titulo": "Regras desabilitadas",
        "severidade": BAIXO, "classe_fc": "FC-11 (disabled carregadas)",
        "resumo": ("%d regras desabilitadas. Decidir ANTES da conversão: migrar "
                   "desabilitada (lixo vira lixo) ou descartar — o conversor carrega "
                   "tudo com status disable." % len(itens)),
        "itens": itens,
    }


def check_a09_fqdn(inv):
    fqdn_objs = {}
    for scope in ("shared", "vsys1", "vsys2"):
        objs = inv["shared"]["objects"] if scope == "shared" else inv[scope]["objects"]
        for name, a in objs["address"].items():
            if a["type"] == "fqdn":
                fqdn_objs[name] = a["value"]
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            used = sorted(set(r["source"] + r["destination"]).intersection(fqdn_objs))
            if used:
                item = _rule_ref(vsys, r)
                item["fqdns"] = [{"objeto": u, "fqdn": fqdn_objs[u]} for u in used]
                itens.append(item)
    return {
        "id": "A09", "titulo": "Regras dependentes de objetos FQDN",
        "severidade": MEDIO, "classe_fc": "FC-7 (incoming interface failed)",
        "resumo": ("%d objetos FQDN definidos; %d regras ativas dependem deles. "
                   "Resolução DNS divergente entre PA e FG muda o efeito da regra — "
                   "conferir DNS do FG (A15) e TTL/refresh." % (len(fqdn_objs), len(itens))),
        "itens": itens,
    }


def _resolve_members(inv, vsys, names):
    """Resolve nomes → valores de address (1 nível de grupo), p/ achar IPs literais."""
    out = []
    for scope in (vsys, "shared"):
        objs = inv["shared"]["objects"] if scope == "shared" else inv[scope]["objects"]
        for n in names:
            if n in objs["address"]:
                out.append(objs["address"][n]["value"])
            elif n in objs["address_group"] and objs["address_group"][n].get("members"):
                for m in objs["address_group"][n]["members"]:
                    if m in objs["address"]:
                        out.append(objs["address"][m]["value"])
    return out


def check_a10_checkmk_dnat(inv):
    itens = []
    for vsys in VSYS_LIST:
        for r in inv[vsys]["nat_rules"]:
            if not r["dnat_address"]:
                continue
            src_blob = " ".join(r["source"]).lower()
            dsts = r["destination"] + _resolve_members(inv, vsys, r["destination"])
            hits_53 = [d for d in dsts if d.startswith("172.27.53.")]
            if "check" not in src_blob and not hits_53:
                continue
            translated = r["dnat_address"]
            to_fg_mgmt = translated.startswith(("172.18.252.43", "172.18.252.44"))
            itens.append({
                "vsys": vsys, "regra": r["name"], "disabled": r["disabled"],
                "extip": ", ".join(d for d in r["destination"]),
                "extip_resolvido": ", ".join(hits_53) or "-",
                "mappedip": translated,
                "mappedport": r["dnat_port"] or "-",
                "service": r["service"],
                "to_zone": ", ".join(r["to"]),
                "vip_fg_sugerido": "VIP_%s" % r["name"].replace(" ", "_"),
                "atencao": ("DNAT para a gerência do PRÓPRIO FortiGate — o caminho de "
                            "monitoração morre quando o PA desligar; desenhar acesso "
                            "direto" if to_fg_mgmt else ""),
            })
    return {
        "id": "A10", "titulo": "DNATs do Check_MK → lista de VIPs obrigatórios no FG",
        "severidade": CRITICO, "classe_fc": "-",
        "resumo": ("%d regras DNAT publicam a gerência do site (172.27.53.x) para o "
                   "Check_MK centralizado ATRAVÉS do Palo Alto. Cada uma precisa "
                   "existir no FG como firewall vip + policy antes da virada — "
                   "esquecê-las cega o monitoramento do edge inteiro. Atenção às que "
                   "publicam a própria gerência dos FortiGates (.43/.44)."
                   % len(itens)),
        "itens": itens,
    }


def _subnet_of(net_a, net_b):
    """net_a ⊂ net_b (mesma família). ipaddress.subnet_of é 3.7+; aqui é o piso 3.6."""
    if net_a.version != net_b.version:
        return False
    return (net_a.network_address >= net_b.network_address
            and net_a.broadcast_address <= net_b.broadcast_address)


def check_a11_routes(inv):
    tunnel_ifaces = set(t["tunnel_interface"] for t in inv["network"]["ipsec_tunnels"]
                        if t["tunnel_interface"])
    tunnel_units = set(inv["network"]["interfaces"]["tunnel_units"])
    problemas = []
    total = 0
    routes_by_vr = inv["network"]["static_routes"]
    for vr, routes in routes_by_vr.items():
        total += len(routes)
        # binding rota → túnel inexistente
        for r in routes:
            iface = r["interface"]
            if iface.startswith("tunnel.") and iface not in tunnel_units:
                problemas.append({"tipo": "rota_para_tunel_inexistente", "vr": vr,
                                  "rota": r["name"], "destino": r["destination"],
                                  "interface": iface})
            if iface.startswith("tunnel.") and iface not in tunnel_ifaces:
                problemas.append({"tipo": "tunel_sem_ipsec_associado", "vr": vr,
                                  "rota": r["name"], "destino": r["destination"],
                                  "interface": iface})
        # sobreposição específica × agregada com saída divergente (shadow route)
        parsed = []
        for r in routes:
            try:
                parsed.append((ipaddress.ip_network(r["destination"], strict=False), r))
            except ValueError:
                continue
        for net_a, ra in parsed:
            for net_b, rb in parsed:
                if net_a is net_b or net_a.prefixlen <= net_b.prefixlen:
                    continue
                if not _subnet_of(net_a, net_b):
                    continue
                same_exit = (ra["interface"] == rb["interface"]
                             and ra["nexthop_ip"] == rb["nexthop_ip"])
                if same_exit:
                    continue
                # Específica coberta pela default com saída divergente é design
                # normal — mas se a específica NÃO for recriada no FG, o tráfego
                # vaza pela default (saída errada, ex.: WAN em vez do túnel).
                if net_b.prefixlen == 0:
                    problemas.append({
                        "tipo": "vaza_pela_default_se_faltar", "vr": vr,
                        "rota": ra["name"], "destino": ra["destination"],
                        "interface": ra["interface"] or ra["next_vr"],
                        "agregada": rb["destination"],
                        "saida_agregada": rb["interface"] or rb["next_vr"],
                    })
                else:
                    problemas.append({
                        "tipo": "especifica_sobrepoe_agregada", "vr": vr,
                        "rota": ra["name"], "destino": ra["destination"],
                        "interface": ra["interface"] or ra["next_vr"],
                        "agregada": rb["destination"],
                        "saida_agregada": rb["interface"] or rb["next_vr"],
                    })
    # túneis IPsec sem rota apontando para eles
    routed_ifaces = set()
    for routes in routes_by_vr.values():
        for r in routes:
            if r["interface"]:
                routed_ifaces.add(r["interface"])
    orfaos = sorted(
        (t["name"], t["tunnel_interface"]) for t in inv["network"]["ipsec_tunnels"]
        if t["tunnel_interface"] and t["tunnel_interface"] not in routed_ifaces)
    return {
        "id": "A11", "titulo": "Rotas estáticas: binding com túneis e shadow routes",
        "severidade": CRITICO, "classe_fc": "FC-9 (interface de túnel indefinida)",
        "resumo": ("%d rotas estáticas em %d VRs, 100%% estático (sem BGP/OSPF). "
                   "%d rotas específicas cobertas pela default com saída divergente "
                   "— se QUALQUER uma faltar no FG o tráfego vaza pela default "
                   "(checklist um-a-um no C01); %d sobreposições entre rotas "
                   "não-default (shadow real, revisar); %d bindings quebrados; %d "
                   "túneis sem rota. No FG cada rota de túnel vira set device "
                   "<phase1> — rename de túnel quebra a rota em silêncio."
                   % (total, len(routes_by_vr),
                      sum(1 for p in problemas if p["tipo"] == "vaza_pela_default_se_faltar"),
                      sum(1 for p in problemas if p["tipo"] == "especifica_sobrepoe_agregada"),
                      sum(1 for p in problemas if p["tipo"] in
                          ("rota_para_tunel_inexistente", "tunel_sem_ipsec_associado")),
                      len(orfaos))),
        "itens": problemas + [{"tipo": "tunel_sem_rota", "tunel": nome,
                               "interface": iface} for nome, iface in orfaos],
    }


def check_a12_zone_tunnels(inv):
    tunnel_units = set(inv["network"]["interfaces"]["tunnel_units"])
    itens = []
    for vsys in VSYS_LIST:
        for zone, ifaces in inv[vsys]["zones"].items():
            tuns = [i for i in ifaces if i.startswith("tunnel.")]
            if not tuns:
                continue
            missing = [t for t in tuns if t not in tunnel_units]
            itens.append({"vsys": vsys, "zona": zone, "tuneis": len(tuns),
                          "inexistentes": missing})
    return {
        "id": "A12", "titulo": "Zonas que contêm interfaces de túnel",
        "severidade": ALTO, "classe_fc": "FC-9",
        "resumo": ("%d zonas contêm tunnel.N. Na conversão do TESP4 o conversor "
                   "emitiu zona com membro indefinido (tunnel.1002). Cada zona↔túnel "
                   "precisa fechar com os phase1 criados no FG." % len(itens)),
        "itens": itens,
    }


def check_a13_names(inv):
    scopes = {
        "shared": inv["shared"]["objects"],
        "vsys1": inv["vsys1"]["objects"],
        "vsys2": inv["vsys2"]["objects"],
    }
    by_name = {}
    for scope, objs in scopes.items():
        for kind in ("address", "service"):
            for name, spec in objs[kind].items():
                by_name.setdefault((kind, name), []).append((scope, str(spec)))
    conflitos = []
    for (kind, name), defs in sorted(by_name.items()):
        if len(defs) > 1 and len(set(d[1] for d in defs)) > 1:
            conflitos.append({"tipo": "mesmo_nome_valor_diferente", "objeto": name,
                              "kind": kind, "escopos": [d[0] for d in defs]})
    ruins = []
    for scope, objs in scopes.items():
        for kind in ("address", "address_group", "service", "service_group"):
            for name in objs[kind]:
                if len(name) > FG_NAME_MAX:
                    ruins.append({"tipo": "nome_longo", "objeto": name, "escopo": scope,
                                  "len": len(name)})
                elif not FG_SAFE_NAME_RE.match(name):
                    ruins.append({"tipo": "caracteres_arriscados", "objeto": name,
                                  "escopo": scope})
    return {
        "id": "A13", "titulo": "Conflitos e nomes problemáticos de objetos",
        "severidade": MEDIO, "classe_fc": "FC-10 (sufixo silencioso)",
        "resumo": ("%d nomes existem em mais de um escopo com valores divergentes "
                   "(o conversor renomeia com sufixo e as referências cruzadas "
                   "quebram); %d nomes longos/com caracteres arriscados para FortiOS."
                   % (len(conflitos), len(ruins))),
        "itens": conflitos + ruins,
    }


def check_a14_ike(inv):
    gws = inv["network"]["ike_gateways"]
    v1 = sum(1 for g in gws if "ikev1" in g["version"])
    psk = sum(1 for g in gws if g["has_psk"])
    infrabase_pa = set(pair[0] for pair in INFRABASE.values())
    itens = []
    for g in gws:
        itens.append({
            "gateway": g["name"], "peer": g["peer_ip"] or "-",
            "local": g["local_interface"] or g["local_ip"],
            "versao": g["version"], "psk": "sim" if g["has_psk"] else "nao",
            "infrabase_plano": "sim" if g["name"] in infrabase_pa else "",
        })
    return {
        "id": "A14", "titulo": "Inventário IKE/IPsec e PSKs a reinserir",
        "severidade": ALTO, "classe_fc": "FC-8 (reset the pre-shared key)",
        "resumo": ("%d IKE gateways (%d ikev1/preferred-legado), %d túneis IPsec; "
                   "%d gateways com PSK — o conversor NÃO transporta PSK utilizável "
                   "(e a saída dele expõe o blob: tratar como segredo vazado). Casa "
                   "com a padronização de PSK pré-virada do Plano (aba 01): reinserir "
                   "manualmente no FG, nunca copiar do output do conversor."
                   % (len(gws), v1, len(inv["network"]["ipsec_tunnels"]), psk)),
        "itens": itens,
    }


def check_a15_mgmt(inv):
    m = inv["meta"]["mgmt"]
    itens = []
    for t in m["syslog_targets"]:
        itens.append({"tipo": "syslog", "perfil": t["profile"],
                      "destino": "%s:%s/%s" % (t["server"], t["port"], t["transport"]),
                      "formato": t["format"]})
    itens.append({"tipo": "snmp", "versao": m["snmp"]["version"],
                  "habilitado": m["snmp"]["enabled"],
                  "nota": "community v2c em uso — recomendar SNMPv3 no FG"})
    itens.append({"tipo": "dns", "servidores": [s for s in m["dns"] if s]})
    itens.append({"tipo": "ntp", "servidores": [s for s in m["ntp"] if s]})
    for vsys, profs in m["log_forwarding_profiles"].items():
        itens.append({"tipo": "log-forwarding", "vsys": vsys, "perfis": profs})
    return {
        "id": "A15", "titulo": "Dependências de gerência a recriar no FG",
        "severidade": ALTO, "classe_fc": "-",
        "resumo": ("Nada disto é convertido: syslog → config log syslogd setting "
                   "(ELK), SNMP (migrar para v3), DNS e NTP por VDOM, perfis de "
                   "log-forwarding → logtraffic + syslogd override. Sem isso o "
                   "critério 'Monitoramento sem anomalias' (aba 08) é inauditável."),
        "itens": itens,
    }


def check_a16_certificates(inv):
    edl_cert_profiles = set(e["certificate_profile"] for e in inv["edls"]
                            if e["certificate_profile"])
    itens = []
    for c in inv["certificates"]:
        relevante = any(p and p.lower() in c["name"].lower() or "edl" in c["name"].lower()
                        for p in edl_cert_profiles) or "edl" in c["name"].lower()
        itens.append({"cert": c["name"], "expira": c["not_valid_after"],
                      "ca": c["ca"], "uso_edl": "sim" if relevante else ""})
    return {
        "id": "A16", "titulo": "Certificados (validade × janela; cadeia das EDLs)",
        "severidade": MEDIO, "classe_fc": "-",
        "resumo": ("%d certificados no shared. EDLs HTTPS (%d com certificate-profile) "
                   "exigem a CA correta também no FG — external-resource falha "
                   "silenciosamente sem ela. Conferir validade contra a janela da "
                   "virada (31/08)." % (len(itens), len(edl_cert_profiles))),
        "itens": itens,
    }


def check_a17_interfaces(inv):
    ifs = inv["network"]["interfaces"]
    itens = []
    for ae, spec in sorted(ifs["aggregate"].items()):
        for sub in spec["subifs"]:
            itens.append({"tipo": "subif", "interface": sub["name"], "vlan": sub["vlan"],
                          "ips": sub["ips"], "comment": sub["comment"],
                          "lag": "%s (%s)" % (ae, "+".join(spec["members"]))})
    for lo in ifs["loopbacks"]:
        itens.append({"tipo": "loopback", "interface": lo["name"], "ips": lo["ips"]})
    for p in ifs["ha_ports"]:
        itens.append({"tipo": "porta_ha", "interface": p})
    n_sub = sum(len(s["subifs"]) for s in ifs["aggregate"].values())
    return {
        "id": "A17", "titulo": "Mapa físico/lógico a recriar no FG",
        "severidade": INFO, "classe_fc": "-",
        "resumo": ("%d LAGs, %d subinterfaces com VLAN/IP, %d loopbacks (VIPs/VPN), "
                   "%d portas HA, %d tunnel units. É o insumo direto do passo 'mover "
                   "VLANs' da virada (aba 05) e do compare C04."
                   % (len(ifs["aggregate"]), n_sub, len(ifs["loopbacks"]),
                      len(ifs["ha_ports"]), len(ifs["tunnel_units"]))),
        "itens": itens,
    }


def check_a18_capacity(inv):
    counts = {
        "security_rules": sum(len(inv[v]["security_rules"]) for v in VSYS_LIST),
        "nat_rules": sum(len(inv[v]["nat_rules"]) for v in VSYS_LIST),
        "addresses": (len(inv["shared"]["objects"]["address"])
                      + sum(len(inv[v]["objects"]["address"]) for v in VSYS_LIST)),
        "services": (len(inv["shared"]["objects"]["service"])
                     + sum(len(inv[v]["objects"]["service"]) for v in VSYS_LIST)),
        "static_routes": sum(len(r) for r in inv["network"]["static_routes"].values()),
        "ipsec_tunnels": len(inv["network"]["ipsec_tunnels"]),
    }
    itens = [{"dimensao": k, "pa_atual": v,
              "referencia_fg_vm": FG_VM_REFERENCE_LIMITS.get(
                  {"security_rules": "policies", "static_routes": "static_routes",
                   "ipsec_tunnels": "phase1_tunnels"}.get(k, ""), "-")}
             for k, v in sorted(counts.items())]
    itens.append({"dimensao": "pico_sessoes_observado",
                  "pa_atual": "%(sessions_vsys1)d (vsys1) / %(sessions_vsys2)d (vsys2)"
                              % PA_OBSERVED_PEAKS,
                  "referencia_fg_vm": FG_VM_REFERENCE_LIMITS["sessions"]})
    itens.append({"dimensao": "pico_cps_observado",
                  "pa_atual": "%(cps_vsys1)d / %(cps_vsys2)d" % PA_OBSERVED_PEAKS,
                  "referencia_fg_vm": "validar com setuprate real na VM"})
    return {
        "id": "A18", "titulo": "Fit de capacidade na FortiGate-VM",
        "severidade": MEDIO, "classe_fc": "-",
        "resumo": ("Números de referência de datasheet VM — CONFIRMAR no destino com "
                   "monitor/system/vdom-resource (variam por licença/vCPU/RAM). VM "
                   "subdimensionada só aparece na virada, com tráfego real; "
                   "acompanhar CPU/mem/sessões no dashboard."),
        "itens": itens,
    }


def check_a19_zones(inv):
    itens = []
    for vsys in VSYS_LIST:
        for zone, ifaces in sorted(inv[vsys]["zones"].items()):
            itens.append({"vsys": vsys, "zona": zone, "interfaces": len(ifaces)})
    return {
        "id": "A19", "titulo": "Inventário de zonas por vsys",
        "severidade": INFO, "classe_fc": "-",
        "resumo": ("vsys1: %d zonas; vsys2: %d zonas. Base do compare C05 (zonas por "
                   "VDOM no FG)." % (len(inv["vsys1"]["zones"]), len(inv["vsys2"]["zones"]))),
        "itens": itens,
    }


def check_a20_nat_classes(inv):
    classes = {}
    itens = []
    for vsys in VSYS_LIST:
        for r in inv[vsys]["nat_rules"]:
            if r["dnat_address"] and r["snat_type"]:
                cls = "dnat+snat"
            elif r["dnat_address"]:
                cls = "dnat"
            elif r["snat_type"] == "dynamic-ip-and-port":
                cls = "snat-dipp"
            elif r["snat_type"]:
                cls = "snat-%s" % r["snat_type"]
            else:
                cls = "sem-traducao"
            classes[cls] = classes.get(cls, 0) + 1
            itens.append({"vsys": vsys, "regra": r["name"], "classe": cls,
                          "disabled": r["disabled"]})
    mapa = {"dnat": "firewall vip + policy", "snat-dipp": "ippool + nat enable na policy",
            "snat-static-ip": "ippool one-to-one / vip", "dnat+snat": "vip + ippool na mesma policy",
            "sem-traducao": "revisar (provável no-NAT explícito)"}
    return {
        "id": "A20", "titulo": "Classificação dos NATs → construto FortiGate",
        "severidade": INFO, "classe_fc": "-",
        "resumo": ("Distribuição: %s. De-para: %s."
                   % ("; ".join("%s=%d" % kv for kv in sorted(classes.items())),
                      "; ".join("%s→%s" % kv for kv in sorted(mapa.items())))),
        "itens": itens,
    }


def check_a21_early_denies(inv):
    edl_names = set(e["name"] for e in inv["edls"]) | set(PANW_BUILTIN_EDLS)
    defined = _all_address_names(inv)
    itens = []
    for vsys in VSYS_LIST:
        for r in _enabled_rules(inv, vsys):
            if r["position"] > 60 or r["action"] not in ("deny", "drop", "reset-both",
                                                         "reset-client", "reset-server"):
                continue
            membros = r["source"] + r["destination"]
            dep_edl = sorted(edl_names.intersection(membros))
            dep_geo = sorted(set(m for m in membros
                                 if GEO_CODE_RE.match(m) and m not in defined))
            if dep_edl or dep_geo:
                item = _rule_ref(vsys, r)
                item["depende_de"] = dep_edl + dep_geo
                itens.append(item)
    return {
        "id": "A21", "titulo": "Denies no topo da rulebase que dependem de EDL/geo",
        "severidade": MEDIO, "classe_fc": "FC-4/FC-5",
        "resumo": ("%d denies nas 60 primeiras posições dependem de EDL/geo. Se o "
                   "conversor os dropar, TUDO que vem abaixo muda de semântica "
                   "(fail-open): o pacote que era barrado no topo passa a consultar "
                   "o resto da rulebase." % len(itens)),
        "itens": itens,
    }


def check_a22_vpn_reconcile(inv):
    gws = set(g["name"] for g in inv["network"]["ike_gateways"])
    faltando = sorted(pa for _fg, (pa, _st) in INFRABASE.items() if pa not in gws)
    presentes = sorted(pa for _fg, (pa, _st) in INFRABASE.items() if pa in gws)
    itens = [{"tipo": "config_snapshot", "ike_gateways": len(gws),
              "ipsec_tunnels": len(inv["network"]["ipsec_tunnels"])},
             {"tipo": "plano_de_virada", "ike_gateways": PLANO_BASELINE["ike_gateways"],
              "ipsec_configurados": PLANO_BASELINE["ipsec_configured"],
              "ipsec_sa_up": PLANO_BASELINE["ipsec_sa_up"]},
             {"tipo": "infrabase_no_snapshot", "presentes": presentes,
              "ausentes": faltando}]
    return {
        "id": "A22", "titulo": "Reconciliação VPN: snapshot × Plano de Virada",
        "severidade": INFO, "classe_fc": "-",
        "resumo": ("Snapshot: %d gateways / %d túneis. Plano: %d / %d configurados / "
                   "%d SAs UP. Diferença provável = FW02 + defasagem do snapshot — "
                   "EXPLICAR antes da virada (pa-baseline mede o valor real). "
                   "InfraBase no snapshot: %d de 7%s."
                   % (len(gws), len(inv["network"]["ipsec_tunnels"]),
                      PLANO_BASELINE["ike_gateways"], PLANO_BASELINE["ipsec_configured"],
                      PLANO_BASELINE["ipsec_sa_up"], len(presentes),
                      ("; AUSENTES DO SNAPSHOT: %s — o Plano de Virada os dá como "
                       "existentes (baseline UP), logo o snapshot está DEFASADO: "
                       "exigir export novo antes do compare final"
                       % ", ".join(faltando)) if faltando else "")),
        "itens": itens,
    }


ALL_CHECKS = [
    check_a01_edl_rules, check_a02_geo_codes, check_a03_appid,
    check_a04_any_any_service, check_a05_userid, check_a06_no_log,
    check_a07_no_profile, check_a08_disabled, check_a09_fqdn,
    check_a10_checkmk_dnat, check_a11_routes, check_a12_zone_tunnels,
    check_a13_names, check_a14_ike, check_a15_mgmt, check_a16_certificates,
    check_a17_interfaces, check_a18_capacity, check_a19_zones,
    check_a20_nat_classes, check_a21_early_denies, check_a22_vpn_reconcile,
]


def run_all(inv):
    """Roda todos os checks e devolve a lista ordenada por severidade."""
    results = [check(inv) for check in ALL_CHECKS]
    results.sort(key=lambda c: (SEV_ORDER.get(c["severidade"], 9), c["id"]))
    return results
