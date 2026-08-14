# -*- coding: utf-8 -*-
"""Fase C — paridade PA↔FG (checks C01–C12).

Entrada: inventario.json (Fase A) + artefatos do fg-snapshot (Fase B2). Saída:
gaps.md + gaps.json (+ push opcional mig_audit). Nunca fala com equipamento.

Topologia real do TECE1: o que no PA era vsys virou **dois clusters FortiGate
separados** — vsys1 (Infrabase) → cluster INFRABASE, vsys2 (External-Clients)
→ cluster CLIENTE, cada um single-VDOM (root). O compare recebe um mapa
"lado → (diretório do fg-snapshot, vdom)" e também aceita o modo legado
(um único FG multi-VDOM root+vsys2).
"""

import ipaddress
import json
import os
import time

from .vpnmap import INFRABASE, CBL3SH_PATTERN

# VR do PA → lado (vsys) correspondente
VR_SIDE_MAP = {"Externo_Infrabase": "vsys1", "External_Clients": "vsys2"}
SIDES = ("vsys1", "vsys2")
SIDE_LABEL = {"vsys1": "infrabase", "vsys2": "cliente"}

MAX_LIST = 40


# ---------------------------------------------------------------------------
# Mapa de lados e leitura dos artefatos FG
# ---------------------------------------------------------------------------

def make_fg_map(fg_dir=None, vsys1=None, vsys2=None):
    """Monta o mapa lado→(dir, vdom).

    Dois clusters (topologia real): vsys1=(dirA, 'root'), vsys2=(dirB, 'root').
    Legado (1 FG multi-VDOM): fg_dir → vsys1=(dir,'root'), vsys2=(dir,'vsys2').
    """
    if vsys1 and vsys2:
        return {"vsys1": vsys1, "vsys2": vsys2}
    if fg_dir:
        return {"vsys1": (fg_dir, "root"), "vsys2": (fg_dir, "vsys2")}
    import sys
    sys.exit("compare: informe --fg vsys1=DIR[:vdom] --fg vsys2=DIR[:vdom] "
             "ou --fg-dir DIR (legado multi-VDOM)")


def _load_file(path):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return data.get("results") or []
    return data


def _fg_load(fg_map, side, name):
    """Artefato cmdb/monitor do lado (vsys1|vsys2)."""
    fg_dir, vdom = fg_map[side]
    data = _load_file(os.path.join(fg_dir, vdom, name + ".json"))
    if data:
        return data
    # tolera slug antigo com ponto (log.syslogd vs log_syslogd)
    alt = name.replace(".", "_")
    if alt != name:
        return _load_file(os.path.join(fg_dir, vdom, alt + ".json"))
    return []


def _fg_load_both(fg_map, name):
    """Concatena o artefato dos dois lados, marcando a origem em _side."""
    out = []
    for side in SIDES:
        for item in _fg_load(fg_map, side, name):
            if isinstance(item, dict):
                item = dict(item)
                item["_side"] = SIDE_LABEL[side]
            out.append(item)
    return out


def _fg_globals(fg_map, name):
    """Artefato _global de cada diretório distinto (2 clusters = 2 arquivos)."""
    seen = set()
    out = []
    for side in SIDES:
        fg_dir = fg_map[side][0]
        if fg_dir in seen:
            continue
        seen.add(fg_dir)
        out.extend(_load_file(os.path.join(fg_dir, "_global", name + ".json")))
    return out


def _side_tag(fg_map, side):
    fg_dir, vdom = fg_map[side]
    return "%s(%s)" % (SIDE_LABEL[side], vdom)


# ---------------------------------------------------------------------------
# Normalizações
# ---------------------------------------------------------------------------

def _net(value):
    """'10.1.1.0/24' | '10.1.1.0 255.255.255.0' | ['10.1.1.0','255...'] → rede."""
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    value = str(value).strip()
    if " " in value:
        addr, mask = value.split()[:2]
        value = "%s/%s" % (addr, mask)
    try:
        return str(ipaddress.ip_network(value.replace(" ", "/"), strict=False))
    except ValueError:
        return value


def _norm_name(name):
    return (name.lower().replace("vpn-", "").replace("vpn_", "")
            .replace("_phase1", "").replace("-p1", "").replace("_p1", "")
            .replace("-", "").replace("_", ""))


def _result(cid, categoria, severidade, resumo, pa_count, fg_count, matched,
            missing_fg, extra_fg=None, itens=None):
    return {
        "id": cid, "categoria": categoria, "severidade": severidade,
        "resumo": resumo, "pa_count": pa_count, "fg_count": fg_count,
        "matched": matched, "missing_fg": missing_fg[:MAX_LIST],
        "missing_fg_total": len(missing_fg),
        "extra_fg": (extra_fg or [])[:MAX_LIST],
        "extra_fg_total": len(extra_fg or []),
        "itens": (itens or [])[:MAX_LIST],
    }


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def c01_routes(inv, fg_map):
    missing, matched, extra_all = [], 0, []
    pa_total = fg_total = 0
    for vr, side in sorted(VR_SIDE_MAP.items()):
        rotulo = _side_tag(fg_map, side)
        pa_routes = inv["network"]["static_routes"].get(vr, [])
        fg_routes = _fg_load(fg_map, side, "cmdb_router_static")
        fg_by_dst = {}
        for r in fg_routes:
            fg_by_dst.setdefault(_net(r.get("dst", "")), []).append(r)
        pa_total += len(pa_routes)
        fg_total += len(fg_routes)
        seen = set()
        for r in pa_routes:
            dst = _net(r["destination"])
            if dst in fg_by_dst:
                matched += 1
                seen.add(dst)
            else:
                missing.append("%s %s (%s → %s)" % (
                    rotulo, dst, r["name"], r["interface"] or r["nexthop_ip"]))
        extra_all.extend("%s %s" % (rotulo, d) for d in fg_by_dst if d not in seen)
    return _result(
        "C01", "routes", "CRITICO",
        "Cada rota estática do PA precisa existir no cluster FG do seu lado "
        "(Externo_Infrabase→INFRABASE, External_Clients→CLIENTE). A falta de "
        "UMA específica vaza tráfego pela default (A11).",
        pa_total, fg_total, matched, missing, extra_all)


def c02_vips_checkmk(inv, fg_map):
    from .checks import check_a10_checkmk_dnat
    alvo = check_a10_checkmk_dnat(inv)["itens"]
    fg_vips = _fg_load_both(fg_map, "cmdb_firewall_vip")
    fg_pairs = set()
    for v in fg_vips:
        ext = _net(v.get("extip", ""))
        mapped = ""
        mr = v.get("mappedip")
        if isinstance(mr, list) and mr:
            mapped = _net(mr[0].get("range", "")) if isinstance(mr[0], dict) \
                else _net(mr[0])
        fg_pairs.add((ext, mapped))
    missing, matched = [], 0
    for item in alvo:
        ext = _net(item["extip_resolvido"] if item["extip_resolvido"] != "-"
                   else item["extip"])
        mapped = _net(item["mappedip"])
        if (ext, mapped) in fg_pairs:
            matched += 1
        else:
            missing.append("%s → %s (%s)%s" % (
                ext, mapped, item["regra"],
                " ⚠ " + item["atencao"] if item["atencao"] else ""))
    return _result(
        "C02", "vips", "CRITICO",
        "DNATs do Check_MK que precisam existir como firewall vip em um dos "
        "clusters FG — cada faltante cega o monitoramento de um equipamento.",
        len(alvo), len(fg_vips), matched, missing)


def c03_vpns(inv, fg_map):
    pa_gws = dict((g["name"], g) for g in inv["network"]["ike_gateways"])
    fg_p1 = _fg_load_both(fg_map, "cmdb_vpn_ipsec_phase1-interface")
    fg_names = set(p.get("name", "") for p in fg_p1)
    fg_norm = dict((_norm_name(n), n) for n in fg_names)

    itens, missing, matched = [], [], 0
    for fg_name, pair in sorted(INFRABASE.items()):
        pa_name, baseline = pair
        no_pa = pa_name in pa_gws
        no_fg = fg_name in fg_names
        if no_fg:
            matched += 1
        else:
            missing.append("%s (PA: %s, baseline %s)" % (fg_name, pa_name, baseline))
        itens.append({"vpn_fg": fg_name, "vpn_pa": pa_name,
                      "baseline_plano": baseline,
                      "no_snapshot_pa": "sim" if no_pa else "NAO",
                      "no_fg": "sim" if no_fg else "NAO"})

    fuzzy = 0
    for pa_name in pa_gws:
        if pa_name in (p[0] for p in INFRABASE.values()):
            continue
        if _norm_name(pa_name) in fg_norm:
            fuzzy += 1
    cbl_pa = sum(1 for n in pa_gws if CBL3SH_PATTERN in n)
    cbl_fg = sum(1 for n in fg_names if CBL3SH_PATTERN in n)
    itens.append({"vpn_fg": "(clientes %s)" % CBL3SH_PATTERN, "vpn_pa": "-",
                  "baseline_plano": "-", "no_snapshot_pa": str(cbl_pa),
                  "no_fg": str(cbl_fg)})
    return _result(
        "C03", "vpns", "CRITICO",
        "As 7 VPNs InfraBase pelo de-para do Plano de Virada + contagem CBL3SH "
        "(varre os dois clusters). %d gateways extras do PA casaram por nome "
        "aproximado; rota de túnel no FG usa set device <phase1> — nome "
        "divergente quebra a rota." % fuzzy,
        len(pa_gws), len(fg_names), matched, missing, itens=itens)


def c04_interfaces(inv, fg_map):
    fg_ifs = _fg_globals(fg_map, "cmdb_system_interface")
    fg_vlans = {}
    fg_ips = set()
    for i in fg_ifs:
        ip = i.get("ip", "")
        if ip and ip not in ("0.0.0.0 0.0.0.0",):
            fg_ips.add(_net(ip))
        vlanid = i.get("vlanid")
        if vlanid:
            fg_vlans.setdefault(str(vlanid), []).append(i)
    missing, matched = [], 0
    pa_total = 0
    for ae, spec in sorted(inv["network"]["interfaces"]["aggregate"].items()):
        for sub in spec["subifs"]:
            pa_total += 1
            ip_ok = any(_net(ip) in fg_ips for ip in sub["ips"])
            vlan_ok = sub["vlan"] in fg_vlans
            if ip_ok and vlan_ok:
                matched += 1
            else:
                missing.append("%s vlan=%s %s (%s)%s" % (
                    sub["name"], sub["vlan"], ",".join(sub["ips"]),
                    sub["comment"] or ae,
                    "" if vlan_ok else " [sem VLAN no FG]"))
    for lo in inv["network"]["interfaces"]["loopbacks"]:
        pa_total += 1
        if any(_net(ip) in fg_ips for ip in lo["ips"]):
            matched += 1
        else:
            missing.append("%s %s [loopback/VIP]" % (lo["name"], ",".join(lo["ips"])))
    return _result(
        "C04", "interfaces", "ALTO",
        "Subinterfaces (VLAN+IP) e loopbacks do PA presentes em ALGUM dos "
        "clusters FG (interfaces globais dos dois somadas). VLAN com IP "
        "ausente = serviço fora no momento de mover a VLAN (aba 05).",
        pa_total, len(fg_ifs), matched, missing)


def c05_zones(inv, fg_map):
    missing, matched = [], 0
    pa_total = fg_total = 0
    for side in SIDES:
        rotulo = _side_tag(fg_map, side)
        pa_zones = set(inv[side]["zones"].keys())
        fg_zones = set(z.get("name", "")
                       for z in _fg_load(fg_map, side, "cmdb_system_zone"))
        pa_total += len(pa_zones)
        fg_total += len(fg_zones)
        for z in sorted(pa_zones):
            if z in fg_zones:
                matched += 1
            else:
                missing.append("%s: %s" % (rotulo, z))
    return _result(
        "C05", "zones", "ALTO",
        "Zonas por lado (vsys1→cluster INFRABASE, vsys2→cluster CLIENTE), por "
        "nome. Zona ausente = policies órfãs na importação.",
        pa_total, fg_total, matched, missing)


def c06_policies(inv, fg_map):
    itens, missing = [], []
    pa_total = fg_total = matched = 0
    for side in SIDES:
        rotulo = _side_tag(fg_map, side)
        pa_rules = inv[side]["security_rules"]
        fg_pols = _fg_load(fg_map, side, "cmdb_firewall_policy")
        pa_en = sum(1 for r in pa_rules if not r["disabled"])
        fg_en = sum(1 for p in fg_pols if p.get("status", "enable") == "enable")
        pa_total += len(pa_rules)
        fg_total += len(fg_pols)
        matched += min(pa_en, fg_en)
        itens.append({"lado": rotulo, "pa_regras": len(pa_rules),
                      "pa_ativas": pa_en, "fg_policies": len(fg_pols),
                      "fg_ativas": fg_en, "delta": pa_en - fg_en})
        if fg_en < pa_en:
            missing.append("%s: faltam ~%d policies ativas" % (rotulo, pa_en - fg_en))
    return _result(
        "C06", "policies", "MEDIO",
        "Sanidade grossa de contagem por lado (± descartes intencionais "
        "declarados na revisão).", pa_total, fg_total, matched, missing,
        itens=itens)


def c07_logtraffic(inv, fg_map):
    total = com_log = 0
    syslog_ok = False
    itens = []
    for side in SIDES:
        rotulo = _side_tag(fg_map, side)
        for p in _fg_load(fg_map, side, "cmdb_firewall_policy"):
            total += 1
            if p.get("logtraffic") in ("all", "utm"):
                com_log += 1
        for s in _fg_load(fg_map, side, "cmdb_log.syslogd_setting"):
            server = s.get("server", "")
            itens.append({"lado": rotulo, "syslog_server": server,
                          "port": s.get("port", ""), "status": s.get("status", "")})
            if server == "172.18.100.2":
                syslog_ok = True
    missing = []
    if total and com_log < total:
        missing.append("%d de %d policies sem logtraffic all/utm" % (total - com_log, total))
    if not syslog_ok:
        missing.append("syslogd não aponta para o ELK 172.18.100.2:9001")
    return _result(
        "C07", "logtraffic", "ALTO",
        "Pega o FC-1 (conversor desliga log em ~100%% das policies) antes da "
        "virada: %d/%d policies logando; syslog→ELK %s."
        % (com_log, total, "OK" if syslog_ok else "AUSENTE"),
        total, total, com_log, missing, itens=itens)


def c08_utm(inv, fg_map):
    UTM_KEYS = ("av-profile", "ips-sensor", "webfilter-profile",
                "application-list", "ssl-ssh-profile", "profile-group",
                "dnsfilter-profile")
    total = com_utm = 0
    for side in SIDES:
        for p in _fg_load(fg_map, side, "cmdb_firewall_policy"):
            total += 1
            if p.get("utm-status") == "enable" or any(p.get(k) for k in UTM_KEYS):
                com_utm += 1
    missing = []
    if total and com_utm == 0:
        missing.append("nenhuma policy com UTM — FC-2 não remediado (matriz SEGINFO)")
    return _result(
        "C08", "utm", "MEDIO",
        "%d/%d policies FG com algum profile UTM. Zero = downgrade de postura "
        "no dia 1 (o conversor não gera UTM)." % (com_utm, total),
        total, total, com_utm, missing)


def c09_objects(inv, fg_map):
    itens, missing = [], []
    pa_total = fg_total = matched = 0
    for side in SIDES:
        rotulo = _side_tag(fg_map, side)
        pa_addr = dict(inv[side]["objects"]["address"])
        pa_addr.update(inv["shared"]["objects"]["address"])   # shared replica por lado
        fg_addr = set(a.get("name", "")
                      for a in _fg_load(fg_map, side, "cmdb_firewall_address"))
        pa_total += len(pa_addr)
        fg_total += len(fg_addr)
        falta = []
        for name in pa_addr:
            if name in fg_addr or ("%s_1" % name) in fg_addr or \
                    ("%s-1" % name) in fg_addr:
                matched += 1
            else:
                falta.append(name)
        itens.append({"lado": rotulo, "pa_address": len(pa_addr),
                      "fg_address": len(fg_addr), "faltando": len(falta)})
        missing.extend("%s: %s" % (rotulo, n) for n in sorted(falta)[:20])
    return _result(
        "C09", "objects", "MEDIO",
        "Address objects por nome (tolerando sufixo _1/-1 do conversor — FC-10). "
        "Serviços ficam na conferência por amostragem do revisor.",
        pa_total, fg_total, matched, missing, itens=itens)


def c10_edls(inv, fg_map):
    pa_edls = [e["name"] for e in inv["edls"]]
    fg_res = [r.get("name", "")
              for r in _fg_load_both(fg_map, "cmdb_system_external-resource")]
    fg_set = set(fg_res)
    missing, matched = [], 0
    for name in pa_edls:
        if name in fg_set or _norm_name(name) in set(_norm_name(f) for f in fg_set):
            matched += 1
        else:
            missing.append(name)
    return _result(
        "C10", "edl", "ALTO",
        "EDLs do PA vs system/external-resource nos clusters FG (FC-4). As "
        "regras de bloqueio do topo dependem disto (A01/A21); conferir também "
        "o attach nas policies equivalentes e a CA (%s)."
        % ", ".join(sorted(set(e["certificate_profile"]
                               for e in inv["edls"] if e["certificate_profile"]))),
        len(pa_edls), len(fg_res), matched, missing)


def c11_snat(inv, fg_map):
    pa_pools = set()
    for side in SIDES:
        for r in inv[side]["nat_rules"]:
            if r["snat_type"]:
                for t in r["snat_translated"]:
                    if t and not t.startswith("interface:"):
                        pa_pools.add(t)
    fg_pools, fg_nat_policies = [], 0
    for side in SIDES:
        for p in _fg_load(fg_map, side, "cmdb_firewall_ippool"):
            fg_pools.append("%s|%s-%s" % (p.get("name", ""),
                                          p.get("startip", ""), p.get("endip", "")))
        for p in _fg_load(fg_map, side, "cmdb_firewall_policy"):
            if p.get("nat") == "enable":
                fg_nat_policies += 1
    fg_blob = " ".join(fg_pools)
    missing, matched = [], 0
    for pool in sorted(pa_pools):
        base = pool.split("/")[0]
        if base and base in fg_blob:
            matched += 1
        else:
            missing.append(pool)
    return _result(
        "C11", "snat", "ALTO",
        "Endereços de SNAT do PA cobertos por ippool nos clusters FG; %d "
        "policies FG com nat enable. Saída de cliente sem SNAT = IP errado "
        "na internet." % fg_nat_policies,
        len(pa_pools), len(fg_pools), matched, missing)


def c12_mgmt(inv, fg_map):
    pa = inv["meta"]["mgmt"]
    alvos = {
        "syslog": "%s:%s" % (pa["syslog_targets"][0]["server"],
                             pa["syslog_targets"][0]["port"])
                  if pa["syslog_targets"] else "-",
        "dns": [s for s in pa["dns"] if s],
        "ntp": [s for s in pa["ntp"] if s],
    }
    itens, missing = [], []
    achou = {"syslog": False, "dns": False, "snmp": False, "ntp": False}
    for side in SIDES:
        rotulo = _side_tag(fg_map, side)
        for s in _fg_load(fg_map, side, "cmdb_log.syslogd_setting"):
            if s.get("server"):
                achou["syslog"] = True
                itens.append({"lado": rotulo, "item": "syslog",
                              "valor": "%s:%s" % (s.get("server"), s.get("port"))})
        for s in _fg_load(fg_map, side, "cmdb_system_dns"):
            if s.get("primary") not in (None, "", "0.0.0.0"):
                achou["dns"] = True
                itens.append({"lado": rotulo, "item": "dns", "valor": s.get("primary")})
        for s in _fg_load(fg_map, side, "cmdb_system_snmp_community"):
            achou["snmp"] = True
            itens.append({"lado": rotulo, "item": "snmp",
                          "valor": "community id %s" % s.get("id", "?")})
        for s in _fg_load(fg_map, side, "cmdb_system_ntp"):
            if s.get("ntpsync") == "enable" or s.get("ntpserver"):
                achou["ntp"] = True
                itens.append({"lado": rotulo, "item": "ntp", "valor": "configurado"})
    for chave, ok in sorted(achou.items()):
        if not ok:
            missing.append("%s não configurado em nenhum cluster FG (PA usa: %s)"
                           % (chave, alvos.get(chave, "?")))
    return _result(
        "C12", "mgmt", "MEDIO",
        "Gerência dos clusters FG: syslog→ELK, DNS, NTP, SNMP. Sem isso o "
        "critério 'Monitoramento sem anomalias' (aba 08) é inauditável.",
        4, sum(1 for v in achou.values() if v),
        sum(1 for v in achou.values() if v), missing, itens=itens)


ALL_COMPARES = [c01_routes, c02_vips_checkmk, c03_vpns, c04_interfaces,
                c05_zones, c06_policies, c07_logtraffic, c08_utm, c09_objects,
                c10_edls, c11_snat, c12_mgmt]


# ---------------------------------------------------------------------------
# Orquestração
# ---------------------------------------------------------------------------

def run_checks(inv, fg_map):
    return [check(inv, fg_map) for check in ALL_COMPARES]


def _gaps_md(results, inv, fg_map):
    out = ["# Paridade PA ↔ FG — gaps", ""]
    out.append("- Gerado em: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    out.append("- Inventário PA: %s (%s)"
               % (inv["meta"]["mgmt"].get("hostname", "?"),
                  inv["meta"]["file"].get("sha256", "?")[:12]))
    for side in SIDES:
        fg_dir, vdom = fg_map[side]
        out.append("- Lado %s (%s): `%s` vdom `%s`"
                   % (side, SIDE_LABEL[side], os.path.abspath(fg_dir), vdom))
    out.append("")
    out.append("| ID | Categoria | Sev | PA | FG | OK | Faltando | Sobrando |")
    out.append("|---|---|---|---|---|---|---|---|")
    for r in results:
        out.append("| %s | %s | %s | %s | %s | %s | %s | %s |"
                   % (r["id"], r["categoria"], r["severidade"], r["pa_count"],
                      r["fg_count"], r["matched"], r["missing_fg_total"],
                      r["extra_fg_total"]))
    out.append("")
    for r in results:
        out.append("## %s — %s (%s)" % (r["id"], r["categoria"], r["severidade"]))
        out.append("")
        out.append(r["resumo"])
        out.append("")
        if r["missing_fg"]:
            out.append("Faltando no FG (%d%s):"
                       % (r["missing_fg_total"],
                          ", primeiros %d" % len(r["missing_fg"])
                          if r["missing_fg_total"] > len(r["missing_fg"]) else ""))
            for m in r["missing_fg"]:
                out.append("- %s" % m)
            out.append("")
        if r["itens"]:
            cols = list(r["itens"][0].keys())
            out.append("| " + " | ".join(cols) + " |")
            out.append("|" + "|".join("---" for _ in cols) + "|")
            for item in r["itens"]:
                out.append("| " + " | ".join(str(item.get(c, "-"))
                                             for c in cols) + " |")
            out.append("")
    return "\n".join(out)


def run(inventory_path, fg_map, out_base):
    with open(inventory_path, "r", encoding="utf-8") as fh:
        inv = json.load(fh)
    import sys
    for side in SIDES:
        fg_dir, _vdom = fg_map[side]
        if not os.path.isdir(fg_dir):
            sys.exit("compare: diretório FG do lado %s não existe: %s"
                     % (side, fg_dir))

    results = run_checks(inv, fg_map)
    stamp = time.strftime("%Y-%m-%d_%H%M")
    outdir = os.path.join(out_base, stamp)
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "gaps.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_gaps_md(results, inv, fg_map))
    with open(os.path.join(outdir, "gaps.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=1, sort_keys=True)

    for r in results:
        print("%s %-10s sev=%-7s PA=%-5s FG=%-5s ok=%-5s falta=%s"
              % (r["id"], r["categoria"], r["severidade"], r["pa_count"],
                 r["fg_count"], r["matched"], r["missing_fg_total"]))
    print("  gaps: %s" % md_path)
    return results


def push_gaps(results, writer, site="TECE1"):
    from .influxpush import line
    now = int(time.time())
    lines = []
    for r in results:
        lines.append(line(
            "mig_audit",
            {"site": site, "category": r["categoria"]},
            {"pa_count": int(r["pa_count"]), "fg_count": int(r["fg_count"]),
             "matched": int(r["matched"]),
             "missing_fg": int(r["missing_fg_total"]),
             "extra_fg": int(r["extra_fg_total"]),
             "sev_max": r["severidade"]},
            ts=now))
    writer.write_lines(lines)
