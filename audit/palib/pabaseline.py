# -*- coding: utf-8 -*-
"""Fase B1 — baseline operacional do Palo Alto (evidências "antes", aba 09).

Todos os comandos são <show> literais (trava em readonly.py). Cada resposta é
gravada crua (.xml) + resumida (baseline.json). Nada aqui altera estado.
"""

import json
import os
import time

# (nome, comando <show>) — espelha a aba 09 do Plano de Virada.
BASELINE_CMDS = [
    ("ike_sa", "<show><vpn><ike-sa></ike-sa></vpn></show>"),
    ("ipsec_sa", "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>"),
    ("vpn_flow", "<show><vpn><flow></flow></vpn></show>"),
    ("sessions", "<show><session><info></info></session></show>"),
    ("routes", "<show><routing><route></route></routing></show>"),
    ("arp", "<show><arp><entry name='all'/></arp></show>"),
    ("ha", "<show><high-availability><state></state></high-availability></show>"),
    ("interfaces", "<show><interface>all</interface></show>"),
]

# Estado do PBF (aba 09) — leitura de config, também na lista branca da trava.
PBF_XPATH = ("/config/devices/entry[@name='localhost.localdomain']"
             "/vsys/entry[@name='%s']/rulebase/pbf")


def _count(root, path):
    if root is None:
        return 0
    return len(root.findall(path))


def summarize(results):
    """Extrai o resumo numérico das respostas cruas (parse defensivo)."""
    summary = {}
    root = results.get("ike_sa")
    summary["ike_sa"] = _count(root, ".//entry")
    root = results.get("ipsec_sa")
    total = root.findtext("./result/total-tun") if root is not None else None
    summary["ipsec_sa_up"] = int(total) if (total or "").strip().isdigit() \
        else _count(root, ".//entries/entry")
    root = results.get("vpn_flow")
    summary["vpn_flow_tunnels"] = _count(root, ".//IPSec/entry")
    root = results.get("sessions")
    num = root.findtext("./result/num-active") if root is not None else None
    summary["sessions_active"] = int(num) if (num or "").strip().isdigit() else 0
    root = results.get("routes")
    summary["routes"] = _count(root, ".//entry")
    root = results.get("arp")
    total = root.findtext("./result/total") if root is not None else None
    summary["arp"] = int(total) if (total or "").strip().isdigit() \
        else _count(root, ".//entries/entry")
    root = results.get("ha")
    summary["ha_state"] = (root.findtext("./result/group/local-info/state")
                           if root is not None else "") or ""
    root = results.get("interfaces")
    summary["interfaces_ifnet"] = _count(root, ".//ifnet/entry")
    return summary


def collect_baseline(fw, out_base, hostname="", vsys_list=("vsys1", "vsys2")):
    """Roda os <show> + leitura do PBF e grava tudo. Devolve o diretório criado."""
    label = hostname or fw.host
    stamp = time.strftime("%Y-%m-%d_%H%M")
    outdir = os.path.join(out_base, stamp, "pa-baseline-%s" % label)
    os.makedirs(outdir, exist_ok=True)

    results = {}
    for name, cmd in BASELINE_CMDS:
        root, raw = fw.get({"type": "op", "cmd": cmd}, label=name)
        results[name] = root
        if raw:
            with open(os.path.join(outdir, "%s.xml" % name), "wb") as fh:
                fh.write(raw)

    for vsys in vsys_list:
        root, raw = fw.get({"type": "config", "action": "get",
                            "xpath": PBF_XPATH % vsys}, label="pbf-%s" % vsys)
        if raw:
            with open(os.path.join(outdir, "pbf_%s.xml" % vsys), "wb") as fh:
                fh.write(raw)

    if fw.dry_run:
        print("pa-baseline: dry-run — nada gravado")
        return outdir

    summary = summarize(results)
    summary["collected_at"] = int(time.time())
    summary["host"] = fw.host
    summary["hostname"] = label
    with open(os.path.join(outdir, "baseline.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1, sort_keys=True)

    print("pa-baseline %s: ike_sa=%d ipsec_sa_up=%d vpn_flow=%d sessions=%d "
          "routes=%d arp=%d ha=%s"
          % (label, summary["ike_sa"], summary["ipsec_sa_up"],
             summary["vpn_flow_tunnels"], summary["sessions_active"],
             summary["routes"], summary["arp"], summary["ha_state"] or "?"))
    print("  evidências: %s" % outdir)
    return outdir


def push_baseline(outdir, writer, hostname, site="TECE1"):
    """Publica o resumo como mig_pa_baseline (fonte de verdade p/ o painel 6)."""
    from .influxpush import line
    path = os.path.join(outdir, "baseline.json")
    with open(path, "r", encoding="utf-8") as fh:
        summary = json.load(fh)
    writer.write_lines([line(
        "mig_pa_baseline",
        {"hostname": hostname, "site": site},
        {"ike_sa": summary["ike_sa"],
         "ipsec_sa_up": summary["ipsec_sa_up"],
         "vpn_flow_tunnels": summary["vpn_flow_tunnels"],
         "sessions": summary["sessions_active"],
         "routes": summary["routes"],
         "arp": summary["arp"],
         "ha_state": summary["ha_state"] or "unknown"},
        ts=summary["collected_at"])])
