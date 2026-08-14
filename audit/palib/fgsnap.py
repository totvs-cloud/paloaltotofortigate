# -*- coding: utf-8 -*-
"""Fase B2 — dump read-only da configuração e estado do FortiGate.

Um arquivo JSON por endpoint em fg/<vdom>/<slug>.json (+ fg/_global/). O
compare (Fase C) lê daqui — nunca do equipamento.
"""

import json
import os
import time

# cmdb por VDOM (paginado)
CMDB_VDOM = [
    "firewall/policy",
    "firewall/address",
    "firewall/addrgrp",
    "firewall/service/custom",
    "firewall/service/group",
    "firewall/vip",
    "firewall/ippool",
    "system/zone",
    "router/static",
    "vpn.ipsec/phase1-interface",
    "vpn.ipsec/phase2-interface",
    "log.syslogd/setting",
    "system/external-resource",
    "system/snmp/sysinfo",
    "system/snmp/community",
    "system/dns",
    "system/ntp",
]

# cmdb de escopo global (uma vez)
CMDB_GLOBAL = [
    "system/interface",
    "system/ha",
    "system/global",
]

# monitor por VDOM
MONITOR_VDOM = [
    "vpn/ipsec",
    "router/ipv4",
    "network/arp",
    "system/vdom-resource",
    "firewall/policy",          # hit counts — uma vez por snapshot, não em loop
]

# monitor de escopo global
MONITOR_GLOBAL = [
    "system/status",
    "system/resource/usage",
    "system/interface",
    "system/ha-statistics",
    "system/ha-checksums",
    "license/status",
]


def _slug(path):
    return path.replace("/", "_").replace(".", "_")


def _write(outdir, name, payload):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "%s.json" % name), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1, sort_keys=True)


def snapshot(client, vdoms, out_base, hostname=""):
    """Coleta tudo. Devolve o diretório fg/ criado (ou None em dry-run)."""
    label = hostname or client.host
    stamp = time.strftime("%Y-%m-%d_%H%M")
    fg_dir = os.path.join(out_base, stamp, "fg-%s" % label)

    status = client.get("monitor/system/status", label="status")
    if client.dry_run:
        for path in CMDB_GLOBAL:
            client.get("cmdb/" + path, params={"scope": "global"}, label="cmdb")
        for vdom in vdoms:
            for path in CMDB_VDOM:
                client.get("cmdb/" + path, vdom=vdom, label="cmdb")
            for path in MONITOR_VDOM:
                client.get("monitor/" + path, vdom=vdom, label="monitor")
        for path in MONITOR_GLOBAL:
            client.get("monitor/" + path, label="monitor")
        print("fg-snapshot: dry-run — nada gravado")
        return None

    meta = {
        "host": client.host,
        "hostname": label,
        "collected_at": int(time.time()),
        "serial": (status or {}).get("serial", ""),
        "version": (status or {}).get("version", ""),
        "build": (status or {}).get("build", ""),
        "vdoms": list(vdoms),
    }
    gdir = os.path.join(fg_dir, "_global")
    _write(gdir, "meta", meta)
    _write(gdir, _slug("monitor/system/status"), status or {})

    for path in CMDB_GLOBAL:
        resp = client.get("cmdb/" + path, params={"scope": "global"},
                          label="cmdb/%s" % path)
        _write(gdir, "cmdb_" + _slug(path), resp or {})
    for path in MONITOR_GLOBAL:
        if path == "system/status":
            continue
        params = {"scope": "global"} if path == "system/resource/usage" else None
        if path == "system/interface":
            params = {"include_vlan": "true"}
        resp = client.get("monitor/" + path, params=params, label="monitor/%s" % path)
        _write(gdir, "monitor_" + _slug(path), resp or {})

    n_req = 0
    for vdom in vdoms:
        vdir = os.path.join(fg_dir, vdom)
        for path in CMDB_VDOM:
            results = client.cmdb_all(path, vdom)
            _write(vdir, "cmdb_" + _slug(path), {"results": results})
            n_req += 1
        for path in MONITOR_VDOM:
            resp = client.get("monitor/" + path, vdom=vdom,
                              label="monitor/%s" % path)
            _write(vdir, "monitor_" + _slug(path), resp or {})
            n_req += 1

    print("fg-snapshot %s: %d vdoms, versão %s build %s"
          % (label, len(vdoms), meta["version"] or "?", meta["build"] or "?"))
    print("  artefatos: %s" % fg_dir)
    return fg_dir
