# -*- coding: utf-8 -*-
"""Coleta de logs para RCA — Palo Alto (XML API, job assíncrono) e FortiGate
(REST api/v2/log) — e a linha do tempo unificada da janela.

Tudo somente leitura (travas em readonly.py). Janela em horário LOCAL dos
equipamentos, formato 'YYYY/MM/DD HH:MM:SS' (PA) / epoch (interno).
"""

import json
import os
import time

PA_TIME_FMT = "%Y/%m/%d %H:%M:%S"

# Categorias de log de evento do FortiOS relevantes para RCA de virada.
FG_EVENT_SUBTYPES = ("system", "ha", "vpn", "user", "router")
FG_LOG_STORES = ("disk", "memory")   # tenta disk primeiro; 404 → memory
FG_MAX_ROWS = 2000

PA_NLOGS = 3000   # teto por consulta (PAN-OS aceita até 5000)


# ---------------------------------------------------------------------------
# Palo Alto
# ---------------------------------------------------------------------------

def _pa_query(start, end):
    return "(receive_time geq '%s') and (receive_time leq '%s')" % (start, end)


def pa_fetch_logs(fw, start, end, outdir, log_types=("config", "system")):
    """Config + system log do PA na janela. Grava XML cru + resumo JSON."""
    os.makedirs(outdir, exist_ok=True)
    all_events = []
    for log_type in log_types:
        root, raw = fw.run_log_job({
            "type": "log", "log-type": log_type,
            "query": _pa_query(start, end),
            "nlogs": str(PA_NLOGS), "dir": "backward",
        }, label="pa-log-%s" % log_type)
        if root is None:      # dry-run
            continue
        with open(os.path.join(outdir, "pa_log_%s.xml" % log_type), "wb") as fh:
            fh.write(raw)
        entries = root.findall(".//log/logs/entry")
        for e in entries:
            item = {
                "fonte": "PA:%s" % log_type,
                "quando": (e.findtext("receive_time") or "").strip(),
                "quem": (e.findtext("admin") or "").strip(),
                "o_que": ((e.findtext("cmd") or "") + " " +
                          (e.findtext("path") or e.findtext("opaque") or ""))
                         .strip()[:300],
                "resultado": (e.findtext("result") or
                              e.findtext("severity") or "").strip(),
            }
            all_events.append(item)
        print("pa-logs %s: %d entradas (%s)" % (log_type, len(entries), fw.host))
        if len(entries) >= PA_NLOGS:
            print("  AVISO: bateu no teto de %d — janela tem mais log que isso; "
                  "estreite o intervalo" % PA_NLOGS)
    with open(os.path.join(outdir, "pa_eventos.json"), "w", encoding="utf-8") as fh:
        json.dump(all_events, fh, ensure_ascii=False, indent=1)
    return all_events


# ---------------------------------------------------------------------------
# FortiGate
# ---------------------------------------------------------------------------

def fg_fetch_logs(client, outdir, vdoms=("root",), rows=FG_MAX_ROWS):
    """Logs de evento do FortiOS (system/ha/vpn/user/router) + revisões de config.

    A API devolve os mais recentes; o corte por janela é feito depois, na
    timeline (o campo de data/hora do FortiOS é local do equipamento).
    """
    os.makedirs(outdir, exist_ok=True)
    all_events = []
    for subtype in FG_EVENT_SUBTYPES:
        got = None
        for store in FG_LOG_STORES:
            resp = client.get("log/%s/event/%s" % (store, subtype),
                              params={"rows": rows},
                              label="fg-log-%s-%s" % (store, subtype))
            if resp is None:      # dry-run
                break
            if resp.get("http_status") == 404:
                continue
            results = resp.get("results") or []
            if results or store == FG_LOG_STORES[-1]:
                got = (store, results)
                break
        if not got:
            continue
        store, results = got
        with open(os.path.join(outdir, "fg_log_event_%s.json" % subtype),
                  "w", encoding="utf-8") as fh:
            json.dump(results, fh, ensure_ascii=False, indent=1)
        for r in results:
            all_events.append({
                "fonte": "FG:%s" % subtype,
                "quando": ("%s %s" % (r.get("date", ""), r.get("time", ""))).strip(),
                "quem": (r.get("user") or r.get("ui") or "").strip(),
                "o_que": (r.get("logdesc", "") + " " + r.get("msg", "")).strip()[:300],
                "resultado": r.get("status", "") or r.get("action", ""),
            })
        print("fg-logs event/%s: %d entradas (%s, %s)"
              % (subtype, len(results), client.host, store))

    # Revisões de configuração — quem salvou config e quando (ouro para RCA)
    resp = client.get("monitor/system/config-revision", label="fg-config-revision")
    if resp is not None:
        revs = resp.get("results")
        if isinstance(revs, dict):
            revs = revs.get("revisions") or []
        revs = revs or []
        with open(os.path.join(outdir, "fg_config_revisions.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(revs, fh, ensure_ascii=False, indent=1)
        for r in revs:
            all_events.append({
                "fonte": "FG:config-revision",
                "quando": str(r.get("time", r.get("created", ""))),
                "quem": r.get("admin", ""),
                "o_que": ("revisão #%s %s" % (r.get("id", "?"),
                                              r.get("comment", ""))).strip()[:300],
                "resultado": "",
            })
        print("fg-logs config-revision: %d revisões" % len(revs))

    with open(os.path.join(outdir, "fg_eventos.json"), "w", encoding="utf-8") as fh:
        json.dump(all_events, fh, ensure_ascii=False, indent=1)
    return all_events


# ---------------------------------------------------------------------------
# Timeline unificada
# ---------------------------------------------------------------------------

def _parse_when(text):
    """Aceita 'YYYY/MM/DD HH:MM:SS', 'YYYY-MM-DD HH:MM:SS' e epoch. 0 se ilegível."""
    text = str(text).strip()
    if text.isdigit():
        return int(text)
    for fmt in (PA_TIME_FMT, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return int(time.mktime(time.strptime(text, fmt)))
        except ValueError:
            continue
    return 0


def build_timeline(event_lists, start=None, end=None):
    """Une listas de eventos, corta pela janela e ordena no tempo."""
    t_start = _parse_when(start) if start else 0
    t_end = _parse_when(end) if end else 2 ** 62
    merged = []
    for events in event_lists:
        for e in events:
            ts = _parse_when(e.get("quando", ""))
            if ts and (ts < t_start or ts > t_end):
                continue
            e = dict(e)
            e["_ts"] = ts
            merged.append(e)
    merged.sort(key=lambda e: (e["_ts"], e["fonte"]))
    return merged


def render_timeline_md(timeline, start, end, notas=None):
    out = ["# RCA — linha do tempo da janela", ""]
    out.append("- Janela: %s → %s" % (start or "-", end or "-"))
    out.append("- Eventos na janela: %d (PA config/system + FG event logs + "
               "revisões de config FG)" % len(timeline))
    out.append("- Horários no fuso LOCAL de cada equipamento — confirme "
               "timezone/NTP antes de comparar ao segundo.")
    out.append("")
    for nota in (notas or []):
        out.append("> %s" % nota)
    if notas:
        out.append("")
    out.append("| Quando | Fonte | Quem | O quê | Resultado |")
    out.append("|---|---|---|---|---|")
    for e in timeline:
        out.append("| %s | %s | %s | %s | %s |" % (
            e.get("quando", "-"), e.get("fonte", "-"),
            e.get("quem", "-") or "-",
            str(e.get("o_que", "-")).replace("|", "\\|"),
            e.get("resultado", "-") or "-"))
    return "\n".join(out)
