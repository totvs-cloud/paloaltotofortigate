# -*- coding: utf-8 -*-
"""Coleta de logs para RCA — Palo Alto (XML API, job assíncrono) e FortiGate
(REST api/v2/log, sessão assíncrona) — e a linha do tempo unificada da janela.

Tudo somente leitura (travas em readonly.py). Janela em horário LOCAL dos
equipamentos, formato 'YYYY/MM/DD HH:MM:SS' (PA).
"""

import json
import os
import time

PA_TIME_FMT = "%Y/%m/%d %H:%M:%S"

# Categorias de log de evento do FortiOS relevantes para RCA de virada.
FG_EVENT_SUBTYPES = ("system", "ha", "vpn", "user", "router")
FG_LOG_STORES = ("disk", "memory")   # tenta disk primeiro; 404/vazio → memory
FG_MAX_ROWS = 2000
FG_SESSION_POLLS = 30                # a API de log do FortiOS é sessionada
FG_SESSION_WAIT = 1.0

PA_NLOGS = 3000   # teto por consulta (PAN-OS aceita até 5000)


# ---------------------------------------------------------------------------
# Palo Alto
# ---------------------------------------------------------------------------

def _pa_query(start, end):
    return "(receive_time geq '%s') and (receive_time leq '%s')" % (start, end)


def pa_fetch_logs(fw, start, end, outdir, log_types=("config", "system")):
    """Config + system log do PA na janela. Grava XML cru + resumo JSON."""
    if getattr(fw, "dry_run", False):
        for log_type in log_types:
            fw.get({"type": "log", "log-type": log_type,
                    "query": _pa_query(start, end), "nlogs": str(PA_NLOGS)},
                   label="pa-log-%s" % log_type)
        return []
    os.makedirs(outdir, exist_ok=True)
    all_events = []
    for log_type in log_types:
        root, raw = fw.run_log_job({
            "type": "log", "log-type": log_type,
            "query": _pa_query(start, end),
            "nlogs": str(PA_NLOGS), "dir": "backward",
        }, label="pa-log-%s" % log_type)
        if root is None:
            continue
        with open(os.path.join(outdir, "pa_log_%s.xml" % log_type), "wb") as fh:
            fh.write(raw)
        entries = root.findall(".//log/logs/entry")
        for e in entries:
            all_events.append({
                "fonte": "PA:%s" % log_type,
                "quando": (e.findtext("receive_time") or "").strip(),
                "quem": (e.findtext("admin") or "").strip(),
                "o_que": ((e.findtext("cmd") or "") + " " +
                          (e.findtext("path") or e.findtext("opaque") or ""))
                         .strip()[:300],
                "resultado": (e.findtext("result") or
                              e.findtext("severity") or "").strip(),
            })
        print("pa-logs %s: %d entradas (%s)" % (log_type, len(entries), fw.host))
        if len(entries) >= PA_NLOGS:
            print("  AVISO: bateu no teto de %d — janela tem mais log que isso; "
                  "estreite o intervalo (o rca deduplica recoletas)" % PA_NLOGS)
    with open(os.path.join(outdir, "pa_eventos.json"), "w", encoding="utf-8") as fh:
        json.dump(all_events, fh, ensure_ascii=False, indent=1)
    return all_events


# ---------------------------------------------------------------------------
# FortiGate
# ---------------------------------------------------------------------------

def _fg_log_read(client, store, subtype, vdom, rows):
    """Leitura sessionada: o FortiOS devolve session_id/completed e monta o
    resultado aos poucos — sem o poll, a coleta sai parcial e silenciosa."""
    params = {"rows": rows}
    resp = client.get("log/%s/event/%s" % (store, subtype), vdom=vdom,
                      params=params, label="fg-log-%s-%s" % (store, subtype))
    if resp is None or resp.get("http_status") == 404:
        return resp
    for _ in range(FG_SESSION_POLLS):
        completed = resp.get("completed")
        session_id = resp.get("session_id")
        if completed is None or session_id is None or completed >= 100:
            break
        time.sleep(FG_SESSION_WAIT)
        params_poll = dict(params)
        params_poll["session_id"] = session_id
        resp = client.get("log/%s/event/%s" % (store, subtype), vdom=vdom,
                          params=params_poll,
                          label="fg-log-%s-%s-poll" % (store, subtype))
        if resp is None or resp.get("http_status") == 404:
            return resp
    else:
        print("  AVISO: log %s/%s (vdom %s) não completou em %ds — resultado "
              "parcial" % (store, subtype, vdom, int(FG_SESSION_POLLS * FG_SESSION_WAIT)))
    return resp


def _fmt_epoch(value):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(value)))
    except (ValueError, TypeError, OverflowError):
        return str(value)


def _norm_when(value):
    """Normaliza p/ 'YYYY-MM-DD HH:MM:SS' o que der (epoch, ctime, Y/m/d...)."""
    text = str(value).strip()
    if text.isdigit():
        return _fmt_epoch(text)
    ts = _parse_when(text)
    if ts:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    return text


def fg_fetch_logs(client, outdir, vdoms=("root",), rows=FG_MAX_ROWS):
    """Logs de evento do FortiOS por VDOM + revisões de config (globais).

    A API devolve os mais recentes; o corte por janela é feito na timeline.
    """
    if getattr(client, "dry_run", False):
        for vdom in vdoms:
            for subtype in FG_EVENT_SUBTYPES:
                client.get("log/disk/event/%s" % subtype, vdom=vdom,
                           params={"rows": rows}, label="fg-log")
        client.get("monitor/system/config-revision", label="fg-config-revision")
        return []
    os.makedirs(outdir, exist_ok=True)
    all_events = []
    for vdom in vdoms:
        for subtype in FG_EVENT_SUBTYPES:
            got = None
            for store in FG_LOG_STORES:
                resp = _fg_log_read(client, store, subtype, vdom, rows)
                if resp is None or resp.get("http_status") == 404:
                    continue
                results = resp.get("results") or []
                if results or store == FG_LOG_STORES[-1]:
                    got = (store, results)
                    break
            if not got:
                continue
            store, results = got
            with open(os.path.join(outdir, "fg_log_event_%s_%s.json"
                                   % (vdom, subtype)), "w", encoding="utf-8") as fh:
                json.dump(results, fh, ensure_ascii=False, indent=1)
            for r in results:
                all_events.append({
                    "fonte": "FG:%s/%s" % (vdom, subtype),
                    "quando": ("%s %s" % (r.get("date", ""),
                                          r.get("time", ""))).strip(),
                    "quem": (r.get("user") or r.get("ui") or "").strip(),
                    "o_que": (r.get("logdesc", "") + " "
                              + r.get("msg", "")).strip()[:300],
                    "resultado": r.get("status", "") or r.get("action", ""),
                })
            print("fg-logs %s/event/%s: %d entradas (%s, %s)"
                  % (vdom, subtype, len(results), client.host, store))

    # Revisões de configuração — quem salvou config e quando (ouro para RCA)
    resp = client.get("monitor/system/config-revision", label="fg-config-revision")
    if resp is not None and resp.get("http_status") != 404:
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
                "quando": _norm_when(r.get("time", r.get("created", ""))),
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
    """Aceita epoch, 'YYYY/MM/DD HH:MM[:SS]', 'YYYY-MM-DD HH:MM[:SS]' e ctime
    ('Fri Aug 14 22:33:05 2026'). 0 se ilegível."""
    text = str(text).strip()
    if text.isdigit():
        return int(text)
    for fmt in (PA_TIME_FMT, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                "%Y/%m/%d %H:%M", "%a %b %d %H:%M:%S %Y"):
        try:
            return int(time.mktime(time.strptime(text, fmt)))
        except ValueError:
            continue
    return 0


def build_timeline(event_lists, start=None, end=None):
    """Une listas, DEDUPLICA (recoletas se sobrepõem), corta pela janela e
    ordena. Eventos com data ilegível (_ts=0) são mantidos e vão para o FIM."""
    t_start = _parse_when(start) if start else 0
    t_end = _parse_when(end) if end else 2 ** 62
    seen = set()
    merged = []
    for events in event_lists:
        for e in events:
            key = (e.get("fonte"), e.get("quando"), e.get("quem"),
                   e.get("o_que"), e.get("resultado"))
            if key in seen:
                continue
            seen.add(key)
            ts = _parse_when(e.get("quando", ""))
            if ts and (ts < t_start or ts > t_end):
                continue
            e = dict(e)
            e["_ts"] = ts
            merged.append(e)
    merged.sort(key=lambda e: (e["_ts"] == 0, e["_ts"], e["fonte"]))
    return merged


def _cell(value):
    return (str(value) or "-").replace("|", "\\|").replace("\n", " ⏎ ") or "-"


def render_timeline_md(timeline, start, end, notas=None):
    com_data = [e for e in timeline if e.get("_ts")]
    sem_data = [e for e in timeline if not e.get("_ts")]
    out = ["# RCA — linha do tempo da janela", ""]
    out.append("- Janela: %s → %s" % (start or "-", end or "-"))
    out.append("- Eventos na janela: %d (+%d com data ilegível, listados no fim)"
               % (len(com_data), len(sem_data)))
    out.append("- Horários no fuso LOCAL de cada equipamento — confirme "
               "timezone/NTP antes de comparar ao segundo.")
    out.append("")
    for nota in (notas or []):
        out.append("> %s" % _cell(nota))
    if notas:
        out.append("")
    out.append("| Quando | Fonte | Quem | O quê | Resultado |")
    out.append("|---|---|---|---|---|")
    for e in com_data:
        out.append("| %s | %s | %s | %s | %s |" % (
            _cell(e.get("quando")), _cell(e.get("fonte")),
            _cell(e.get("quem")), _cell(e.get("o_que")),
            _cell(e.get("resultado"))))
    if sem_data:
        out.append("")
        out.append("## Eventos com data ilegível (fora da ordenação e do corte)")
        out.append("")
        out.append("| Quando (cru) | Fonte | Quem | O quê | Resultado |")
        out.append("|---|---|---|---|---|")
        for e in sem_data:
            out.append("| %s | %s | %s | %s | %s |" % (
                _cell(e.get("quando")), _cell(e.get("fonte")),
                _cell(e.get("quem")), _cell(e.get("o_que")),
                _cell(e.get("resultado"))))
    return "\n".join(out)
