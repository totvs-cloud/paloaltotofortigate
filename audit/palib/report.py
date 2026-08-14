# -*- coding: utf-8 -*-
"""Relatório da auditoria: Markdown + HTML simples + JSONs de evidência.

O MD/HTML mostram até MAX_ROWS itens por check; a evidência completa fica em
out/<data>/checks/<id>.json. Nenhum segredo chega aqui (redação na origem).
"""

import json
import os
import time

from . import VERSION
from .checks import SEV_ORDER

MAX_ROWS = 30

SEV_BADGE = {"CRITICO": "🟥 CRÍTICO", "ALTO": "🟧 ALTO", "MEDIO": "🟨 MÉDIO",
             "BAIXO": "🟦 BAIXO", "INFO": "⬜ INFO"}


def _fmt_cell(value):
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "-"
    if isinstance(value, bool):
        return "sim" if value else "nao"
    if value is None or value == "":
        return "-"
    return str(value)


def _table_md(itens):
    if not itens:
        return "_(nenhum item)_\n"
    cols = []
    for item in itens:
        for k in item:
            if k not in cols:
                cols.append(k)
    lines = ["| " + " | ".join(cols) + " |",
             "|" + "|".join("---" for _ in cols) + "|"]
    for item in itens[:MAX_ROWS]:
        lines.append("| " + " | ".join(
            _fmt_cell(item.get(c)).replace("|", "\\|") for c in cols) + " |")
    if len(itens) > MAX_ROWS:
        lines.append("")
        lines.append("_… mais %d itens no JSON de evidência._" % (len(itens) - MAX_ROWS))
    return "\n".join(lines) + "\n"


def _inventory_summary(inv):
    net = inv["network"]
    ifs = net["interfaces"]
    rows = []
    for vsys in ("vsys1", "vsys2"):
        v = inv[vsys]
        rows.append({
            "escopo": "%s (%s)" % (vsys, inv["meta"]["vsys"].get(vsys, {}).get("display_name", "")),
            "security_rules": len(v["security_rules"]),
            "nat_rules": len(v["nat_rules"]),
            "pbf": len(v["pbf_rules"]),
            "zonas": len(v["zones"]),
            "address": len(v["objects"]["address"]),
            "addr_group": len(v["objects"]["address_group"]),
            "service": len(v["objects"]["service"]),
        })
    sh = inv["shared"]["objects"]
    rows.append({"escopo": "shared", "security_rules": "-", "nat_rules": "-",
                 "pbf": "-", "zonas": "-", "address": len(sh["address"]),
                 "addr_group": len(sh["address_group"]), "service": len(sh["service"])})
    extras = {
        "rotas_estaticas": {vr: len(rt) for vr, rt in net["static_routes"].items()},
        "ike_gateways": len(net["ike_gateways"]),
        "ipsec_tunnels": len(net["ipsec_tunnels"]),
        "edls": len(inv["edls"]),
        "subinterfaces": sum(len(a["subifs"]) for a in ifs["aggregate"].values()),
        "loopbacks": len(ifs["loopbacks"]),
        "tunnel_units": len(ifs["tunnel_units"]),
        "certificados": len(inv["certificates"]),
    }
    return rows, extras


def render_md(inv, results, generated_at=None):
    meta = inv["meta"]
    fmeta = meta.get("file", {})
    ts = generated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    rows, extras = _inventory_summary(inv)

    out = []
    out.append("# Auditoria de migração PA → FortiGate — %s"
               % meta["mgmt"].get("hostname", "?"))
    out.append("")
    out.append("- Gerado em: %s (fwaudit %s)" % (ts, VERSION))
    out.append("- Snapshot: `%s`" % fmeta.get("path", "?"))
    out.append("- sha256: `%s` · PAN-OS: %s · mgmt: %s"
               % (fmeta.get("sha256", "?")[:16], fmeta.get("panos_version", "?"),
                  meta["mgmt"].get("mgmt_ip", "?")))
    out.append("- ⚠️ O snapshot pode divergir do running-config: pedir export novo "
               "antes da comparação final (docs/DECISOES.md).")
    out.append("")

    out.append("## Sumário executivo")
    out.append("")
    sev_count = {}
    for r in results:
        sev_count[r["severidade"]] = sev_count.get(r["severidade"], 0) + 1
    out.append("| Severidade | Checks |")
    out.append("|---|---|")
    for sev in sorted(sev_count, key=lambda s: SEV_ORDER.get(s, 9)):
        out.append("| %s | %d |" % (SEV_BADGE.get(sev, sev), sev_count[sev]))
    out.append("")
    out.append("| ID | Severidade | Check | Itens |")
    out.append("|---|---|---|---|")
    for r in results:
        out.append("| %s | %s | %s | %d |"
                   % (r["id"], SEV_BADGE.get(r["severidade"], r["severidade"]),
                      r["titulo"], len(r["itens"])))
    out.append("")

    out.append("## Inventário do snapshot")
    out.append("")
    out.append(_table_md(rows))
    out.append("Rede: %s" % "; ".join("%s=%s" % (k, v) for k, v in sorted(extras.items())))
    out.append("")

    for r in results:
        out.append("## %s — %s" % (r["id"], r["titulo"]))
        out.append("")
        out.append("**%s** · classe FortiConverter: %s · itens: %d"
                   % (SEV_BADGE.get(r["severidade"], r["severidade"]),
                      r.get("classe_fc", "-"), len(r["itens"])))
        out.append("")
        out.append(r["resumo"])
        out.append("")
        out.append(_table_md(r["itens"]))
        out.append("")

    out.append("---")
    out.append("_Relatório gerado por fwaudit (repo paloaltotofortigate). Diagnóstico "
               "somente leitura; toda correção é proposta escrita._")
    return "\n".join(out)


def _md_to_html(md_text):
    """Conversor mínimo (títulos, tabelas, ênfase) — suficiente para o relatório."""
    import re as _re
    html = []
    in_table = False
    for line in md_text.split("\n"):
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                html.append("<table>")
                in_table = True
            html.append("<tr>" + "".join("<%s>%s</%s>" % (tag, c, tag)
                                         for c in cells) + "</tr>")
            continue
        if in_table:
            html.append("</table>")
            in_table = False
        stripped = line.strip()
        esc = (stripped.replace("&", "&amp;").replace("<", "&lt;")
               .replace(">", "&gt;"))
        esc = _re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
        esc = _re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", esc)
        esc = _re.sub(r"_([^_]+)_", r"<i>\1</i>", esc)
        if stripped.startswith("# "):
            html.append("<h1>%s</h1>" % esc[2:])
        elif stripped.startswith("## "):
            html.append("<h2>%s</h2>" % esc[3:])
        elif stripped.startswith("- "):
            html.append("<div class='li'>• %s</div>" % esc[2:])
        elif stripped == "---":
            html.append("<hr>")
        elif stripped:
            html.append("<p>%s</p>" % esc)
    if in_table:
        html.append("</table>")
    return ("<!-- gerado por fwaudit -->\n<meta charset='utf-8'>"
            "<style>body{font-family:sans-serif;max-width:1200px;margin:2em auto;"
            "padding:0 1em;color:#222}table{border-collapse:collapse;margin:1em 0;"
            "font-size:13px}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}"
            "th{background:#f0f0f0}code{background:#f4f4f4;padding:1px 4px}"
            "h1,h2{border-bottom:1px solid #ddd;padding-bottom:4px}</style>\n"
            + "\n".join(html))


def write_outputs(outdir, inv, results, html=True):
    """Grava relatorio.md(.html), inventario.json e checks/<id>.json. Devolve paths."""
    stamp = time.strftime("%Y-%m-%d_%H%M")
    base = os.path.join(outdir, stamp)
    checks_dir = os.path.join(base, "checks")
    os.makedirs(checks_dir, exist_ok=True)

    md = render_md(inv, results)
    paths = {"dir": base, "md": os.path.join(base, "relatorio.md")}
    with open(paths["md"], "w", encoding="utf-8") as fh:
        fh.write(md)
    if html:
        paths["html"] = os.path.join(base, "relatorio.html")
        with open(paths["html"], "w", encoding="utf-8") as fh:
            fh.write(_md_to_html(md))

    paths["inventario"] = os.path.join(base, "inventario.json")
    with open(paths["inventario"], "w", encoding="utf-8") as fh:
        json.dump(inv, fh, ensure_ascii=False, indent=1, sort_keys=True)

    for r in results:
        with open(os.path.join(checks_dir, "%s.json" % r["id"]), "w",
                  encoding="utf-8") as fh:
            json.dump(r, fh, ensure_ascii=False, indent=1, sort_keys=True)
    return paths
