#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fgpoller — métricas de FortiGate para o dashboard de migração PA→FG.

Standalone de propósito (decisão D1 em docs/DECISOES.md): um arquivo, só
stdlib, para sobreviver sozinho em /opt na dev-redes. GET-only nos endpoints
api/v2/monitor do FortiOS, por VDOM, escrevendo line protocol no InfluxDB
central (bucket fw_migration). Token SEMPRE via variável de ambiente e SEMPRE
em header Authorization: Bearer — nunca query string.

Ciclos: fast (60s) recursos/HA/interfaces/túneis · slow (300s) vdom-resource/
rotas/ARP · hourly (3600s) hit counts/licença. ~250 séries por firewall.

Uso:
    fgpoller.py --config /opt/fw-migration/fgpoller.conf           # daemon
    fgpoller.py --config ... --once            # 1 ciclo completo e sai
    fgpoller.py --config ... --once --dry-run  # imprime line protocol, não POSTa
    fgpoller.py --selftest                     # valida parsers com respostas canned
"""

import argparse
import configparser
import json
import logging
import logging.handlers
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "fgpoller/1.0"
FG_ALLOWED_PREFIXES = ("api/v2/monitor/",)


# ---------------------------------------------------------------------------
# Trava de leitura (cópia local — ver docs/DECISOES.md D1/D2)
# ---------------------------------------------------------------------------

def assert_fg_read_only(method, path):
    where = "fgpoller: requisição bloqueada pela trava de leitura"
    if method != "GET":
        sys.exit("%s — método %r (só GET)" % (where, method))
    clean = path.lstrip("/")
    for prefix in FG_ALLOWED_PREFIXES:
        if clean.startswith(prefix):
            return path
    sys.exit("%s — path fora de api/v2/monitor: %.120s" % (where, path))


# ---------------------------------------------------------------------------
# Line protocol
# ---------------------------------------------------------------------------

def _esc_tag(value):
    return (str(value).replace("\\", "\\\\").replace(" ", "\\ ")
            .replace(",", "\\,").replace("=", "\\="))


def line(measurement, tags, fields, ts):
    parts = [_esc_tag(measurement)]
    for key in sorted(tags):
        value = tags[key]
        if value in (None, ""):
            value = "unknown"
        parts.append("%s=%s" % (_esc_tag(key), _esc_tag(value)))
    fparts = []
    for key in sorted(fields):
        value = fields[key]
        if isinstance(value, bool):
            fparts.append("%s=%s" % (_esc_tag(key), "true" if value else "false"))
        elif isinstance(value, int):
            fparts.append("%s=%di" % (_esc_tag(key), value))
        elif isinstance(value, float):
            fparts.append("%s=%s" % (_esc_tag(key), repr(value)))
        else:
            fparts.append('%s="%s"' % (_esc_tag(key),
                                       str(value).replace("\\", "\\\\")
                                       .replace('"', '\\"')))
    return "%s %s %d" % (",".join(parts), ",".join(fparts), ts)


# ---------------------------------------------------------------------------
# Cliente FortiOS (GET-only)
# ---------------------------------------------------------------------------

class FortiClient(object):
    def __init__(self, host, token, timeout=30, verify=False):
        self.host = host
        self._token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path, vdom=None, params=None):
        clean = "api/v2/" + path.lstrip("/")
        assert_fg_read_only("GET", clean)
        query = dict(params or {})
        if vdom:
            query["vdom"] = vdom
        url = "https://%s/%s" % (self.host, clean)
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(
            url, headers={"Authorization": "Bearer %s" % self._token,
                          "User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout,
                                    context=self.ctx) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Parsers (defensivos: formatos variam entre builds 7.4)
# ---------------------------------------------------------------------------

def metric_current(results, key):
    """resource/usage: aceita escalar, lista histórica [{current:..}] ou dict."""
    value = (results or {}).get(key)
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, dict):
        value = value.get("current", value.get("value", 0))
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def parse_resource_usage(resp, tags, ts):
    results = (resp or {}).get("results") or {}
    return [line("fg_system_resources", tags, {
        "cpu_pct": metric_current(results, "cpu"),
        "mem_pct": metric_current(results, "mem"),
        "session_count": int(metric_current(results, "session")),
        "session_setup_rate": int(metric_current(results, "setuprate")),
        "npu_session_count": int(metric_current(results, "npu_session")),
    }, ts)]


def parse_interfaces(resp, tags, ts):
    results = (resp or {}).get("results") or {}
    if isinstance(results, list):
        results = dict((i.get("name", str(n)), i) for n, i in enumerate(results))
    lines = []
    offset = 0
    for name in sorted(results):
        item = results[name] or {}
        t = dict(tags)
        t["interface"] = item.get("name", name)
        vdom = item.get("vdom")
        if vdom:
            t["vdom"] = vdom
        lines.append(line("fg_interface_stats", t, {
            "rx_bytes": int(item.get("rx_bytes", 0) or 0),
            "tx_bytes": int(item.get("tx_bytes", 0) or 0),
            "rx_packets": int(item.get("rx_packets", 0) or 0),
            "tx_packets": int(item.get("tx_packets", 0) or 0),
            "rx_errors": int(item.get("rx_errors", 0) or 0),
            "tx_errors": int(item.get("tx_errors", 0) or 0),
            "link": 1 if item.get("link") else 0,
            "speed": float(item.get("speed", 0) or 0),
        }, ts + offset))
        offset += 1
    return lines


def parse_ha(stats_resp, checks_resp, tags, ts):
    members = (stats_resp or {}).get("results") or []
    checks = (checks_resp or {}).get("results") or []
    sums = set()
    for member in checks:
        blob = member.get("checksum")
        if isinstance(blob, dict):
            sums.add(blob.get("all") or json.dumps(blob, sort_keys=True))
        elif blob:
            sums.add(str(blob))
    return [line("fg_ha", tags, {
        "member_count": len(members),
        "sync_ok": 1 if len(members) >= 2 else 0,
        "checksum_match": 1 if len(sums) <= 1 else 0,
    }, ts)]


def parse_vpn_ipsec(resp, tags, ts):
    results = (resp or {}).get("results") or []
    lines = []
    offset = 0
    for tun in results:
        proxy = tun.get("proxyid") or []
        p2_up = sum(1 for p in proxy if p.get("status") == "up")
        up = 1 if (p2_up or tun.get("status") == "up") else 0
        t = dict(tags)
        t["phase1"] = tun.get("name", "?")
        lines.append(line("fg_vpn_tunnel", t, {
            "up": up,
            "incoming_bytes": int(tun.get("incoming_bytes", 0) or 0),
            "outgoing_bytes": int(tun.get("outgoing_bytes", 0) or 0),
            "p2_total": len(proxy),
            "p2_up": p2_up,
        }, ts + offset))
        offset += 1
    total_up = sum(1 for tun in results
                   if any(p.get("status") == "up" for p in (tun.get("proxyid") or []))
                   or tun.get("status") == "up")
    lines.append(line("fg_vpn_summary", tags,
                      {"tunnels_total": len(results), "tunnels_up": total_up}, ts))
    return lines


def parse_vdom_resource(resp, tags, ts):
    results = (resp or {}).get("results") or {}
    session = results.get("session") or results.get("sessions") or {}
    if isinstance(session, list) and session:
        session = session[0]
    current = int(session.get("current_usage", session.get("current", 0)) or 0)
    maximum = int(session.get("max_guaranteed", session.get("max", 0)) or 0)
    pct = (100.0 * current / maximum) if maximum else 0.0
    return [line("fg_sessions", tags,
                 {"num_active": current, "session_pct": pct}, ts)]


def parse_routes(resp, tags, ts):
    results = (resp or {}).get("results") or []
    static = sum(1 for r in results if r.get("type") == "static")
    connected = sum(1 for r in results if r.get("type") == "connect")
    return [line("fg_route_count", tags,
                 {"total": len(results), "static": static,
                  "connected": connected}, ts)]


def parse_arp(resp, tags, ts):
    results = (resp or {}).get("results") or []
    return [line("fg_arp_count", tags, {"total": len(results)}, ts)]


def parse_policy_hits(resp, tags, ts):
    results = (resp or {}).get("results") or []
    zero = sum(1 for p in results if not p.get("hit_count"))
    return [line("fg_policy_hits", tags,
                 {"policies_total": len(results), "policies_zero_hit": zero}, ts)]


def parse_license(resp, tags, ts):
    results = (resp or {}).get("results") or {}
    forticare = results.get("forticare") or {}
    status = forticare.get("status", "")
    return [line("fg_license", tags,
                 {"valid": 1 if status in ("registered", "licensed") else 0,
                  "status": status or "unknown"}, ts)]


# ---------------------------------------------------------------------------
# Coleta por firewall
# ---------------------------------------------------------------------------

def collect_tier(client, fw, tier, log):
    """Roda um tier (fast/slow/hourly) e devolve (lines, endpoints_failed)."""
    ts = int(time.time())
    base = {"hostname": fw["name"], "site": fw["site"]}
    lines = []
    failed = 0

    def call(fn, path, vdom=None, params=None, extra_tags=None):
        tags = dict(base)
        if vdom:
            tags["vdom"] = vdom
        if extra_tags:
            tags.update(extra_tags)
        try:
            resp = client.get(path, vdom=vdom, params=params)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                ValueError) as exc:
            log.warning("%s %s%s: %s", fw["name"], path,
                        " vdom=%s" % vdom if vdom else "", exc)
            return 1
        lines.extend(fn(resp, tags, ts))
        return 0

    if tier == "fast":
        failed += call(parse_resource_usage, "monitor/system/resource/usage",
                       params={"scope": "global", "interval": "1-min"})
        failed += call(parse_interfaces, "monitor/system/interface",
                       params={"include_vlan": "true", "scope": "global"})
        try:
            stats = client.get("monitor/system/ha-statistics")
            checks = client.get("monitor/system/ha-checksums")
            lines.extend(parse_ha(stats, checks, dict(base), ts))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                ValueError) as exc:
            log.warning("%s ha: %s", fw["name"], exc)
            failed += 1
        for vdom in fw["vdoms"]:
            failed += call(parse_vpn_ipsec, "monitor/vpn/ipsec", vdom=vdom)
    elif tier == "slow":
        for vdom in fw["vdoms"]:
            failed += call(parse_vdom_resource, "monitor/system/vdom-resource",
                           vdom=vdom)
            failed += call(parse_routes, "monitor/router/ipv4", vdom=vdom)
            failed += call(parse_arp, "monitor/network/arp", vdom=vdom)
    elif tier == "hourly":
        for vdom in fw["vdoms"]:
            failed += call(parse_policy_hits, "monitor/firewall/policy", vdom=vdom)
        failed += call(parse_license, "monitor/license/status")

    return lines, failed


# ---------------------------------------------------------------------------
# Influx
# ---------------------------------------------------------------------------

def influx_write(cfg, lines, log, dry_run=False):
    if not lines:
        return True
    if dry_run:
        for ln in lines:
            print(ln)
        return True
    token = os.environ.get(cfg["token_env"], "")
    if not token:
        log.error("influx: env %s vazia", cfg["token_env"])
        return False
    query = urllib.parse.urlencode({"org": cfg["org"], "bucket": cfg["bucket"],
                                    "precision": "s"})
    req = urllib.request.Request(
        "%s/api/v2/write?%s" % (cfg["url"].rstrip("/"), query),
        data="\n".join(lines).encode("utf-8"),
        headers={"Authorization": "Token %s" % token,
                 "Content-Type": "text/plain; charset=utf-8"},
        method="POST")
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status in (200, 204):
                    return True
        except urllib.error.HTTPError as exc:
            log.error("influx HTTP %s", exc.code)
            if exc.code in (400, 401, 403, 404):
                return False
        except urllib.error.URLError as exc:
            log.warning("influx: %s", exc.reason)
        time.sleep(attempt)
    return False


# ---------------------------------------------------------------------------
# Config / main
# ---------------------------------------------------------------------------

def load_config(path):
    if not os.path.isfile(path):
        sys.exit("fgpoller: config não encontrada: %s" % path)
    parser = configparser.ConfigParser()
    parser.read(path)
    influx = {
        "url": parser.get("influx", "url", fallback="http://10.114.35.75:8086"),
        "org": parser.get("influx", "org", fallback="TOTVS"),
        "bucket": parser.get("influx", "bucket", fallback="fw_migration"),
        "token_env": parser.get("influx", "token_env", fallback="INFLUX_TOKEN"),
    }
    intervals = {
        "fast": parser.getint("intervals", "fast", fallback=60),
        "slow": parser.getint("intervals", "slow", fallback=300),
        "hourly": parser.getint("intervals", "hourly", fallback=3600),
    }
    firewalls = []
    for section in parser.sections():
        if not section.startswith("fw:"):
            continue
        if not parser.getboolean(section, "enabled", fallback=True):
            continue
        firewalls.append({
            "name": section[3:],
            "host": parser.get(section, "host"),
            "token_env": parser.get(section, "token_env"),
            "site": parser.get(section, "site", fallback="TECE1"),
            "vdoms": [v.strip() for v in
                      parser.get(section, "vdoms", fallback="root").split(",")
                      if v.strip()],
        })
    if not firewalls:
        sys.exit("fgpoller: nenhuma seção [fw:*] habilitada em %s" % path)
    return influx, intervals, firewalls


def load_env_file(path):
    if not path or not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, _, value = raw.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


def make_logger(logfile):
    log = logging.getLogger("fgpoller")
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    if logfile:
        os.makedirs(os.path.dirname(logfile), exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            logfile, maxBytes=50 * 1024 * 1024, backupCount=3)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    return log


def run_cycle(influx_cfg, firewalls, tiers, log, dry_run=False):
    for fw in firewalls:
        token = os.environ.get(fw["token_env"], "")
        if not token:
            log.error("%s: env %s vazia — pulando", fw["name"], fw["token_env"])
            continue
        client = FortiClient(fw["host"], token)
        started = time.time()
        all_lines = []
        total_failed = 0
        for tier in tiers:
            lines, failed = collect_tier(client, fw, tier, log)
            all_lines.extend(lines)
            total_failed += failed
        all_lines.append(line(
            "fg_collector_health",
            {"hostname": fw["name"], "site": fw["site"]},
            {"ok": 1 if total_failed == 0 else 0,
             "duration_ms": int((time.time() - started) * 1000),
             "endpoints_failed": total_failed,
             "lines": len(all_lines)},
            int(time.time())))
        ok = influx_write(influx_cfg, all_lines, log, dry_run=dry_run)
        log.info("%s: tiers=%s lines=%d failed_endpoints=%d influx=%s",
                 fw["name"], "+".join(tiers), len(all_lines), total_failed,
                 "dry-run" if dry_run else ("ok" if ok else "ERRO"))


def selftest():
    """Valida parsers + line protocol com respostas canned — sem rede."""
    ts = 1700000000
    tags = {"hostname": "FW05TECE01-FORTINET", "site": "TECE1"}
    canned = []
    canned += parse_resource_usage(
        {"results": {"cpu": [{"current": 7}], "mem": [{"current": 33}],
                     "session": [{"current": 12345}],
                     "setuprate": [{"current": 210}]}}, tags, ts)
    canned += parse_interfaces(
        {"results": {"ae1.2906": {"name": "ae1.2906", "vdom": "root",
                                  "link": True, "speed": 10000.0,
                                  "rx_bytes": 1000, "tx_bytes": 2000,
                                  "rx_packets": 10, "tx_packets": 20,
                                  "rx_errors": 0, "tx_errors": 0}}}, tags, ts)
    canned += parse_ha({"results": [{"serial_no": "A"}, {"serial_no": "B"}]},
                       {"results": [{"serial_no": "A", "checksum": {"all": "x"}},
                                    {"serial_no": "B", "checksum": {"all": "x"}}]},
                       tags, ts)
    vtags = dict(tags)
    vtags["vdom"] = "root"
    canned += parse_vpn_ipsec(
        {"results": [{"name": "VPN_TESP03_P1", "incoming_bytes": 5, "outgoing_bytes": 6,
                      "proxyid": [{"status": "up"}, {"status": "down"}]}]},
        vtags, ts)
    canned += parse_vdom_resource(
        {"results": {"session": {"current_usage": 4321, "max_guaranteed": 100000}}},
        vtags, ts)
    canned += parse_routes({"results": [{"type": "static"}, {"type": "connect"}]},
                           vtags, ts)
    canned += parse_arp({"results": [{"ip": "10.0.0.1"}]}, vtags, ts)
    canned += parse_policy_hits({"results": [{"policyid": 1, "hit_count": 0},
                                             {"policyid": 2, "hit_count": 9}]},
                                vtags, ts)
    canned += parse_license({"results": {"forticare": {"status": "registered"}}},
                            tags, ts)
    bad = [ln for ln in canned if " " not in ln or not ln.rsplit(" ", 1)[1].isdigit()]
    for ln in canned:
        print(ln)
    if bad:
        sys.exit("selftest: %d linhas inválidas" % len(bad))
    print("# selftest OK — %d linhas de line protocol válidas" % len(canned))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="fgpoller")
    parser.add_argument("--config", default="/opt/fw-migration/fgpoller.conf")
    parser.add_argument("--env-file", default="/opt/fw-migration/.env")
    parser.add_argument("--log-file", default="/opt/fw-migration/logs/fgpoller.log")
    parser.add_argument("--once", action="store_true",
                        help="roda fast+slow+hourly uma vez e sai")
    parser.add_argument("--dry-run", action="store_true",
                        help="imprime line protocol em vez de POSTar")
    parser.add_argument("--selftest", action="store_true",
                        help="valida parsers sem rede e sai")
    args = parser.parse_args(argv)

    if args.selftest:
        selftest()
        return 0

    load_env_file(args.env_file)
    influx_cfg, intervals, firewalls = load_config(args.config)
    log = make_logger(None if args.dry_run else args.log_file)
    log.info("fgpoller: %d firewall(s), fast=%ds slow=%ds hourly=%ds",
             len(firewalls), intervals["fast"], intervals["slow"],
             intervals["hourly"])

    if args.once:
        run_cycle(influx_cfg, firewalls, ("fast", "slow", "hourly"), log,
                  dry_run=args.dry_run)
        return 0

    last = {"fast": 0.0, "slow": 0.0, "hourly": 0.0}
    while True:
        now = time.time()
        due = [t for t in ("fast", "slow", "hourly")
               if now - last[t] >= intervals[t]]
        if due:
            for t in due:
                last[t] = now
            run_cycle(influx_cfg, firewalls, tuple(due), log,
                      dry_run=args.dry_run)
        time.sleep(2)


if __name__ == "__main__":
    sys.exit(main())
