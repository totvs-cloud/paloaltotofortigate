# -*- coding: utf-8 -*-
"""Escrita mínima no InfluxDB v2 (line protocol via urllib, sem dependências).

Usada pelo compare (mig_audit) e pelo pa-baseline (mig_pa_baseline). O fgpoller
tem a própria cópia standalone (decisão D1 — docs/DECISOES.md).
"""

import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _esc_tag(value):
    return (str(value).replace("\\", "\\\\").replace(" ", "\\ ")
            .replace(",", "\\,").replace("=", "\\="))


def _esc_str_field(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def line(measurement, tags, fields, ts=None):
    """Monta uma linha de line protocol. Fields int viram i; str viram "..."."""
    parts = [_esc_tag(measurement)]
    for key in sorted(tags):
        value = tags[key]
        if value in (None, ""):
            value = "unknown"   # tag vazia some no Influx (lição do palo-collector)
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
            fparts.append('%s="%s"' % (_esc_tag(key), _esc_str_field(value)))
    out = "%s %s" % (",".join(parts), ",".join(fparts))
    if ts is not None:
        out += " %d" % ts
    return out


class InfluxWriter(object):
    def __init__(self, url, org, bucket, token, timeout=15):
        self.url = url.rstrip("/")
        self.org = org
        self.bucket = bucket
        self._token = token
        self.timeout = timeout

    @classmethod
    def from_env(cls):
        url = os.environ.get("INFLUX_URL", "")
        org = os.environ.get("INFLUX_ORG", "TOTVS")
        bucket = os.environ.get("INFLUX_BUCKET", "fw_migration")
        token = os.environ.get("INFLUX_TOKEN", "")
        if not url or not token:
            sys.exit("influx: defina INFLUX_URL e INFLUX_TOKEN no ambiente/.env")
        return cls(url, org, bucket, token)

    def write_lines(self, lines):
        if not lines:
            return
        query = urllib.parse.urlencode(
            {"org": self.org, "bucket": self.bucket, "precision": "s"})
        req = urllib.request.Request(
            "%s/api/v2/write?%s" % (self.url, query),
            data="\n".join(lines).encode("utf-8"),
            headers={"Authorization": "Token %s" % self._token,
                     "Content-Type": "text/plain; charset=utf-8"},
            method="POST")
        for attempt in range(1, 4):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status in (200, 204):
                        return
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read().decode("utf-8", "replace")[:200]
                except Exception:
                    pass
                if exc.code in (400, 401, 403, 404):
                    sys.exit("influx: HTTP %s ao escrever (%s)" % (exc.code, body))
            except urllib.error.URLError:
                pass
            time.sleep(attempt)
        sys.exit("influx: falha ao escrever após 3 tentativas em %s" % self.url)
