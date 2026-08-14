# -*- coding: utf-8 -*-
"""Cliente REST FortiOS — GET-only, token em header Bearer (nunca query string).

Trava mecânica: todo path passa por assert_fg_read_only e o método é fixo GET.
Paginação de cmdb via start/count. Throttle entre requisições para não pesar
no management plane durante a janela.
"""

import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .readonly import assert_fg_read_only

PAGE_SIZE = 500


class FortiClient(object):
    def __init__(self, host, token, verify=False, timeout=60, throttle=0.3,
                 dry_run=False):
        self.host = host
        self._token = token
        self.timeout = timeout
        self.throttle = throttle
        self.dry_run = dry_run
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path, vdom=None, params=None, label=""):
        """GET api/v2/<path>. Devolve o JSON decodificado (dict) ou None em dry-run."""
        clean = path.lstrip("/")
        if not clean.startswith("api/v2/"):
            clean = "api/v2/" + clean
        assert_fg_read_only("GET", clean)

        query = dict(params or {})
        if vdom:
            query["vdom"] = vdom
        url = "https://%s/%s" % (self.host, clean)
        if query:
            url += "?" + urllib.parse.urlencode(query)

        if self.dry_run:
            print("[dry-run] %s%s" % (label and label + ": " or "", url))
            return None

        req = urllib.request.Request(
            url, headers={"Authorization": "Bearer %s" % self._token,
                          "User-Agent": "fwaudit/1.0"})
        last_err = ""
        for attempt in range(1, 4):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout,
                                            context=self.ctx) as resp:
                    data = resp.read()
                if self.throttle:
                    time.sleep(self.throttle)
                try:
                    return json.loads(data.decode("utf-8", "replace"))
                except ValueError:
                    sys.exit("FG %s: resposta não-JSON em %s" % (self.host, clean))
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    sys.exit("FG %s: HTTP %s em %s — token inválido/sem permissão "
                             "ou IP fora do trusthost do admin de API"
                             % (self.host, exc.code, clean))
                if exc.code == 404:
                    return {"http_status": 404, "results": []}
                last_err = "HTTP %s" % exc.code
            except urllib.error.URLError as exc:
                last_err = str(exc.reason)
            time.sleep(attempt)
        sys.exit("FG %s: falha em %s após 3 tentativas (%s)"
                 % (self.host, clean, last_err))

    def cmdb_all(self, path, vdom):
        """GET cmdb paginado (start/count) até esgotar. Devolve lista de results."""
        results = []
        start = 0
        while True:
            resp = self.get("cmdb/" + path, vdom=vdom,
                            params={"start": start, "count": PAGE_SIZE},
                            label="cmdb/%s" % path)
            if resp is None:      # dry-run
                return []
            page = resp.get("results") or []
            results.extend(page)
            if len(page) < PAGE_SIZE:
                return results
            start += PAGE_SIZE
