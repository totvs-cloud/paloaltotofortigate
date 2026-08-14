# -*- coding: utf-8 -*-
"""Cliente XML API PAN-OS — derivado de ferramentas/pa-forense/pa_forense.py.

Toda requisição passa por assert_read_only ANTES de sair. A chave nunca
aparece em log/print (mask_key).
"""

import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .readonly import assert_read_only, mask_key


class Firewall(object):
    def __init__(self, host, api_key, verify=False, timeout=60, dry_run=False):
        self.host = host
        self._key = api_key
        self.timeout = timeout
        self.dry_run = dry_run
        self.ctx = ssl.create_default_context()
        if not verify:
            # Certificado próprio dos firewalls; mesmo `curl -k` da operação.
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, params, label=""):
        """GET na XML API. Devolve (root ET, bytes crus) ou (None, b'') em dry-run."""
        assert_read_only(params)
        full = dict(params)
        full["key"] = self._key
        url = "https://%s/api/?%s" % (self.host, urllib.parse.urlencode(full))

        if self.dry_run:
            print("[dry-run] %s%s" % (label and label + ": " or "", mask_key(url)))
            return None, b""

        req = urllib.request.Request(url, headers={"User-Agent": "fwaudit/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self.ctx) as resp:
                data = resp.read()
        except urllib.error.HTTPError as exc:
            sys.exit("PA %s: HTTP %s (%s)" % (self.host, exc.code, label or "req"))
        except urllib.error.URLError as exc:
            sys.exit("PA %s: falha de conexão: %s" % (self.host, exc.reason))

        root = ET.fromstring(data)
        if root.get("status") not in (None, "success"):
            msg = "".join(root.itertext()).strip()
            sys.exit("PA %s respondeu status=%s em %s: %s"
                     % (self.host, root.get("status"), label, mask_key(msg)[:300]))
        return root, data
