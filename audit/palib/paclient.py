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

    def run_log_job(self, params, label, poll_interval=2.0, attempts=15):
        """Consulta de log no PAN-OS é assíncrona: submete, recebe job id, poleia.

        Mesma mecânica do pa-forense/palo-collector (logjob.go), inclusive o
        detalhe de aceitar os DOIS sinais de término — progress=100 ou o job
        reportando FIN. A trava de leitura vale igual (type=log).
        """
        import time
        root, _raw = self.get(params, label + "-submit")
        if root is None:      # dry-run
            return None, b""
        job_el = root.find("./result/job")
        if job_el is None or not (job_el.text or "").strip():
            sys.exit("PA %s: %s não devolveu job id" % (self.host, label))
        job_id = job_el.text.strip()
        for _ in range(attempts):
            time.sleep(poll_interval)
            root, raw = self.get({"type": "log", "action": "get",
                                  "job-id": job_id}, label + "-poll")
            logs = root.find("./result/log/logs")
            status = root.findtext("./result/job/status", "")
            if (logs is not None and logs.get("progress") == "100") or \
                    status == "FIN":
                return root, raw
        sys.exit("PA %s: job %s de %s não terminou em %ds"
                 % (self.host, job_id, label, int(attempts * poll_interval)))
