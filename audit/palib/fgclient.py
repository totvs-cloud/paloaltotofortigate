# -*- coding: utf-8 -*-
"""Cliente REST FortiOS — GET-only. Duas autenticações:

- token de API: header Authorization: Bearer (nunca query string) — preferida;
- sessão (usuário/senha): POST /logincheck + cookie ccsrftoken. O login/logout
  é a MESMA exceção estreita do keygen no pa-forense: autenticação não é
  configuração, os endpoints são literais desta função e nada de fora passa
  por eles. Depois de autenticado, TODA requisição continua na trava GET-only.

Senha/token SEMPRE via variável de ambiente — nunca em argv (tabela de
processos, histórico). Paginação de cmdb via start/count; throttle entre
requisições para não pesar no management plane durante a janela.
"""

import http.cookiejar
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
    def __init__(self, host, token=None, username=None, password=None,
                 verify=False, timeout=60, throttle=0.3, dry_run=False):
        if not token and not (username and password):
            sys.exit("FG %s: informe token OU usuário+senha" % host)
        self.host = host
        self._token = token
        self._username = username
        self._password = password
        self._csrf = None
        self.timeout = timeout
        self.throttle = throttle
        self.dry_run = dry_run
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ctx),
            urllib.request.HTTPCookieProcessor(self._jar))
        if not token and not dry_run:
            self._login()

    def _login(self):
        """POST /logincheck — exceção de autenticação (ver docstring do módulo)."""
        body = urllib.parse.urlencode({"username": self._username,
                                       "secretkey": self._password,
                                       "ajax": "1"}).encode()
        req = urllib.request.Request(
            "https://%s/logincheck" % self.host, data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "fwaudit/1.0"})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                out = resp.read().decode("utf-8", "replace")
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            sys.exit("FG %s: logincheck falhou: %s" % (self.host, exc))
        # resposta ajax: '1' = ok; '0' = credencial errada; '3' = admin bloqueado
        if not out.strip().startswith("1"):
            sys.exit("FG %s: login recusado (resposta %r) — credencial errada, "
                     "admin bloqueado ou IP fora do trusthost"
                     % (self.host, out.strip()[:20]))
        for cookie in self._jar:
            if cookie.name.startswith("ccsrftoken"):
                self._csrf = cookie.value.strip('"')
        if not self._csrf:
            sys.exit("FG %s: login ok mas sem cookie ccsrftoken" % self.host)

    def logout(self):
        """POST /logout — encerra a sessão (não deixar sessão admin pendurada)."""
        if self._token or self._csrf is None or self.dry_run:
            return
        try:
            req = urllib.request.Request(
                "https://%s/logout" % self.host, data=b"",
                headers={"User-Agent": "fwaudit/1.0"})
            self._opener.open(req, timeout=10).read()
        except Exception:
            pass  # sessão expira sozinha; logout é best-effort
        self._csrf = None

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

        headers = {"User-Agent": "fwaudit/1.0"}
        if self._token:
            headers["Authorization"] = "Bearer %s" % self._token
        elif self._csrf:
            headers["X-CSRFTOKEN"] = self._csrf   # GET nem exige, mas não custa
        req = urllib.request.Request(url, headers=headers)
        last_err = ""
        for attempt in range(1, 4):
            try:
                if self._token:
                    resp_cm = urllib.request.urlopen(req, timeout=self.timeout,
                                                     context=self.ctx)
                else:
                    resp_cm = self._opener.open(req, timeout=self.timeout)
                with resp_cm as resp:
                    data = resp.read()
                if self.throttle:
                    time.sleep(self.throttle)
                try:
                    return json.loads(data.decode("utf-8", "replace"))
                except ValueError:
                    sys.exit("FG %s: resposta não-JSON em %s (sessão expirou? "
                             "IP fora do trusthost?)" % (self.host, clean))
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    sys.exit("FG %s: HTTP %s em %s — credencial inválida/sem "
                             "permissão ou IP fora do trusthost"
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
