# -*- coding: utf-8 -*-
"""A trava é o contrato do repo com o time: cada verbo de escrita tem que abortar."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from palib.readonly import assert_read_only, assert_fg_read_only, mask_key


class AssertReadOnlyPA(unittest.TestCase):
    def ok(self, params):
        self.assertEqual(assert_read_only(dict(params)), dict(params))

    def blocked(self, params):
        with self.assertRaises(SystemExit):
            assert_read_only(dict(params))

    def test_show_passa(self):
        self.ok({"type": "op", "cmd": "<show><session><info/></session></show>"})
        self.ok({"type": "op", "cmd": "<show><vpn><ipsec-sa/></vpn></show>"})

    def test_config_leitura_passa(self):
        self.ok({"type": "config", "action": "get", "xpath": "/config/shared/address"})
        self.ok({"type": "config", "action": "show", "xpath": "/config"})

    def test_log_passa(self):
        self.ok({"type": "log", "log-type": "config"})
        self.ok({"type": "log", "action": "get", "job-id": "42"})

    def test_verbos_de_escrita_bloqueiam(self):
        for verb in ("set", "edit", "delete", "commit", "request", "clear",
                     "debug", "restore", "test"):
            self.blocked({"type": "op", "cmd": "<%s>x</%s>" % (verb, verb)})
            # escondido dentro de um <show> também bloqueia
            self.blocked({"type": "op",
                          "cmd": "<show><%s>x</%s></show>" % (verb, verb)})

    def test_config_escrita_bloqueia(self):
        self.blocked({"type": "config", "action": "set", "xpath": "/x"})
        self.blocked({"type": "config", "action": "edit", "xpath": "/x"})
        self.blocked({"type": "config", "action": "delete", "xpath": "/x"})
        # action de leitura mas com element = escrita
        self.blocked({"type": "config", "action": "get", "xpath": "/x",
                      "element": "<a/>"})

    def test_tipos_fora_da_lista_bloqueiam(self):
        self.blocked({"type": "keygen"})
        self.blocked({"type": "commit"})
        self.blocked({"type": "import"})
        self.blocked({"type": "user-id"})
        self.blocked({})

    def test_log_types_fora_da_lista_bloqueiam(self):
        self.blocked({"type": "log", "log-type": "userid"})
        self.blocked({"type": "log", "action": "finish"})


class AssertReadOnlyFG(unittest.TestCase):
    def test_get_monitor_cmdb_e_log_passam(self):
        assert_fg_read_only("GET", "api/v2/monitor/system/status")
        assert_fg_read_only("GET", "/api/v2/cmdb/firewall/policy")
        assert_fg_read_only("GET", "api/v2/log/memory/event/system")
        assert_fg_read_only("GET", "api/v2/log/disk/event/ha")

    def test_metodos_de_escrita_bloqueiam(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.assertRaises(SystemExit):
                assert_fg_read_only(method, "api/v2/monitor/system/status")
            with self.assertRaises(SystemExit):
                assert_fg_read_only(method, "api/v2/log/memory/event/system")

    def test_paths_fora_do_prefixo_bloqueiam(self):
        for path in ("api/v2/cmdb", "logincheck", "api/v2/log",
                     "api/v2/monitor-x/system", "jsonrpc"):
            with self.assertRaises(SystemExit):
                assert_fg_read_only("GET", path)


class MaskKey(unittest.TestCase):
    def test_mascarada(self):
        out = mask_key("https://h/api/?type=op&key=ABCDEF0123456789&x=1")
        self.assertNotIn("ABCDEF0123456789", out)
        self.assertIn("MASCARADA", out)


class FortiClientAuth(unittest.TestCase):
    """O cliente exige credencial e mantém a trava GET-only nos dois modos."""

    def test_sem_credencial_aborta(self):
        from palib.fgclient import FortiClient
        with self.assertRaises(SystemExit):
            FortiClient("192.0.2.1")

    def test_modo_token_respeita_trava(self):
        from palib.fgclient import FortiClient
        client = FortiClient("192.0.2.1", token="x", dry_run=True)
        # path fora de monitor/cmdb/log aborta ANTES de qualquer rede (mesmo dry-run)
        with self.assertRaises(SystemExit):
            client.get("logincheck")
        with self.assertRaises(SystemExit):
            client.get("api/v2/backup")
        self.assertIsNone(client.get("log/memory/event/system"))  # log é leitura

    def test_modo_sessao_respeita_trava(self):
        from palib.fgclient import FortiClient
        # dry_run pula o login de rede; a trava continua valendo no get()
        client = FortiClient("192.0.2.1", username="admin", password="s",
                             dry_run=True)
        with self.assertRaises(SystemExit):
            client.get("jsonrpc")
        self.assertIsNone(client.get("monitor/system/status"))  # dry-run → None


if __name__ == "__main__":
    unittest.main()
