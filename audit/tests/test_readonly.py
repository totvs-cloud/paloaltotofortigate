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
    def test_get_monitor_e_cmdb_passam(self):
        assert_fg_read_only("GET", "api/v2/monitor/system/status")
        assert_fg_read_only("GET", "/api/v2/cmdb/firewall/policy")

    def test_metodos_de_escrita_bloqueiam(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.assertRaises(SystemExit):
                assert_fg_read_only(method, "api/v2/monitor/system/status")

    def test_paths_fora_do_prefixo_bloqueiam(self):
        for path in ("api/v2/cmdb", "logincheck", "api/v2/log/memory",
                     "api/v2/monitor-x/system", "jsonrpc"):
            with self.assertRaises(SystemExit):
                assert_fg_read_only("GET", path)


class MaskKey(unittest.TestCase):
    def test_mascarada(self):
        out = mask_key("https://h/api/?type=op&key=ABCDEF0123456789&x=1")
        self.assertNotIn("ABCDEF0123456789", out)
        self.assertIn("MASCARADA", out)


if __name__ == "__main__":
    unittest.main()
