# -*- coding: utf-8 -*-
"""Cada check dispara no fixture (que contém 1 exemplar de cada risco)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from palib import paxml, inventory, checks

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "snapshot_mini.xml")


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root, meta = paxml.load_snapshot(FIXTURE)
        cls.inv = inventory.build_inventory(root, meta)
        cls.by_id = dict((c["id"], c) for c in checks.run_all(cls.inv))

    def itens(self, cid):
        return self.by_id[cid]["itens"]

    def test_todos_os_checks_rodaram(self):
        self.assertEqual(len(self.by_id), 22)

    def test_a01_edl(self):
        self.assertEqual([i["regra"] for i in self.itens("A01")], ["deny-edl-topo"])

    def test_a02_geo(self):
        self.assertEqual([i["regra"] for i in self.itens("A02")], ["allow-geo"])
        self.assertEqual(self.itens("A02")[0]["codigos"], ["EU"])

    def test_a03_appid(self):
        item = self.itens("A03")[0]
        self.assertEqual(item["regra"], "allow-appid")
        self.assertTrue(item["application_default"])

    def test_a04_anyany(self):
        nomes = [i["regra"] for i in self.itens("A04")]
        self.assertIn("allow-anyany", nomes)
        # deny com any/any não entra (só allow)
        self.assertNotIn("deny-edl-topo", nomes)

    def test_a05_userid(self):
        self.assertEqual([i["regra"] for i in self.itens("A05")], ["allow-userid"])

    def test_a06_sem_log(self):
        self.assertEqual([i["regra"] for i in self.itens("A06")], ["allow-sem-log"])

    def test_a07_sem_profile(self):
        nomes = [i["regra"] for i in self.itens("A07")]
        self.assertIn("deny-edl-topo", nomes)   # sem profile-setting
        self.assertIn("allow-fqdn", nomes)
        self.assertNotIn("allow-appid", nomes)  # tem profile group

    def test_a08_disabled(self):
        self.assertEqual([i["regra"] for i in self.itens("A08")],
                         ["regra-desabilitada"])

    def test_a09_fqdn(self):
        item = self.itens("A09")[0]
        self.assertEqual(item["regra"], "allow-fqdn")
        self.assertEqual(item["fqdns"][0]["fqdn"], "updates.example.com")

    def test_a10_checkmk(self):
        self.assertEqual(len(self.itens("A10")), 1)
        item = self.itens("A10")[0]
        self.assertEqual(item["mappedip"], "172.18.252.43/32")
        self.assertTrue(item["atencao"])  # DNAT para a gerência do próprio FG

    def test_a11_rotas(self):
        tipos = {}
        for i in self.itens("A11"):
            tipos.setdefault(i["tipo"], []).append(i)
        # rota para tunnel.99 que não existe
        self.assertEqual(tipos["rota_para_tunel_inexistente"][0]["rota"],
                         "rota-quebrada")
        # 10.1.1.0/24 via tunnel.1 coberta pela default (vaza se faltar) e pela
        # agregada 10.1.0.0/16 com saída divergente (shadow real)
        self.assertIn("vaza_pela_default_se_faltar", tipos)
        self.assertIn("especifica_sobrepoe_agregada", tipos)
        # TUN-SEM-ROTA (tunnel.2) não tem rota apontando para ele
        sem_rota = [i for i in self.itens("A11") if i["tipo"] == "tunel_sem_rota"]
        self.assertEqual(sem_rota[0]["interface"], "tunnel.2")

    def test_a12_zona_tunel(self):
        item = self.itens("A12")[0]
        self.assertEqual(item["zona"], "Z-VPN")
        self.assertEqual(item["inexistentes"], ["tunnel.88"])

    def test_a13_nomes(self):
        tipos = [i["tipo"] for i in self.itens("A13")]
        self.assertIn("mesmo_nome_valor_diferente", tipos)
        self.assertIn("nome_longo", tipos)

    def test_a14_ike(self):
        item = self.itens("A14")[0]
        self.assertEqual(item["gateway"], "GW-PEER-A")
        self.assertEqual(item["psk"], "sim")

    def test_a15_gerencia(self):
        tipos = dict((i["tipo"], i) for i in self.itens("A15"))
        self.assertEqual(tipos["syslog"]["destino"], "172.18.100.2:9001/TCP")
        self.assertEqual(tipos["snmp"]["versao"], "v2c")

    def test_a16_certs(self):
        item = self.itens("A16")[0]
        self.assertEqual(item["cert"], "certificate_EDL-Edges")
        self.assertEqual(item["uso_edl"], "sim")

    def test_a20_nat_classes(self):
        classes = dict((i["regra"], i["classe"]) for i in self.itens("A20"))
        self.assertEqual(classes["DNAT-monitor-cmk"], "dnat")
        self.assertEqual(classes["SNAT-saida"], "snat-dipp")

    def test_a21_denies_topo(self):
        self.assertEqual([i["regra"] for i in self.itens("A21")], ["deny-edl-topo"])

    def test_severidade_ordena(self):
        ordem = [c["severidade"] for c in checks.run_all(self.inv)]
        vistos = [checks.SEV_ORDER[s] for s in ordem]
        self.assertEqual(vistos, sorted(vistos))


if __name__ == "__main__":
    unittest.main()
