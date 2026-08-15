# -*- coding: utf-8 -*-
"""Fase C contra um FG sintético: 1 match e 1 falta em cada categoria chave.

Usa o modo legado (1 diretório multi-VDOM root+vsys2) via make_fg_map(fg_dir=…);
a classe TwoClusters cobre o mapa de 2 clusters da topologia real do TECE1."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from palib import paxml, inventory, compare

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "snapshot_mini.xml")


def write_json(base, vdom, name, results):
    d = os.path.join(base, vdom)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name + ".json"), "w", encoding="utf-8") as fh:
        json.dump({"results": results}, fh)


class Compare(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root, meta = paxml.load_snapshot(FIXTURE)
        cls.inv = inventory.build_inventory(root, meta)
        cls.fg = tempfile.mkdtemp(prefix="fgsnap-test-")
        # root: rota 10.1.1.0/24 presente; default e demais ausentes
        write_json(cls.fg, "root", "cmdb_router_static",
                   [{"dst": "10.1.1.0 255.255.255.0", "device": "VPN-CLIENT-A",
                     "gateway": "0.0.0.0"}])
        # VIP do Check_MK presente (extip sem máscara, mappedip em range)
        write_json(cls.fg, "root", "cmdb_firewall_vip",
                   [{"name": "VIP_DNAT-monitor-cmk", "extip": "172.27.53.99",
                     "mappedip": [{"range": "172.18.252.43"}]}])
        # 2 das 7 VPNs InfraBase criadas
        write_json(cls.fg, "root", "cmdb_vpn_ipsec_phase1-interface",
                   [{"name": "VPN_TESP03_P1"}, {"name": "VPN_TESP6"},
                    {"name": "CBL3SH-F1-01"}])
        # zonas: Z-WAN existe, Z-VPN não
        write_json(cls.fg, "root", "cmdb_system_zone", [{"name": "Z-WAN"}])
        # policies: 1 logando com UTM, 1 sem log
        write_json(cls.fg, "root", "cmdb_firewall_policy",
                   [{"policyid": 1, "status": "enable", "logtraffic": "all",
                     "utm-status": "enable", "ips-sensor": "default",
                     "nat": "enable"},
                    {"policyid": 2, "status": "enable", "logtraffic": "disable"}])
        # syslog certo
        write_json(cls.fg, "root", "cmdb_log_syslogd_setting",
                   [{"server": "172.18.100.2", "port": 9001, "status": "enable"}])
        # address: um dos objetos com sufixo _1 (tolerância FC-10)
        write_json(cls.fg, "root", "cmdb_firewall_address",
                   [{"name": "HST-10.9.9.9_1"}, {"name": "DUP-OBJ"}])
        # ippool cobre o SNAT
        write_json(cls.fg, "root", "cmdb_firewall_ippool",
                   [{"name": "ippool-saida", "startip": "198.51.100.2",
                     "endip": "198.51.100.2"}])
        # interface global: só a vlan 100
        gdir = os.path.join(cls.fg, "_global")
        os.makedirs(gdir, exist_ok=True)
        with open(os.path.join(gdir, "cmdb_system_interface.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"results": [{"name": "vlan_100", "vlanid": 100,
                                    "ip": "198.51.100.1 255.255.255.248"}]}, fh)
        # vsys2 vazio (nada coletado)
        os.makedirs(os.path.join(cls.fg, "vsys2"), exist_ok=True)

        fg_map = compare.make_fg_map(fg_dir=cls.fg)
        cls.by_id = dict((r["id"], r) for r in compare.run_checks(cls.inv, fg_map))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.fg, ignore_errors=True)

    def test_c01_rotas(self):
        r = self.by_id["C01"]
        self.assertEqual(r["pa_count"], 4)
        self.assertEqual(r["matched"], 1)          # 10.1.1.0/24
        self.assertEqual(r["missing_fg_total"], 3)  # default, agregada, quebrada

    def test_c02_vip(self):
        r = self.by_id["C02"]
        self.assertEqual(r["pa_count"], 1)
        self.assertEqual(r["matched"], 1)
        self.assertEqual(r["missing_fg_total"], 0)

    def test_c03_vpns(self):
        r = self.by_id["C03"]
        self.assertEqual(r["matched"], 2)           # TESP03_P1 + TESP6
        self.assertEqual(r["missing_fg_total"], 5)
        cbl = [i for i in r["itens"] if "CBL3SH" in i["vpn_fg"]][0]
        self.assertEqual(cbl["no_fg"], "1")

    def test_c04_interfaces(self):
        r = self.by_id["C04"]
        self.assertEqual(r["pa_count"], 3)          # 2 subifs + 1 loopback
        self.assertEqual(r["matched"], 1)           # ae1.100 (vlan+ip)
        self.assertEqual(r["missing_fg_total"], 2)

    def test_c05_zonas(self):
        r = self.by_id["C05"]
        self.assertEqual(r["matched"], 1)
        missing = " ".join(r["missing_fg"])
        self.assertIn("Z-VPN", missing)
        self.assertIn("Z2-EXT", missing)

    def test_c07_logtraffic(self):
        r = self.by_id["C07"]
        self.assertEqual(r["matched"], 1)           # 1 de 2 com logtraffic all
        self.assertEqual(r["missing_fg"][0][:6], "1 de 2")

    def test_c08_utm(self):
        r = self.by_id["C08"]
        self.assertEqual(r["matched"], 1)
        self.assertEqual(r["missing_fg_total"], 0)  # há pelo menos 1 com UTM

    def test_c09_objetos_sufixo(self):
        r = self.by_id["C09"]
        # No lado infrabase(root): HST-10.9.9.9 casa via sufixo _1 e DUP-OBJ
        # casa direto. (vsys2 está vazio de propósito — lá tudo falta mesmo.)
        faltando_root = " ".join(m for m in r["missing_fg"]
                                 if m.startswith("infrabase(root):"))
        self.assertNotIn("HST-10.9.9.9", faltando_root)
        self.assertNotIn("infrabase(root): DUP-OBJ", faltando_root)

    def test_c10_edl(self):
        r = self.by_id["C10"]
        self.assertEqual(r["missing_fg"], ["EDL-Test"])

    def test_c11_snat(self):
        r = self.by_id["C11"]
        self.assertEqual(r["pa_count"], 1)
        self.assertEqual(r["matched"], 1)

    def test_c12_mgmt(self):
        r = self.by_id["C12"]
        faltando = " ".join(r["missing_fg"])
        self.assertNotIn("syslog", faltando)        # syslog OK
        self.assertIn("dns", faltando)              # dns/ntp/snmp ausentes

    def test_c13_mss_faltando(self):
        r = self.by_id["C13"]
        # ae1.100 tem clamp no PA; a vlan_100 do FG existe mas SEM tcp-mss
        self.assertEqual(r["pa_count"], 1)
        self.assertEqual(r["matched"], 0)
        self.assertIn("ae1.100", " ".join(r["missing_fg"]))
        self.assertIn("SEM tcp-mss", " ".join(r["missing_fg"]))

    def test_c16_default_route(self):
        r = self.by_id["C16"]
        # default do VR Externo_Infrabase via 198.51.100.6; FG sem default
        self.assertEqual(r["pa_count"], 1)
        self.assertEqual(r["matched"], 0)
        self.assertIn("198.51.100.6", " ".join(r["missing_fg"]))

    def test_c17_pbf(self):
        r = self.by_id["C17"]
        self.assertEqual(r["pa_count"], 1)
        self.assertIn("pbf-forca-tunel", " ".join(r["missing_fg"]))


class TwoClusters(unittest.TestCase):
    """Topologia real do TECE1: vsys1→cluster INFRABASE, vsys2→cluster CLIENTE,
    cada um no seu diretório de fg-snapshot, ambos vdom root."""

    @classmethod
    def setUpClass(cls):
        root, meta = paxml.load_snapshot(FIXTURE)
        cls.inv = inventory.build_inventory(root, meta)
        cls.dir_infra = tempfile.mkdtemp(prefix="fg-infra-")
        cls.dir_cli = tempfile.mkdtemp(prefix="fg-cli-")
        # rota do VR Externo_Infrabase existe no cluster INFRABASE
        write_json(cls.dir_infra, "root", "cmdb_router_static",
                   [{"dst": "10.1.1.0 255.255.255.0", "device": "VPN-CLIENT-A"}])
        # VPN de cliente existe no cluster CLIENTE
        write_json(cls.dir_cli, "root", "cmdb_vpn_ipsec_phase1-interface",
                   [{"name": "CBL3SH-F1-01"}])
        # interfaces globais divididas entre os dois clusters
        for d, vlanid, ip in ((cls.dir_infra, 100, "198.51.100.1 255.255.255.248"),):
            gdir = os.path.join(d, "_global")
            os.makedirs(gdir, exist_ok=True)
            with open(os.path.join(gdir, "cmdb_system_interface.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"results": [{"name": "vlan_%d" % vlanid,
                                        "vlanid": vlanid, "ip": ip}]}, fh)
        fg_map = compare.make_fg_map(vsys1=(cls.dir_infra, "root"),
                                     vsys2=(cls.dir_cli, "root"))
        cls.by_id = dict((r["id"], r) for r in compare.run_checks(cls.inv, fg_map))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir_infra, ignore_errors=True)
        shutil.rmtree(cls.dir_cli, ignore_errors=True)

    def test_c01_rota_no_lado_certo(self):
        r = self.by_id["C01"]
        self.assertEqual(r["matched"], 1)            # 10.1.1.0/24 no INFRABASE
        faltando = " ".join(r["missing_fg"])
        self.assertIn("infrabase(root)", faltando)   # default/agregada/quebrada

    def test_c03_vpn_cliente_contada(self):
        r = self.by_id["C03"]
        cbl = [i for i in r["itens"] if "CBL3SH" in i["vpn_fg"]][0]
        self.assertEqual(cbl["no_fg"], "1")          # veio do cluster CLIENTE

    def test_c04_interfaces_somadas_dos_dois(self):
        r = self.by_id["C04"]
        self.assertEqual(r["matched"], 1)            # vlan 100 no INFRABASE


if __name__ == "__main__":
    unittest.main()
