# -*- coding: utf-8 -*-
"""Parsers contra o fixture sintético — e a garantia de que segredo não entra."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from palib import paxml, inventory

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "snapshot_mini.xml")


def load():
    root, meta = paxml.load_snapshot(FIXTURE)
    return inventory.build_inventory(root, meta)


class Inventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = load()

    def test_meta(self):
        self.assertEqual(self.inv["meta"]["mgmt"]["hostname"], "FW-FIXTURE")
        self.assertEqual(self.inv["meta"]["mgmt"]["mgmt_ip"], "192.0.2.10")
        self.assertTrue(self.inv["meta"]["ha"]["enabled"])
        self.assertEqual(self.inv["meta"]["ha"]["group_id"], "7")
        self.assertEqual(self.inv["meta"]["vsys"]["vsys1"]["display_name"],
                         "Fixture-VSYS1")

    def test_interfaces(self):
        ifs = self.inv["network"]["interfaces"]
        self.assertEqual(ifs["aggregate"]["ae1"]["members"],
                         ["ethernet1/1", "ethernet1/2"])
        self.assertEqual(len(ifs["aggregate"]["ae1"]["subifs"]), 2)
        self.assertEqual(ifs["ha_ports"], ["ethernet1/11"])
        self.assertEqual(sorted(ifs["tunnel_units"]), ["tunnel.1", "tunnel.2"])

    def test_rules(self):
        self.assertEqual(len(self.inv["vsys1"]["security_rules"]), 8)
        self.assertEqual(len(self.inv["vsys2"]["security_rules"]), 1)
        r1 = self.inv["vsys1"]["security_rules"][0]
        self.assertEqual(r1["name"], "deny-edl-topo")
        self.assertEqual(r1["position"], 1)
        self.assertEqual(r1["source"], ["EDL-Test"])
        disabled = [r for r in self.inv["vsys1"]["security_rules"] if r["disabled"]]
        self.assertEqual([r["name"] for r in disabled], ["regra-desabilitada"])

    def test_nat(self):
        nats = self.inv["vsys1"]["nat_rules"]
        self.assertEqual(len(nats), 2)
        dnat = nats[0]
        self.assertEqual(dnat["dnat_address"], "172.18.252.43/32")
        snat = nats[1]
        self.assertEqual(snat["snat_type"], "dynamic-ip-and-port")
        self.assertEqual(snat["snat_translated"], ["198.51.100.2"])

    def test_routes_e_vpn(self):
        self.assertEqual(len(self.inv["network"]["static_routes"]["Externo_Infrabase"]), 4)
        self.assertEqual(len(self.inv["network"]["ike_gateways"]), 1)
        self.assertEqual(len(self.inv["network"]["ipsec_tunnels"]), 2)
        gw = self.inv["network"]["ike_gateways"][0]
        self.assertTrue(gw["has_psk"])

    def test_edl_e_syslog(self):
        self.assertEqual(len(self.inv["edls"]), 1)
        self.assertEqual(self.inv["edls"][0]["certificate_profile"],
                         "certificate_EDL-Edges")
        targets = self.inv["meta"]["mgmt"]["syslog_targets"]
        self.assertEqual(targets[0]["server"], "172.18.100.2")
        self.assertEqual(targets[0]["port"], "9001")

    def test_segredos_nunca_entram(self):
        blob = json.dumps(self.inv, ensure_ascii=False)
        self.assertNotIn("SUPERSECRETPSK", blob)   # PSK do IKE gateway
        self.assertNotIn("COMMUNITY123", blob)     # community SNMP
        self.assertNotIn("FAKEHASH", blob)         # phash de admin
        self.assertIn("<REDIGIDO>", blob)


if __name__ == "__main__":
    unittest.main()
