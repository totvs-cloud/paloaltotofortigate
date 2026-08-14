# -*- coding: utf-8 -*-
"""Inventário estruturado do snapshot PAN-OS.

Cada parse_* devolve estruturas JSON-serializáveis. Segredos (PSK, community
SNMP, phash de usuários) são substituídos por REDACTED **aqui, na origem** —
não é filtro de saída: os valores nunca entram nas estruturas retornadas
(mesma filosofia do palo-collector internal/configlog/redact.go).
"""

from . import REDACTED
from .paxml import dev, text, members, iter_entries

VSYS_LIST = ("vsys1", "vsys2")


# ---------------------------------------------------------------------------
# Rede
# ---------------------------------------------------------------------------

def parse_interfaces(root):
    d = dev(root)
    net = d.find("network/interface")
    out = {"aggregate": {}, "ha_ports": [], "loopbacks": [], "tunnel_units": [],
           "ethernet": {}}
    if net is None:
        return out

    for name, entry in iter_entries(net, "ethernet"):
        agg = text(entry, "aggregate-group")
        is_ha = entry.find("ha") is not None
        out["ethernet"][name] = {"aggregate_group": agg, "ha": is_ha}
        if is_ha:
            out["ha_ports"].append(name)

    for ae_name, ae in iter_entries(net, "aggregate-ethernet"):
        subifs = []
        for sub_name, sub in iter_entries(ae, "layer3/units"):
            ips = [ip_name for ip_name, _ in iter_entries(sub, "ip")]
            subifs.append({
                "name": sub_name,
                "vlan": text(sub, "tag"),
                "ips": ips,
                "comment": text(sub, "comment"),
            })
        phys = [n for n, e in out["ethernet"].items()
                if e["aggregate_group"] == ae_name]
        out["aggregate"][ae_name] = {"members": sorted(phys), "subifs": subifs}

    for lo_name, lo in iter_entries(net, "loopback/units"):
        ips = [ip_name for ip_name, _ in iter_entries(lo, "ip")]
        out["loopbacks"].append({"name": lo_name, "ips": ips,
                                 "comment": text(lo, "comment")})

    for tu_name, _tu in iter_entries(net, "tunnel/units"):
        out["tunnel_units"].append(tu_name)

    return out


def parse_zones(root, vsys):
    d = dev(root)
    ventry = d.find("vsys/entry[@name='%s']" % vsys)
    zones = {}
    for zname, zentry in iter_entries(ventry, "zone"):
        ifaces = []
        layer3 = zentry.find("network/layer3")
        if layer3 is not None:
            ifaces = [m.text.strip() for m in layer3.findall("member")
                      if m.text and m.text.strip()]
        zones[zname] = ifaces
    return zones


def parse_static_routes(root):
    d = dev(root)
    out = {}
    for vr_name, vr in iter_entries(d, "network/virtual-router"):
        routes = []
        for r_name, r in iter_entries(vr, "routing-table/ip/static-route"):
            routes.append({
                "name": r_name,
                "destination": text(r, "destination"),
                "interface": text(r, "interface"),
                "nexthop_ip": text(r, "nexthop/ip-address"),
                "next_vr": text(r, "nexthop/next-vr"),
                "metric": text(r, "metric", "10"),
            })
        out[vr_name] = routes
    return out


def parse_ike_gateways(root):
    d = dev(root)
    gws = []
    for name, g in iter_entries(d, "network/ike/gateway"):
        has_psk = g.find("authentication/pre-shared-key/key") is not None
        version = text(g, "protocol/version", "ikev1")
        gws.append({
            "name": name,
            "peer_ip": text(g, "peer-address/ip"),
            "local_ip": text(g, "local-address/ip"),
            "local_interface": text(g, "local-address/interface"),
            "version": version,
            "psk": REDACTED if has_psk else "",
            "has_psk": has_psk,
        })
    return gws


def parse_ipsec_tunnels(root):
    d = dev(root)
    tunnels = []
    for name, t in iter_entries(d, "network/tunnel/ipsec"):
        gw = ""
        for gw_name, _ in iter_entries(t, "auto-key/ike-gateway"):
            gw = gw_name
        proxy_ids = [p_name for p_name, _ in iter_entries(t, "auto-key/proxy-id")]
        tunnels.append({
            "name": name,
            "tunnel_interface": text(t, "tunnel-interface"),
            "ike_gateway": gw,
            "proxy_id_count": len(proxy_ids),
            "monitor_enabled": text(t, "tunnel-monitor/enable") == "yes",
        })
    return tunnels


def parse_crypto_profiles(root):
    d = dev(root)
    out = {"ike": [], "ipsec": []}
    for name, p in iter_entries(d, "network/ike/crypto-profiles/ike-crypto-profiles"):
        out["ike"].append({
            "name": name,
            "dh_group": members(p, "dh-group"),
            "encryption": members(p, "encryption"),
            "hash": members(p, "hash"),
            "lifetime_h": text(p, "lifetime/hours"),
        })
    for name, p in iter_entries(d, "network/ike/crypto-profiles/ipsec-crypto-profiles"):
        out["ipsec"].append({
            "name": name,
            "dh_group": text(p, "dh-group"),
            "encryption": members(p, "esp/encryption"),
            "auth": members(p, "esp/authentication"),
            "lifetime_h": text(p, "lifetime/hours"),
        })
    return out


def parse_ha(root):
    d = dev(root)
    ha = d.find("deviceconfig/high-availability")
    if ha is None:
        return {"enabled": False}
    links = {}
    for link in ("ha1", "ha1-backup", "ha2", "ha2-backup"):
        el = ha.find("interface/%s" % link)
        if el is not None:
            links[link] = {"port": text(el, "port"), "ip": text(el, "ip-address"),
                           "netmask": text(el, "netmask")}
    return {
        "enabled": text(ha, "enabled") == "yes",
        "group_id": text(ha, "group/group-id"),
        "peer_ip": text(ha, "group/peer-ip"),
        "peer_ip_backup": text(ha, "group/peer-ip-backup"),
        "links": links,
    }


# ---------------------------------------------------------------------------
# Objetos e rulebase
# ---------------------------------------------------------------------------

def _scope_el(root, scope):
    if scope == "shared":
        return root.find("shared")
    return dev(root).find("vsys/entry[@name='%s']" % scope)


def parse_objects(root, scope):
    """Objetos de um escopo ('shared', 'vsys1', 'vsys2')."""
    el = _scope_el(root, scope)
    out = {"address": {}, "address_group": {}, "service": {}, "service_group": {},
           "tag_count": 0}
    if el is None:
        return out

    for name, a in iter_entries(el, "address"):
        if a.find("ip-netmask") is not None:
            typ, value = "ip-netmask", text(a, "ip-netmask")
        elif a.find("ip-range") is not None:
            typ, value = "ip-range", text(a, "ip-range")
        elif a.find("fqdn") is not None:
            typ, value = "fqdn", text(a, "fqdn")
        else:
            typ, value = "other", ""
        out["address"][name] = {"type": typ, "value": value}

    for name, g in iter_entries(el, "address-group"):
        static = g.find("static")
        if static is not None:
            out["address_group"][name] = {
                "type": "static",
                "members": [m.text.strip() for m in static.findall("member")
                            if m.text and m.text.strip()],
            }
        else:
            out["address_group"][name] = {"type": "dynamic",
                                          "filter": text(g, "dynamic/filter")}

    for name, s in iter_entries(el, "service"):
        proto, port = "", ""
        for p in ("tcp", "udp"):
            node = s.find("protocol/%s" % p)
            if node is not None:
                proto, port = p, text(node, "port")
                break
        out["service"][name] = {"protocol": proto, "port": port}

    for name, g in iter_entries(el, "service-group"):
        out["service_group"][name] = [m.text.strip()
                                      for m in g.findall("members/member")
                                      if m.text and m.text.strip()]

    out["tag_count"] = len(list(iter_entries(el, "tag")))
    return out


def parse_edls(root):
    """External Dynamic Lists — shared e por vsys (no 10.2 do TECE1 estão em shared)."""
    edls = []
    scopes = [("shared", root.find("shared"))]
    for vsys in VSYS_LIST:
        scopes.append((vsys, _scope_el(root, vsys)))
    for scope, el in scopes:
        if el is None:
            continue
        for name, e in iter_entries(el, "external-list"):
            etype, url, recurring, cert = "", "", "", ""
            type_el = e.find("type")
            if type_el is not None and len(type_el):
                sub = type_el[0]
                etype = sub.tag
                url = text(sub, "url")
                cert = text(sub, "certificate-profile")
                rec = sub.find("recurring")
                if rec is not None and len(rec):
                    recurring = rec[0].tag
            edls.append({"name": name, "scope": scope, "type": etype,
                         "url": url, "recurring": recurring,
                         "certificate_profile": cert})
    return edls


def _profile_summary(entry):
    """Resumo do profile-setting de uma regra: ('group', [nomes]) | ('profiles', [tipos]) | ('none', [])."""
    ps = entry.find("profile-setting")
    if ps is None:
        return "none", []
    group = ps.find("group")
    if group is not None:
        names = [m.text.strip() for m in group.findall("member")
                 if m.text and m.text.strip()]
        return "group", names
    profiles = ps.find("profiles")
    if profiles is not None:
        return "profiles", sorted(child.tag for child in profiles)
    return "none", []


def parse_security_rules(root, vsys):
    ventry = _scope_el(root, vsys)
    rules = []
    pos = 0
    if ventry is None:
        return rules
    for name, r in iter_entries(ventry, "rulebase/security/rules"):
        pos += 1
        ptype, pnames = _profile_summary(r)
        rules.append({
            "position": pos,
            "name": name,
            "uuid": r.get("uuid", ""),
            "disabled": text(r, "disabled") == "yes",
            "action": text(r, "action"),
            "from": members(r, "from"),
            "to": members(r, "to"),
            "source": members(r, "source"),
            "destination": members(r, "destination"),
            "source_user": members(r, "source-user"),
            "application": members(r, "application"),
            "service": members(r, "service"),
            "category": members(r, "category"),
            "log_setting": text(r, "log-setting"),
            "log_start": text(r, "log-start") == "yes",
            "log_end": text(r, "log-end", "yes") != "no",
            "profile_type": ptype,
            "profiles": pnames,
            "negate_source": text(r, "negate-source") == "yes",
            "negate_destination": text(r, "negate-destination") == "yes",
            "tags": [] if members(r, "tag") == ["any"] else members(r, "tag"),
        })
    return rules


def parse_nat_rules(root, vsys):
    ventry = _scope_el(root, vsys)
    rules = []
    pos = 0
    if ventry is None:
        return rules
    for name, r in iter_entries(ventry, "rulebase/nat/rules"):
        pos += 1
        st = r.find("source-translation")
        snat_type = ""
        snat_translated = []
        if st is not None:
            if st.find("dynamic-ip-and-port") is not None:
                snat_type = "dynamic-ip-and-port"
                snat_translated = members(st, "dynamic-ip-and-port/translated-address")
                if snat_translated == ["any"]:
                    iface = text(st, "dynamic-ip-and-port/interface-address/interface")
                    snat_translated = ["interface:%s" % iface] if iface else []
            elif st.find("static-ip") is not None:
                snat_type = "static-ip"
                snat_translated = [text(st, "static-ip/translated-address")]
            elif st.find("dynamic-ip") is not None:
                snat_type = "dynamic-ip"
                snat_translated = members(st, "dynamic-ip/translated-address")
        rules.append({
            "position": pos,
            "name": name,
            "disabled": text(r, "disabled") == "yes",
            "from": members(r, "from"),
            "to": members(r, "to"),
            "source": members(r, "source"),
            "destination": members(r, "destination"),
            "service": text(r, "service", "any"),
            "to_interface": text(r, "to-interface", "any"),
            "dnat_address": text(r, "destination-translation/translated-address"),
            "dnat_port": text(r, "destination-translation/translated-port"),
            "snat_type": snat_type,
            "snat_translated": snat_translated,
            "bidirectional": text(r, "source-translation/static-ip/bi-directional") == "yes",
        })
    return rules


def parse_pbf_rules(root, vsys):
    ventry = _scope_el(root, vsys)
    rules = []
    if ventry is None:
        return rules
    for name, r in iter_entries(ventry, "rulebase/pbf/rules"):
        rules.append({
            "name": name,
            "disabled": text(r, "disabled") == "yes",
            "from": members(r, "from"),
            "source": members(r, "source"),
            "destination": members(r, "destination"),
            "egress_interface": text(r, "action/forward/egress-interface"),
            "nexthop": text(r, "action/forward/nexthop/ip-address"),
        })
    return rules


# ---------------------------------------------------------------------------
# Gerência e metadados
# ---------------------------------------------------------------------------

def parse_mgmt_deps(root):
    d = dev(root)
    sysel = d.find("deviceconfig/system")
    snmp = {"enabled": False, "version": "", "community": ""}
    if sysel is not None and sysel.find("snmp-setting") is not None:
        snmp["enabled"] = True
        if sysel.find("snmp-setting/access-setting/version/v2c") is not None:
            snmp["version"] = "v2c"
            if text(sysel, "snmp-setting/access-setting/version/v2c/snmp-community-string"):
                snmp["community"] = REDACTED
        elif sysel.find("snmp-setting/access-setting/version/v3") is not None:
            snmp["version"] = "v3"

    syslog_targets = []
    shared = root.find("shared")
    if shared is not None:
        for prof_name, prof in iter_entries(shared, "log-settings/syslog"):
            for srv_name, srv in iter_entries(prof, "server"):
                syslog_targets.append({
                    "profile": prof_name,
                    "server_entry": srv_name,
                    "server": text(srv, "server"),
                    "port": text(srv, "port"),
                    "transport": text(srv, "transport"),
                    "format": text(srv, "format"),
                })

    log_profiles = {}
    for vsys in VSYS_LIST:
        ventry = _scope_el(root, vsys)
        names = [n for n, _ in iter_entries(ventry, "log-settings/profiles")]
        log_profiles[vsys] = names

    return {
        "hostname": text(sysel, "hostname"),
        "mgmt_ip": text(sysel, "ip-address"),
        "timezone": text(sysel, "timezone"),
        "dns": [text(sysel, "dns-setting/servers/primary"),
                text(sysel, "dns-setting/servers/secondary")],
        "ntp": [text(sysel, "ntp-servers/primary-ntp-server/ntp-server-address"),
                text(sysel, "ntp-servers/secondary-ntp-server/ntp-server-address")],
        "snmp": snmp,
        "syslog_targets": syslog_targets,
        "log_forwarding_profiles": log_profiles,
    }


def parse_certificates(root):
    certs = []
    shared = root.find("shared")
    for name, c in iter_entries(shared, "certificate"):
        certs.append({
            "name": name,
            "not_valid_after": text(c, "not-valid-after"),
            "subject": text(c, "subject"),
            "ca": text(c, "ca") == "yes",
        })
    return certs


def parse_vsys_meta(root):
    d = dev(root)
    out = {}
    for vsys, ventry in iter_entries(d, "vsys"):
        imported = []
        imp = ventry.find("import/network/interface")
        if imp is not None:
            imported = [m.text.strip() for m in imp.findall("member")
                        if m.text and m.text.strip()]
        out[vsys] = {"display_name": text(ventry, "display-name"),
                     "interfaces": imported}
    return out


# ---------------------------------------------------------------------------
# Inventário completo
# ---------------------------------------------------------------------------

def build_inventory(root, file_meta=None):
    inv = {
        "meta": {
            "file": file_meta or {},
            "mgmt": parse_mgmt_deps(root),
            "vsys": parse_vsys_meta(root),
            "ha": parse_ha(root),
        },
        "network": {
            "interfaces": parse_interfaces(root),
            "static_routes": parse_static_routes(root),
            "ike_gateways": parse_ike_gateways(root),
            "ipsec_tunnels": parse_ipsec_tunnels(root),
            "crypto_profiles": parse_crypto_profiles(root),
        },
        "shared": {"objects": parse_objects(root, "shared")},
        "edls": parse_edls(root),
        "certificates": parse_certificates(root),
    }
    for vsys in VSYS_LIST:
        inv[vsys] = {
            "zones": parse_zones(root, vsys),
            "security_rules": parse_security_rules(root, vsys),
            "nat_rules": parse_nat_rules(root, vsys),
            "pbf_rules": parse_pbf_rules(root, vsys),
            "objects": parse_objects(root, vsys),
        }
    return inv
