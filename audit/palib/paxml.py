# -*- coding: utf-8 -*-
"""Navegação no snapshot XML do PAN-OS (export de configuração)."""

import hashlib
import os
import sys
import xml.etree.ElementTree as ET

DEVICE_XPATH = "./devices/entry[@name='localhost.localdomain']"


def load_snapshot(path):
    """Carrega o snapshot e devolve (root <config>, meta do arquivo).

    Valida que é um export PAN-OS; erro claro se não for.
    """
    if not os.path.isfile(path):
        sys.exit("fwaudit: snapshot não encontrado: %s" % path)
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        sys.exit("fwaudit: %s não é XML válido: %s" % (path, exc))
    if root.tag != "config" or not (root.get("version") or "").startswith("10."):
        sys.exit("fwaudit: %s não parece export PAN-OS 10.x (raiz <%s version=%r>)"
                 % (path, root.tag, root.get("version")))
    meta = {
        "path": os.path.abspath(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "mtime": int(os.path.getmtime(path)),
        "panos_version": root.get("detail-version") or root.get("version"),
    }
    return root, meta


def dev(root):
    """Elemento do device (localhost.localdomain)."""
    el = root.find(DEVICE_XPATH)
    if el is None:
        sys.exit("fwaudit: snapshot sem devices/entry[localhost.localdomain]")
    return el


def text(el, path, default=""):
    if el is None:
        return default
    value = el.findtext(path)
    if value is None:
        return default
    return value.strip()


def members(el, path):
    """Achata <member> em lista de strings. ['any'] quando o nó não existe.

    Mesmo problema que o palo-collector resolve em internal/configlog/diff.go
    (flatten): pertença é lista, não substring.
    """
    if el is None:
        return ["any"]
    node = el.find(path)
    if node is None:
        return ["any"]
    out = []
    for m in node.findall("member"):
        if m.text and m.text.strip():
            out.append(m.text.strip())
    return out or ["any"]


def iter_entries(parent, path):
    """Gerador (name, entry_el) de path + '/entry'."""
    if parent is None:
        return
    for entry in parent.findall(path + "/entry"):
        yield entry.get("name") or "", entry
