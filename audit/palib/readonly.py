# -*- coding: utf-8 -*-
"""Trava de leitura — a garantia é mecânica, não documental.

Copiada de ferramentas/pa-forense/pa_forense.py (a referência do time), com a
adição da trava equivalente para o FortiGate. Qualquer requisição fora da lista
branca aborta o processo: aparecer um verbo de escrita aqui é erro de
programação deste repositório, não entrada de usuário.
"""

import re
import sys

# Verbos que alteram o equipamento (PAN-OS).
FORBIDDEN = (
    "set", "edit", "delete", "move", "rename", "commit", "load", "save",
    "import", "export", "restore", "request", "test", "clear", "debug",
    "fetch", "install", "disable", "enable",
)

ALLOWED_CONFIG_ACTIONS = ("get", "show")
ALLOWED_LOG_TYPES = ("config", "system", "threat", "traffic")


def assert_read_only(params):
    """Aborta se a requisição PAN-OS não for estritamente de leitura.

    Lista branca: só passa o que está explicitamente previsto aqui. Qualquer
    coisa fora disso é tratada como alteração, mesmo que seja inofensiva.
    """
    where = "fwaudit: requisição bloqueada pela trava de leitura"
    rtype = params.get("type")

    if rtype == "op":
        cmd = params.get("cmd", "")
        if not re.match(r"^\s*<show>.*</show>\s*$", cmd, re.DOTALL):
            sys.exit("%s — type=op só aceita <show>…</show>, recebeu: %.80s" % (where, cmd))
        for verb in FORBIDDEN:
            if "<%s>" % verb in cmd or "<%s " % verb in cmd:
                sys.exit("%s — verbo proibido <%s> em: %.80s" % (where, verb, cmd))

    elif rtype == "config":
        action = params.get("action")
        if action not in ALLOWED_CONFIG_ACTIONS:
            sys.exit("%s — type=config só aceita action=get|show, recebeu: %r" % (where, action))
        if "element" in params:
            sys.exit("%s — type=config com 'element' escreve configuração" % where)

    elif rtype == "log":
        log_type = params.get("log-type")
        action = params.get("action")
        if log_type is not None and log_type not in ALLOWED_LOG_TYPES:
            sys.exit("%s — log-type não previsto: %r" % (where, log_type))
        if action is not None and action != "get":
            sys.exit("%s — type=log só aceita action=get (poll), recebeu: %r" % (where, action))

    else:
        sys.exit("%s — type=%r não é de leitura (previstos: op, config, log)" % (where, rtype))

    return params


# Prefixos de API FortiOS permitidos. cmdb via GET é leitura de configuração;
# escrita em cmdb seria POST/PUT/DELETE — bloqueados pela checagem de método.
FG_ALLOWED_PREFIXES = ("api/v2/monitor/", "api/v2/cmdb/")


def assert_fg_read_only(method, path):
    """Aborta se a requisição FortiOS não for GET em monitor/ ou cmdb/."""
    where = "fwaudit: requisição FortiGate bloqueada pela trava de leitura"
    if method != "GET":
        sys.exit("%s — método %r (só GET é permitido)" % (where, method))
    clean = path.lstrip("/")
    for prefix in FG_ALLOWED_PREFIXES:
        if clean.startswith(prefix):
            return path
    sys.exit("%s — path fora de api/v2/{monitor,cmdb}: %.120s" % (where, path))


def mask_key(text):
    """Esconde chave de API PAN-OS em qualquer texto antes de imprimir ou gravar."""
    return re.sub(r"(key=)([^&\s]{6})[^&\s]*", r"\1\2…[MASCARADA]", text)
