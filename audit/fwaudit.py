#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwaudit — auditoria da migração Palo Alto → FortiGate (TECE1).

Fases:
    offline      parse do snapshot PAN-OS local + checks A01–A22 (NÃO toca equipamento)
    pa-baseline  evidências operacionais "antes" no PA (só <show>, aba 09 do Plano)
    fg-snapshot  dump read-only da config+estado do FortiGate (GET, paginado)
    compare      paridade PA↔FG (checks C01–C12) a partir dos artefatos acima
    checks       lista os checks disponíveis

⛔ SÓ LEITURA. A garantia é mecânica: palib/readonly.py inspeciona cada
requisição e aborta o processo se ela não for GET/show. Não existe passagem de
comando arbitrário — todo comando enviado a equipamento é literal, escrito
neste repositório.

Credenciais SEMPRE via variável de ambiente (--key-env/--token-env apontam o
NOME da variável), nunca em argv. Python 3.6+, só stdlib.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from palib import VERSION  # noqa: E402
from palib import paxml, inventory, checks, report  # noqa: E402


def load_env_file(path):
    """Dotenv mínimo: KEY=VALUE, ignora comentários. Não sobrescreve o ambiente."""
    if not path or not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


def env_secret(var_name, what):
    value = os.environ.get(var_name or "", "")
    if not value:
        sys.exit("fwaudit: variável de ambiente %r vazia — exporte a %s nela "
                 "(nunca passe o segredo em argv)" % (var_name, what))
    return value


def cmd_offline(args):
    snap = args.snapshot or os.environ.get("SNAPSHOT_PATH", "")
    if not snap:
        sys.exit("fwaudit offline: informe --snapshot (ou SNAPSHOT_PATH no .env)")
    root, meta = paxml.load_snapshot(snap)
    inv = inventory.build_inventory(root, meta)
    results = checks.run_all(inv)
    paths = report.write_outputs(args.out, inv, results, html=not args.no_html)
    crit = sum(1 for r in results if r["severidade"] == "CRITICO")
    alto = sum(1 for r in results if r["severidade"] == "ALTO")
    print("fwaudit offline: %d checks (%d CRÍTICO, %d ALTO)"
          % (len(results), crit, alto))
    print("  relatório: %s" % paths["md"])
    if "html" in paths:
        print("  html:      %s" % paths["html"])
    print("  evidência: %s/checks/" % paths["dir"])


def cmd_pa_baseline(args):
    from palib.paclient import Firewall
    from palib import pabaseline
    key = env_secret(args.key_env, "chave de API do PA")
    fw = Firewall(args.host, key, verify=args.verify, dry_run=args.dry_run)
    outdir = pabaseline.collect_baseline(fw, args.out, hostname=args.hostname)
    if args.influx and not args.dry_run:
        from palib.influxpush import InfluxWriter
        writer = InfluxWriter.from_env()
        pabaseline.push_baseline(outdir, writer,
                                 hostname=args.hostname or args.host)
        print("  baseline publicado no bucket %s (mig_pa_baseline)" % writer.bucket)


def cmd_fg_snapshot(args):
    from palib.fgclient import FortiClient
    from palib import fgsnap
    if args.token_env:
        client = FortiClient(args.host, token=env_secret(args.token_env,
                                                         "token de API do FG"),
                             verify=args.verify, throttle=args.throttle,
                             dry_run=args.dry_run)
    elif args.user and args.pass_env:
        client = FortiClient(args.host, username=args.user,
                             password=env_secret(args.pass_env, "senha do admin FG"),
                             verify=args.verify, throttle=args.throttle,
                             dry_run=args.dry_run)
    else:
        sys.exit("fg-snapshot: informe --token-env OU --user + --pass-env "
                 "(a senha vai numa variável de ambiente, nunca em argv)")
    vdoms = [v.strip() for v in args.vdoms.split(",") if v.strip()]
    try:
        fgsnap.snapshot(client, vdoms, args.out, hostname=args.hostname)
    finally:
        client.logout()


def _parse_fg_side(spec):
    """'vsys1=/caminho[:vdom]' → (lado, (dir, vdom)). vdom default: root."""
    lado, _, resto = spec.partition("=")
    if lado not in ("vsys1", "vsys2") or not resto:
        sys.exit("fwaudit compare: --fg espera vsys1=DIR[:vdom] ou "
                 "vsys2=DIR[:vdom], recebeu %r" % spec)
    fg_dir, _, vdom = resto.partition(":")
    return lado, (fg_dir, vdom or "root")


def cmd_compare(args):
    from palib import compare
    sides = dict(_parse_fg_side(s) for s in (args.fg or []))
    fg_map = compare.make_fg_map(fg_dir=args.fg_dir,
                                 vsys1=sides.get("vsys1"),
                                 vsys2=sides.get("vsys2"))
    result = compare.run(args.inventory, fg_map, args.out)
    if args.influx:
        from palib.influxpush import InfluxWriter
        writer = InfluxWriter.from_env()
        compare.push_gaps(result, writer, site=args.site)
        print("  paridade publicada no bucket %s (mig_audit)" % writer.bucket)


def cmd_checks(_args):
    root_stub = None  # apenas listagem — não precisa de snapshot
    print("Checks offline (Fase A):")
    for fn in checks.ALL_CHECKS:
        doc = fn.__name__.replace("check_", "").upper().replace("_", " ")
        print("  %s" % doc)
    print("Checks de paridade (Fase C): C01..C12 — ver palib/compare.py")
    return root_stub


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="fwaudit",
        description="Auditoria read-only da migração PA→FG (v%s)" % VERSION)
    parser.add_argument("--env-file", default=".env",
                        help="arquivo KEY=VALUE opcional (default: .env)")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("offline", help="Fase A: auditoria do snapshot (sem equipamento)")
    p.add_argument("--snapshot", help="export XML do PAN-OS (fora do repo!)")
    p.add_argument("--out", default="out", help="diretório de saída (default: out/)")
    p.add_argument("--no-html", action="store_true")
    p.set_defaults(func=cmd_offline)

    p = sub.add_parser("pa-baseline", help="Fase B1: evidências 'antes' no PA (só <show>)")
    p.add_argument("--host", required=True)
    p.add_argument("--key-env", required=True, help="NOME da env var com a chave")
    p.add_argument("--hostname", default="", help="rótulo (default: host)")
    p.add_argument("--out", default="out")
    p.add_argument("--influx", action="store_true", help="publica resumo (mig_pa_baseline)")
    p.add_argument("--verify", action="store_true", help="valida certificado TLS")
    p.add_argument("--dry-run", action="store_true", help="imprime as URLs, não chama")
    p.set_defaults(func=cmd_pa_baseline)

    p = sub.add_parser("fg-snapshot", help="Fase B2: dump read-only do FortiGate")
    p.add_argument("--host", required=True)
    p.add_argument("--token-env", help="NOME da env var com o token de API (preferido)")
    p.add_argument("--user", help="admin p/ login por sessão (alternativa ao token)")
    p.add_argument("--pass-env", help="NOME da env var com a senha do admin")
    p.add_argument("--hostname", default="", help="rótulo (default: host)")
    p.add_argument("--vdoms", default="root,vsys2")
    p.add_argument("--out", default="out")
    p.add_argument("--throttle", type=float, default=0.3,
                   help="pausa entre requisições em s (default: 0.3)")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_fg_snapshot)

    p = sub.add_parser("compare", help="Fase C: paridade PA↔FG (C01–C12)")
    p.add_argument("--inventory", required=True, help="inventario.json da fase offline")
    p.add_argument("--fg", action="append", metavar="LADO=DIR[:vdom]",
                   help="topologia 2 clusters: --fg vsys1=<dir do fg-snapshot "
                        "INFRABASE> --fg vsys2=<dir do CLIENTE> (vdom default root)")
    p.add_argument("--fg-dir", help="modo legado: 1 FG multi-VDOM root+vsys2")
    p.add_argument("--out", default="out")
    p.add_argument("--site", default="TECE1")
    p.add_argument("--influx", action="store_true", help="publica contadores (mig_audit)")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("checks", help="lista os checks")
    p.set_defaults(func=cmd_checks)

    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1
    load_env_file(args.env_file)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
