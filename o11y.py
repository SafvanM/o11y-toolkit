#!/usr/bin/env python3
"""O11y Toolkit: detector operations for Splunk Observability Cloud.

Every write command is a DRY RUN unless --apply is given.
Run `python o11y.py <command> -h` for help on any command.
"""
import argparse
import json
import sys
from pathlib import Path

from config.settings import load_settings
from core.client import ApiError, O11yClient
from core.safety import Safety
from modules.detectors import (
    DetectorService, mut_add_recipient, mut_add_tag, mut_add_team,
    mut_remove_recipient, mut_remove_tag, mut_remove_team,
    mut_replace_recipient, parse_recipient,
)

SEVERITIES = ["Critical", "Major", "Minor", "Warning", "Info"]
WRITE_COMMANDS = {
    "add-recipient", "remove-recipient", "replace-recipient", "add-team",
    "remove-team", "add-tag", "remove-tag", "enable", "disable", "delete",
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="o11y", description="Splunk O11y detector toolkit (dry run by default)")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    sel = argparse.ArgumentParser(add_help=False)
    g = sel.add_argument_group("detector selection (combine to narrow down)")
    g.add_argument("--id", action="append", dest="ids", help="detector ID (repeatable)")
    g.add_argument("--ids-file", help="file with one detector ID per line")
    g.add_argument("--name", help="name contains (case-insensitive)")
    g.add_argument("--prefix", help="name starts with (case-sensitive)")
    g.add_argument("--regex", help="name matches regular expression")
    g.add_argument("--tag", action="append", dest="tags", help="has tag (repeatable)")
    g.add_argument("--all", action="store_true", dest="select_all",
                   help="required to run a write command on ALL detectors")

    act = argparse.ArgumentParser(add_help=False)
    a = act.add_argument_group("execution")
    a.add_argument("--apply", action="store_true", help="actually make the change")
    a.add_argument("--yes", action="store_true",
                   help="skip confirmation (ignored in PROD orgs)")
    a.add_argument("--show-diff", action="store_true", help="print JSON diff per detector")

    sev = argparse.ArgumentParser(add_help=False)
    sev.add_argument("--severity", choices=SEVERITIES,
                     help="only touch rules with this severity")

    sub.add_parser("ping", help="check token, realm and connectivity")
    sub.add_parser("list", parents=[sel], help="list matching detectors")
    gp = sub.add_parser("get", help="print one detector as JSON")
    gp.add_argument("--id", required=True)
    sub.add_parser("report", parents=[sel], help="hygiene report to CSV")
    ep = sub.add_parser("export", parents=[sel], help="export detectors to JSON files")
    ep.add_argument("--out", help="output folder")

    r = "recipient spec, e.g. email:a@b.com | team:ID | slack:CRED_ID:channel"
    p1 = sub.add_parser("add-recipient", parents=[sel, act, sev], help="add a recipient")
    p1.add_argument("--recipient", required=True, help=r)
    p2 = sub.add_parser("remove-recipient", parents=[sel, act, sev], help="remove a recipient")
    p2.add_argument("--recipient", required=True, help=r)
    p3 = sub.add_parser("replace-recipient", parents=[sel, act, sev], help="swap a recipient")
    p3.add_argument("--old", required=True, help=r)
    p3.add_argument("--new", required=True, help=r)

    for cmd, what in [("add-team", "link a team"), ("remove-team", "unlink a team")]:
        sp = sub.add_parser(cmd, parents=[sel, act], help=what)
        sp.add_argument("--team-id", required=True)
    for cmd, what in [("add-tag", "add a tag"), ("remove-tag", "remove a tag")]:
        sp = sub.add_parser(cmd, parents=[sel, act], help=what)
        sp.add_argument("--value", required=True, help="tag value")

    for cmd in ("enable", "disable"):
        sp = sub.add_parser(cmd, parents=[sel, act], help=f"{cmd} detector rules")
        sp.add_argument("--label", action="append", dest="labels",
                        help="only this detectLabel (repeatable); default all rules")

    vp = sub.add_parser("validate", help="validate detector JSON without saving")
    vp.add_argument("--file", required=True)
    cp = sub.add_parser("create", parents=[act], help="create detector(s) from JSON")
    cp.add_argument("--file", required=True)
    sub.add_parser("delete", parents=[sel, act], help="delete detectors (backup first)")
    rp = sub.add_parser("restore", parents=[act], help="restore from a backup folder")
    rp.add_argument("--from", dest="backup", required=True, help="backups/<run_id>")

    tp = sub.add_parser("teams", help="look up team IDs by name")
    tp.add_argument("--name", required=True)
    return p


def read_ids_file(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [x.strip() for x in lines if x.strip() and not x.strip().startswith("#")]


def has_selector(args):
    return any([args.ids, args.ids_file, args.name, args.prefix, args.regex, args.tags])


def banner(settings, args):
    mode = "APPLY" if getattr(args, "apply", False) else "DRY RUN"
    print(f"Org: {settings.org_label} | Realm: {settings.realm} | "
          f"Operator: {settings.operator} | Mode: {mode}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    settings = load_settings()
    client = O11yClient(settings)
    safety = Safety(settings)
    svc = DetectorService(client, safety, settings)
    banner(settings, args)

    if args.command in WRITE_COMMANDS and not has_selector(args) and not args.select_all:
        sys.exit("Refusing to run on ALL detectors. Add a selector (--prefix, --id, ...) "
                 "or pass --all explicitly.")

    def selected():
        ids = list(args.ids or [])
        if getattr(args, "ids_file", None):
            ids += read_ids_file(args.ids_file)
        dets = svc.select(ids=ids or None, name=args.name, prefix=args.prefix,
                          regex=args.regex, tags=args.tags)
        print(f"Selected {len(dets)} detector(s).")
        return dets

    c = args.command
    run = dict(apply=getattr(args, "apply", False), assume_yes=getattr(args, "yes", False))

    if c == "ping":
        data = client.get("/detector", params={"limit": 1}) or {}
        print(f"Connected to {settings.api_url}. Detectors in org: {data.get('count', '?')}")
    elif c == "list":
        for d in selected():
            print(f"{d['id']}  {len(d.get('rules') or []):>2} rules  "
                  f"{d.get('detectorOrigin', ''):<10} {d.get('name')}")
    elif c == "get":
        print(json.dumps(svc.get(args.id), indent=2, sort_keys=True))
    elif c == "report":
        svc.report(selected())
    elif c == "export":
        svc.export(selected(), args.out)
    elif c == "add-recipient":
        spec = parse_recipient(args.recipient)
        svc.run_change(selected(), "add-recipient", mut_add_recipient(spec, args.severity),
                       show_diff=args.show_diff, **run)
    elif c == "remove-recipient":
        spec = parse_recipient(args.recipient)
        svc.run_change(selected(), "remove-recipient",
                       mut_remove_recipient(spec, args.severity),
                       show_diff=args.show_diff, **run)
    elif c == "replace-recipient":
        old, new = parse_recipient(args.old), parse_recipient(args.new)
        svc.run_change(selected(), "replace-recipient",
                       mut_replace_recipient(old, new, args.severity),
                       show_diff=args.show_diff, **run)
    elif c in ("add-team", "remove-team"):
        fn = mut_add_team if c == "add-team" else mut_remove_team
        svc.run_change(selected(), c, fn(args.team_id), show_diff=args.show_diff, **run)
    elif c in ("add-tag", "remove-tag"):
        fn = mut_add_tag if c == "add-tag" else mut_remove_tag
        svc.run_change(selected(), c, fn(args.value), show_diff=args.show_diff, **run)
    elif c in ("enable", "disable"):
        svc.run_toggle(selected(), enable=(c == "enable"), labels=args.labels, **run)
    elif c == "validate":
        sys.exit(0 if svc.validate_file(args.file) else 1)
    elif c == "create":
        svc.create_from_file(args.file, **run)
    elif c == "delete":
        svc.delete(selected(), **run)
    elif c == "restore":
        svc.restore(args.backup, **run)
    elif c == "teams":
        data = client.get("/team", params={"name": args.name, "limit": 50}) or {}
        for t in data.get("results", []):
            print(f"{t.get('id')}  {t.get('name')}")


if __name__ == "__main__":
    try:
        main()
    except ApiError as e:
        sys.exit(f"API error: {e}")
    except ValueError as e:
        sys.exit(f"Input error: {e}")
    except KeyboardInterrupt:
        sys.exit("\nInterrupted. Any detector already processed is listed in the audit log.")
