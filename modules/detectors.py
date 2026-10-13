"""Detector operations: select, report, export, bulk change, enable/disable,
create, delete, restore.

Every write follows the same pattern:
    plan (dry run) -> confirm -> re-fetch fresh copy -> backup -> write -> audit
"""
import copy
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from core.client import ApiError
from core.safety import json_diff

# ---------------------------------------------------------------- recipients
# CLI format -> (API notification type, ordered keys after the colon)
NOTIFICATION_TYPES = {
    "email": ("Email", ["email"]),
    "team": ("Team", ["team"]),
    "teamemail": ("TeamEmail", ["team"]),
    "slack": ("Slack", ["credentialId", "channel"]),
    "pagerduty": ("PagerDuty", ["credentialId"]),
    "webhook": ("Webhook", ["credentialId"]),
}


def parse_recipient(spec: str) -> dict:
    """'email:a@b.com' | 'team:TEAM_ID' | 'teamemail:TEAM_ID' |
    'slack:CRED_ID:channel' | 'pagerduty:CRED_ID' | 'webhook:CRED_ID'"""
    kind, _, rest = spec.partition(":")
    kind = kind.strip().lower()
    if kind not in NOTIFICATION_TYPES or not rest:
        raise ValueError(
            f"Bad recipient '{spec}'. Use one of: "
            + ", ".join(f"{k}:..." for k in NOTIFICATION_TYPES)
        )
    ntype, keys = NOTIFICATION_TYPES[kind]
    values = [v.strip() for v in rest.split(":", len(keys) - 1)]
    if len(values) != len(keys) or not all(values):
        raise ValueError(f"Recipient '{spec}' needs: {kind}:" + ":".join(keys))
    return {"type": ntype, **dict(zip(keys, values))}


def matches(notification: dict, spec: dict) -> bool:
    return all(notification.get(k) == v for k, v in spec.items())


def fmt_recipient(n: dict) -> str:
    rest = ":".join(str(v) for k, v in n.items() if k != "type")
    return f"{n.get('type', '?')}:{rest}"


def _rules(d: dict, severity=None):
    return [
        r for r in d.get("rules") or []
        if not severity or (r.get("severity") or "").lower() == severity.lower()
    ]


def _empty_rule_warning(d: dict) -> str:
    empty = [r.get("detectLabel", "?") for r in d.get("rules") or []
             if not r.get("notifications")]
    return f" | WARNING: no recipients left on rule(s) {empty}" if empty else ""


# ----------------------------------------------------------------- mutators
# Each mutator edits the detector dict in place and returns a summary string
# ("" means nothing to change).

def mut_add_recipient(spec, severity=None):
    def m(d):
        n = 0
        for r in _rules(d, severity):
            notifs = r.setdefault("notifications", [])
            if not any(matches(x, spec) for x in notifs):
                notifs.append(dict(spec))
                n += 1
        return f"add {fmt_recipient(spec)} to {n} rule(s)" if n else ""
    return m


def mut_remove_recipient(spec, severity=None):
    def m(d):
        n = 0
        for r in _rules(d, severity):
            notifs = r.get("notifications") or []
            keep = [x for x in notifs if not matches(x, spec)]
            if len(keep) != len(notifs):
                n += len(notifs) - len(keep)
                r["notifications"] = keep
        if not n:
            return ""
        return f"remove {fmt_recipient(spec)} from {n} rule(s)" + _empty_rule_warning(d)
    return m


def mut_replace_recipient(old, new, severity=None):
    def m(d):
        n = 0
        for r in _rules(d, severity):
            notifs = r.get("notifications") or []
            if any(matches(x, old) for x in notifs):
                keep = [x for x in notifs if not matches(x, old)]
                if not any(matches(x, new) for x in keep):
                    keep.append(dict(new))
                r["notifications"] = keep
                n += 1
        return (f"replace {fmt_recipient(old)} -> {fmt_recipient(new)} "
                f"in {n} rule(s)") if n else ""
    return m


def _mut_list_field(field, value, add: bool):
    def m(d):
        items = list(d.get(field) or [])
        if add and value not in items:
            d[field] = items + [value]
            return f"add {field[:-1]} {value}"
        if not add and value in items:
            d[field] = [x for x in items if x != value]
            return f"remove {field[:-1]} {value}"
        return ""
    return m


def mut_add_team(team_id):
    return _mut_list_field("teams", team_id, add=True)


def mut_remove_team(team_id):
    return _mut_list_field("teams", team_id, add=False)


def mut_add_tag(tag):
    return _mut_list_field("tags", tag, add=True)


def mut_remove_tag(tag):
    return _mut_list_field("tags", tag, add=False)


# ------------------------------------------------------------------ helpers

def _ts(ms):
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def _stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _load_json_file(path) -> list:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


# ------------------------------------------------------------------ service

class DetectorService:
    def __init__(self, client, safety, settings):
        self.client = client
        self.safety = safety
        self.settings = settings

    # ---------- read ----------
    def fetch_all(self) -> list:
        return list(self.client.paginate("/detector", page_size=self.settings.page_size))

    def get(self, detector_id: str) -> dict:
        return self.client.get(f"/detector/{detector_id}")

    def select(self, ids=None, name=None, prefix=None, regex=None, tags=None) -> list:
        """IDs are fetched one by one; every other filter runs client-side on the
        full list, so results never depend on server-side search behaviour."""
        if ids:
            found = []
            for i in ids:
                try:
                    found.append(self.get(i))
                except ApiError as e:
                    print(f"  ! could not fetch {i}: HTTP {e.status}")
            return found

        result = self.fetch_all()
        if name:
            result = [d for d in result if name.lower() in (d.get("name") or "").lower()]
        if prefix:
            result = [d for d in result if (d.get("name") or "").startswith(prefix)]
        if regex:
            rx = re.compile(regex)
            result = [d for d in result if rx.search(d.get("name") or "")]
        if tags:
            result = [d for d in result if set(tags) <= set(d.get("tags") or [])]
        return result

    def protected_reason(self, d: dict):
        if d.get("detectorOrigin") == "AutoDetect":
            return "AutoDetect detector (read-only)"
        hit = set(d.get("tags") or []) & set(self.settings.exclude_tags)
        if hit:
            return f"excluded tag {sorted(hit)}"
        for p in self.settings.exclude_name_prefixes:
            if (d.get("name") or "").startswith(p):
                return f"excluded name prefix '{p}'"
        return None

    def clean(self, d: dict) -> dict:
        return {k: v for k, v in d.items() if k not in self.settings.read_only_fields}

    # ---------- reports / export ----------
    def report(self, detectors: list) -> Path:
        self.settings.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.settings.report_dir / f"detectors-{_stamp()}.csv"
        cols = ["id", "name", "origin", "teams", "tags", "rules", "disabled_rules",
                "severities", "recipients", "rules_without_recipients",
                "created", "last_updated", "last_updated_by", "flags"]
        counts = {"NO_RECIPIENTS": 0, "NO_TEAM": 0, "ALL_RULES_DISABLED": 0}
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            for d in detectors:
                rules = d.get("rules") or []
                recips = sorted({fmt_recipient(n) for r in rules
                                 for n in r.get("notifications") or []})
                no_recip = [r.get("detectLabel", "?") for r in rules
                            if not r.get("notifications")]
                disabled = [r for r in rules if r.get("disabled")]
                flags = []
                if not recips:
                    flags.append("NO_RECIPIENTS")
                if not d.get("teams"):
                    flags.append("NO_TEAM")
                if rules and len(disabled) == len(rules):
                    flags.append("ALL_RULES_DISABLED")
                if self.protected_reason(d):
                    flags.append("PROTECTED")
                for f in flags:
                    if f in counts:
                        counts[f] += 1
                w.writerow({
                    "id": d.get("id"),
                    "name": d.get("name"),
                    "origin": d.get("detectorOrigin", ""),
                    "teams": ";".join(d.get("teams") or []),
                    "tags": ";".join(d.get("tags") or []),
                    "rules": len(rules),
                    "disabled_rules": len(disabled),
                    "severities": ";".join(sorted({r.get("severity", "") for r in rules})),
                    "recipients": ";".join(recips),
                    "rules_without_recipients": ";".join(no_recip),
                    "created": _ts(d.get("created")),
                    "last_updated": _ts(d.get("lastUpdated")),
                    "last_updated_by": d.get("lastUpdatedBy", ""),
                    "flags": ";".join(flags),
                })
        print(f"Report: {len(detectors)} detector(s) -> {path}")
        for k, v in counts.items():
            print(f"  {k:<20} {v}")
        return path

    def export(self, detectors: list, out=None) -> Path:
        out_dir = Path(out) if out else self.settings.export_dir / _stamp()
        out_dir.mkdir(parents=True, exist_ok=True)
        for d in detectors:
            (out_dir / f"{d['id']}.json").write_text(
                json.dumps(d, indent=2, sort_keys=True), encoding="utf-8")
        index = [{"id": d["id"], "name": d.get("name")} for d in detectors]
        (out_dir / "_index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
        print(f"Exported {len(detectors)} detector(s) -> {out_dir}")
        return out_dir

    # ---------- generic change engine ----------
    def _print_plan(self, action, plan, skipped, show_diff):
        print(f"\nPlan: {action}")
        print(f"  {len(plan)} detector(s) will change, {len(skipped)} skipped (protected)\n")
        for before, after, summary in plan:
            print(f"  * {before.get('name')} ({before['id']}): {summary}")
            if show_diff:
                print(json_diff(self.clean(before), self.clean(after)))
        for d, reason in skipped:
            print(f"  - SKIP {d.get('name')} ({d.get('id')}): {reason}")

    def run_change(self, detectors, action, mutate, apply=False,
                   assume_yes=False, show_diff=False):
        plan, skipped = [], []
        for d in detectors:
            reason = self.protected_reason(d)
            if reason:
                skipped.append((d, reason))
                continue
            after = copy.deepcopy(d)
            summary = mutate(after)
            if summary:
                plan.append((d, after, summary))

        self._print_plan(action, plan, skipped, show_diff)
        if not plan:
            print("Nothing to change.")
            return
        if not apply:
            print(f"\nDRY RUN: nothing was changed. Add --apply to change "
                  f"{len(plan)} detector(s).")
            return
        if not self.safety.confirm(len(plan), action, assume_yes):
            print("Aborted. Nothing was changed.")
            return

        ok = fail = 0
        for d, _, _ in plan:
            try:
                fresh = self.get(d["id"])  # never write from a stale copy
                after = copy.deepcopy(fresh)
                summary = mutate(after)
                if not summary:
                    print(f"  = {fresh.get('name')}: already up to date")
                    self.safety.audit(action, d["id"], fresh.get("name"), "skipped",
                                      "no change needed")
                    continue
                self.safety.backup(fresh)
                self.client.put(f"/detector/{d['id']}", json=self.clean(after))
                ok += 1
                print(f"  OK   {fresh.get('name')}: {summary}")
                self.safety.audit(action, d["id"], fresh.get("name"), "success", summary)
            except ApiError as e:
                fail += 1
                print(f"  FAIL {d.get('name')}: {e}")
                self.safety.audit(action, d["id"], d.get("name"), "failed", str(e))
        self._done(ok, fail)

    def _done(self, ok, fail):
        print(f"\nDone: {ok} succeeded, {fail} failed.")
        print(f"Backups:   {self.safety.backup_dir}")
        print(f"Audit log: {self.safety.audit_file}")

    # ---------- enable / disable ----------
    def run_toggle(self, detectors, enable: bool, labels=None, apply=False,
                   assume_yes=False):
        action = "enable" if enable else "disable"

        def targets(d):
            return [r["detectLabel"] for r in d.get("rules") or []
                    if r.get("detectLabel")
                    and (not labels or r["detectLabel"] in labels)
                    and bool(r.get("disabled")) == enable]

        plan, skipped = [], []
        for d in detectors:
            reason = self.protected_reason(d)
            # AutoDetect detectors CAN be disabled/enabled; other protections still apply
            if reason and not reason.startswith("AutoDetect"):
                skipped.append((d, reason))
                continue
            t = targets(d)
            if t:
                plan.append((d, d, f"{action} rule(s) {t}"))

        self._print_plan(action, plan, skipped, show_diff=False)
        if not plan:
            print("Nothing to change.")
            return
        if not apply:
            print(f"\nDRY RUN: nothing was changed. Add --apply to {action} "
                  f"{len(plan)} detector(s).")
            return
        if not self.safety.confirm(len(plan), action, assume_yes):
            print("Aborted. Nothing was changed.")
            return

        ok = fail = 0
        for d, _, _ in plan:
            try:
                fresh = self.get(d["id"])
                t = targets(fresh)
                if not t:
                    print(f"  = {fresh.get('name')}: already {action}d")
                    continue
                self.safety.backup(fresh)
                self.client.put(f"/detector/{d['id']}/{action}", json=t)
                ok += 1
                print(f"  OK   {fresh.get('name')}: {action}d {t}")
                self.safety.audit(action, d["id"], fresh.get("name"), "success", str(t))
            except ApiError as e:
                fail += 1
                print(f"  FAIL {d.get('name')}: {e}")
                self.safety.audit(action, d["id"], d.get("name"), "failed", str(e))
        self._done(ok, fail)

    # ---------- validate / create ----------
    def validate_file(self, path) -> bool:
        all_ok = True
        for det in _load_json_file(path):
            try:
                self.client.post("/detector/validate", json=self.clean(det))
                print(f"  VALID   {det.get('name')}")
            except ApiError as e:
                all_ok = False
                print(f"  INVALID {det.get('name')}: {e.body[:500]}")
        return all_ok

    def create_from_file(self, path, apply=False, assume_yes=False):
        dets = _load_json_file(path)
        print(f"\nPlan: create {len(dets)} detector(s) from {path}")
        for det in dets:
            print(f"  * {det.get('name')}")
        print("\nValidating...")
        if not self.validate_file(path):
            print("Fix validation errors first. Nothing was created.")
            return
        if not apply:
            print(f"\nDRY RUN: nothing was created. Add --apply to create {len(dets)} detector(s).")
            return
        if not self.safety.confirm(len(dets), "create", assume_yes):
            print("Aborted. Nothing was created.")
            return
        ok = fail = 0
        for det in dets:
            try:
                new = self.client.post("/detector", json=self.clean(det))
                ok += 1
                print(f"  OK   {new.get('name')} -> id {new.get('id')}")
                self.safety.audit("create", new.get("id"), new.get("name"), "success")
            except ApiError as e:
                fail += 1
                print(f"  FAIL {det.get('name')}: {e}")
                self.safety.audit("create", None, det.get("name"), "failed", str(e))
        self._done(ok, fail)

    # ---------- delete ----------
    def delete(self, detectors, apply=False, assume_yes=False):
        plan = [(d, d, "DELETE") for d in detectors if not self.protected_reason(d)]
        skipped = [(d, self.protected_reason(d)) for d in detectors if self.protected_reason(d)]
        self._print_plan("delete", plan, skipped, show_diff=False)
        if not plan:
            print("Nothing to delete.")
            return
        if not apply:
            print(f"\nDRY RUN: nothing was deleted. Add --apply to delete {len(plan)} detector(s).")
            return
        # Delete always needs typed confirmation, even with --yes
        if not self.safety.confirm(len(plan), "delete", assume_yes=False, phrase="delete"):
            print("Aborted. Nothing was deleted.")
            return
        ok = fail = 0
        for d, _, _ in plan:
            try:
                fresh = self.get(d["id"])
                self.safety.backup(fresh)
                self.client.delete(f"/detector/{d['id']}")
                ok += 1
                print(f"  OK   deleted {fresh.get('name')}")
                self.safety.audit("delete", d["id"], fresh.get("name"), "success")
            except ApiError as e:
                fail += 1
                print(f"  FAIL {d.get('name')}: {e}")
                self.safety.audit("delete", d["id"], d.get("name"), "failed", str(e))
        self._done(ok, fail)

    # ---------- restore ----------
    def restore(self, backup_folder, apply=False, assume_yes=False):
        folder = Path(backup_folder)
        files = sorted(p for p in folder.glob("*.json") if not p.name.startswith("_"))
        if not files:
            print(f"No backup files found in {folder}")
            return
        plan = []
        for f in files:
            saved = json.loads(f.read_text(encoding="utf-8"))
            try:
                current = self.get(saved["id"])
                mode = "update"
            except ApiError as e:
                if e.status != 404:
                    raise
                current, mode = None, "recreate (gets a NEW id)"
            plan.append((saved, current, mode))

        print(f"\nPlan: restore {len(plan)} detector(s) from {folder}")
        for saved, _, mode in plan:
            print(f"  * {saved.get('name')} ({saved['id']}): {mode}")
        if not apply:
            print(f"\nDRY RUN: nothing was restored. Add --apply to restore {len(plan)} detector(s).")
            return
        if not self.safety.confirm(len(plan), "restore", assume_yes):
            print("Aborted. Nothing was restored.")
            return
        ok = fail = 0
        for saved, current, mode in plan:
            try:
                if current:
                    self.safety.backup(current)  # restore is itself reversible
                    self.client.put(f"/detector/{saved['id']}", json=self.clean(saved))
                else:
                    new = self.client.post("/detector", json=self.clean(saved))
                    mode = f"recreated as {new.get('id')}"
                ok += 1
                print(f"  OK   {saved.get('name')}: {mode}")
                self.safety.audit("restore", saved["id"], saved.get("name"), "success", mode)
            except ApiError as e:
                fail += 1
                print(f"  FAIL {saved.get('name')}: {e}")
                self.safety.audit("restore", saved["id"], saved.get("name"), "failed", str(e))
        self._done(ok, fail)
