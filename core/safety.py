"""Safety layer: backups before every write, audit log, confirmations, diffs."""
import difflib
import json
from datetime import datetime, timezone


class Safety:
    def __init__(self, settings):
        self.settings = settings
        self.run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.backup_dir = settings.backup_dir / self.run_id
        self.audit_file = settings.log_dir / "audit.jsonl"
        settings.log_dir.mkdir(parents=True, exist_ok=True)

    def backup(self, obj: dict):
        """Save the exact current state of an object before it is changed."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        path = self.backup_dir / f"{obj['id']}.json"
        path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def audit(self, action, obj_id, name, result, detail=""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "operator": self.settings.operator,
            "org": self.settings.org_label,
            "realm": self.settings.realm,
            "action": action,
            "detector_id": obj_id,
            "detector_name": name,
            "result": result,
            "detail": detail,
        }
        with self.audit_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def confirm(self, count: int, action: str, assume_yes=False, phrase=None) -> bool:
        """Ask before writing. In a PROD org the operator must type the org label;
        --yes is ignored there."""
        if phrase is None:
            phrase = self.settings.org_label if self.settings.is_prod else "yes"
        elif self.settings.is_prod:
            phrase = f"{phrase} {self.settings.org_label}"
        if assume_yes and not self.settings.is_prod:
            return True
        answer = input(
            f"\nApply '{action}' to {count} detector(s) in org "
            f"'{self.settings.org_label}' (realm {self.settings.realm})?\n"
            f"Type '{phrase}' to continue: "
        ).strip()
        return answer == phrase


def json_diff(before: dict, after: dict) -> str:
    a = json.dumps(before, indent=2, sort_keys=True).splitlines()
    b = json.dumps(after, indent=2, sort_keys=True).splitlines()
    return "\n".join(
        difflib.unified_diff(a, b, "before", "after", lineterm="", n=2)
    )
