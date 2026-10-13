"""Loads toolkit settings from environment variables / .env file.

Secrets (the token) live only in .env or the environment, never in code.
"""
import getpass
import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

ROOT = Path(__file__).resolve().parent.parent

# Fields returned by GET /detector that should not be sent back on PUT/POST.
# Verify this list against a test detector before the first prod run.
DEFAULT_READ_ONLY_FIELDS = [
    "id",
    "created",
    "creator",
    "lastUpdated",
    "lastUpdatedBy",
    "overMTSLimit",
    "labelResolutions",
    "detectorOrigin",
    "status",
]


def _list(name: str, default: str = "") -> list:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    realm: str
    token: str
    api_url: str
    org_label: str
    operator: str
    backup_dir: Path
    log_dir: Path
    report_dir: Path
    export_dir: Path
    exclude_tags: list
    exclude_name_prefixes: list
    read_only_fields: list
    page_size: int
    timeout: int
    max_retries: int

    @property
    def is_prod(self) -> bool:
        return "PROD" in self.org_label.upper()


def load_settings() -> Settings:
    token = os.getenv("SFX_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "SFX_TOKEN is not set. Copy .env.example to .env and add your API token."
        )
    realm = os.getenv("SFX_REALM", "eu0").strip()
    api_url = os.getenv(
        "SFX_API_URL", f"https://api.{realm}.observability.splunkcloud.com/v2"
    ).rstrip("/")

    return Settings(
        realm=realm,
        token=token,
        api_url=api_url,
        org_label=os.getenv("SFX_ORG_LABEL", "UNLABELLED").strip(),
        operator=os.getenv("OPERATOR", "").strip() or getpass.getuser(),
        backup_dir=ROOT / os.getenv("BACKUP_DIR", "backups"),
        log_dir=ROOT / os.getenv("LOG_DIR", "logs"),
        report_dir=ROOT / os.getenv("REPORT_DIR", "reports"),
        export_dir=ROOT / os.getenv("EXPORT_DIR", "exports"),
        exclude_tags=_list("EXCLUDE_TAGS", "terraform"),
        exclude_name_prefixes=_list("EXCLUDE_NAME_PREFIXES"),
        read_only_fields=_list("READ_ONLY_FIELDS") or DEFAULT_READ_ONLY_FIELDS,
        page_size=int(os.getenv("PAGE_SIZE", "100")),
        timeout=int(os.getenv("HTTP_TIMEOUT", "30")),
        max_retries=int(os.getenv("MAX_RETRIES", "5")),
    )
