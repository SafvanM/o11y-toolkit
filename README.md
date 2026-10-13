# O11y Toolkit: Detector Operations (Phase 1)

In-house command-line toolkit for Splunk Observability Cloud detector tasks (realm **eu0**), replacing Postman.

**Safe by default:** every write command is a dry run unless `--apply` is added. Before each write the tool re-fetches the detector, saves a backup, and logs the action.

## 1. Setup (one time)

Requires Python 3.9+.

```bash
cd o11y-toolkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # then edit .env and paste your token
python o11y.py ping                # confirms token + realm work
```

In `.env`, set `SFX_ORG_LABEL`. Any label containing `PROD` makes the tool require you to type the org label before every write, and `--yes` is ignored.

## 2. Commands

| Command | What it does | Writes? |
| --- | --- | --- |
| `ping` | Test token and connectivity | No |
| `list` | List matching detectors | No |
| `get --id X` | Print one detector as JSON | No |
| `report` | Hygiene CSV: no recipients, no team, all rules disabled | No |
| `export` | Save detectors as JSON files | No |
| `teams --name X` | Look up team IDs | No |
| `validate --file f.json` | Check detector JSON without saving | No |
| `add-recipient` / `remove-recipient` / `replace-recipient` | Bulk recipient changes, optional `--severity` | Yes |
| `add-team` / `remove-team` | Link or unlink a team | Yes |
| `add-tag` / `remove-tag` | Manage tags | Yes |
| `enable` / `disable` | Toggle rules, optional `--label` | Yes |
| `create --file f.json` | Validate, then create detector(s) | Yes |
| `delete` | Delete after backup; always needs typed confirmation | Yes |
| `restore --from backups/<run>` | Roll back a run | Yes |

**Selecting detectors** (combine to narrow down): `--prefix`, `--name` (contains), `--regex`, `--tag`, `--id` (repeatable), `--ids-file`. A write command with no selector is refused unless you pass `--all`.

**Recipient format:** `email:a@b.com`, `team:TEAM_ID`, `teamemail:TEAM_ID`, `slack:CRED_ID:channel`, `pagerduty:CRED_ID`, `webhook:CRED_ID`.

## 3. Example: the Mobile4 recipient cleanup

```bash
# 1. See what will change (dry run)
python o11y.py remove-recipient --prefix "Mobile4" --recipient team:ABC123 --show-diff

# 2. Apply
python o11y.py remove-recipient --prefix "Mobile4" --recipient team:ABC123 --apply

# 3. Undo, if needed
python o11y.py restore --from backups/20261008-143000 --apply
```

The plan warns you if a rule would be left with no recipients.

## 4. Built-in safety

1. Dry run by default, with a plan showing each change and optional JSON diff.
2. Protected detectors are always skipped: AutoDetect (except enable/disable), anything tagged with `EXCLUDE_TAGS` (default `terraform`), or matching `EXCLUDE_NAME_PREFIXES`.
3. The detector is re-fetched just before writing, so changes are never made from a stale copy.
4. A backup of each detector's exact pre-change state is saved to `backups/<run_id>/`.
5. Every action is logged in `logs/audit.jsonl` (who, when, org, what, result).
6. Restore is reversible too, since the current state is backed up first.
7. HTTP 429 and 5xx responses are retried automatically with backoff.

## 5. First-run checklist (verify before using in prod)

- [ ] `ping` works with the eu0 token.
- [ ] Run `report` and `export` (read-only) and review the output.
- [ ] Pick one **test detector** and run `add-tag --id <id> --value toolkit-test --apply`. Check it in the UI, then `restore`.
- [ ] Confirm `READ_ONLY_FIELDS` is right: if a PUT returns 400 mentioning a field, add that field to `READ_ONLY_FIELDS` in `.env`.
- [ ] Export a detector that has a Slack recipient and confirm the channel format matches what you pass (`slack:CRED_ID:channel`).
- [ ] Confirm the `teams --name` lookup works in our org.
- [ ] Tag Terraform-managed detectors (or list their prefixes) so they are protected.

## 6. Structure

```
o11y-toolkit/
├── o11y.py              # command-line entry point
├── config/settings.py   # loads .env (realm, token, exclusions)
├── core/client.py       # API calls, retries, pagination
├── core/safety.py       # backup, audit log, confirmation, diff
├── modules/detectors.py # all detector operations
├── tests/               # offline tests: python -m unittest
├── backups/ logs/ reports/ exports/   # created at runtime, git-ignored
└── .env.example
```

Adding a new bulk operation means writing one small "mutator" function in `modules/detectors.py` and adding a command in `o11y.py`. The safety flow is reused automatically.
