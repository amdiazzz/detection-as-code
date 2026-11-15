# Contributing

## Workflow

1. **Open an issue first.** Use the *Detection request* template so the
   intended behaviour and the false-positive risk are written down before any
   YAML exists.
2. **Branch per issue**, named `feat/<issue>-<slug>` or `fix/<issue>-<slug>`.
3. **One rule per pull request.** A reviewer can reason about one detection and
   its test cases; they cannot meaningfully review six at once.
4. **Conventional Commits** — `feat(detections): add SSH brute force rule`.
   Scopes in use: `detections`, `correlations`, `parsers`, `engine`, `tests`,
   `ci`, `docs`.
5. **Squash merge**, then delete the branch.

## Adding a detection rule

A rule and its test case are a single unit of work. CI enforces this, so a
rule without a test case cannot merge.

1. Write the rule under `detections/<platform>/<name>.yml`. Generate the `id`
   with `python3 -c "import uuid; print(uuid.uuid4())"`.
2. Write `tests/cases/<name>.yml` with at least one true positive and one true
   negative. Prefer near-miss negatives: lines that *nearly* match are what
   actually catch an over-broad rule. A negative such as
   `zipfile.example.com` for a `.zip` TLD rule is worth ten unrelated lines.
3. Where a clean captured log exists, add it under `true_negative_fixtures` so
   the rule is proven quiet against real traffic rather than hand-picked lines.
4. Run `make ci`.

### Required rule fields

`title`, `id` (UUID), `status`, `description`, `author`, `date` (`YYYY/MM/DD`),
`level`, `logsource`, `detection`, plus at least one `attack.*` tag and a
non-empty `falsepositives` list. Write `Unknown` if there genuinely are none —
an empty list reads as "not considered".

Validation rejects a condition referencing an undefined selection, a duplicate
rule `id`, a malformed MITRE tag, and a quantifier matching no selection.

### Severity

| Level | Meaning |
|---|---|
| `informational` | Never alerts alone. A building block for a correlation. |
| `low` | Worth knowing during an investigation. |
| `medium` | Worth a look this week. |
| `high` | Worth a look today. |
| `critical` | Wake someone up. |

If a rule fires more than a handful of times a day it is not `high`. Demote it
to `informational` and correlate it instead.

## Adding a correlation rule

Correlations reference detection rules by `id` and need `type`, `rules`,
`group-by`, `timespan`, and a `condition` such as `{gte: 5}`. Use
`event_count` for volume and `value_count` for breadth — a scanner touching
five distinct paths once each is a scan, while one path hit a hundred times is
usually a bug.

Scenarios must include at least one that fires and one that stays silent. A
threshold proven only to fire has not been shown to have a threshold.

## Adding a parser

Normalise onto the existing field names (`src_ip`, `user`, `uri_path`,
`status_code`, `timestamp`, ...) so existing rules keep working, return `None`
for lines of no interest, and never raise on malformed input — a corrupt line
must not abort a scan. Register it in `PARSERS` and add unit tests covering a
well-formed line, a malformed line, and a line from a neighbouring format.

## What CI runs

`ruff check`, `ruff format --check`, `bandit`, `dac validate`, and `pytest`
with an 80% coverage floor, on Python 3.11 through 3.13. CodeQL and Dependabot
run separately.
