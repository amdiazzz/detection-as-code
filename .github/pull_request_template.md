## What this changes

<!-- One or two sentences. Link the issue: Closes #123 -->

Closes #

## Type

- [ ] New detection rule
- [ ] New correlation rule
- [ ] Rule tuning (threshold, scope, or false-positive fix)
- [ ] Parser change
- [ ] Engine or tooling change
- [ ] Docs only

## Detection content checklist

<!-- Delete this section for engine- or docs-only changes. -->

- [ ] Rule has a UUID `id`, at least one `attack.*` tag, and a non-empty `falsepositives` list
- [ ] `level` reflects real-world volume (anything noisy is `informational` and correlated)
- [ ] `tests/cases/<name>.yml` exists with **at least one true positive and one true negative**
- [ ] At least one negative is a deliberate **near miss**, not just unrelated traffic
- [ ] Proven quiet against a captured fixture via `true_negative_fixtures`, where one exists
- [ ] Correlation rules have a scenario that fires **and** one that stays silent

## False-positive analysis

<!-- What benign activity could trigger this, and why is that acceptable?
     "None" is almost never the right answer. -->

## Verification

<!-- Paste the output. Do not claim green without it. -->

```
$ make ci
```

## Notes for the reviewer

<!-- Anything non-obvious: a trade-off, something deliberately left out,
     a follow-up issue you plan to open. -->
