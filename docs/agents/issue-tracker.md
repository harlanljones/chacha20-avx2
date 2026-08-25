# Issue tracker: Linear

Issues and specs for this repo live as numbered tickets in Linear.

| Setting | Value                                                  |
| ------- | ------------------------------------------------------ |
| Team    | `HJ` (Harlan Jones)                                    |
| Project | `chacha20-avx2`                                        |
| CLI     | `@schpet/linear-cli`, invoked as `linear`              |
| Auth    | `linear auth login` (interactive; never log the token) |

Commands always pass explicit flags (`--team HJ`, `--project chacha20-avx2`);
no `.linear.toml` is committed to this repo. Command `--help` output is
authoritative — the CLI updates independently of this file.

## Conventions

- One ticket per unit of work:
  `linear issue create --no-interactive --team HJ --project chacha20-avx2 --title "..." --description-file <path>`
- Triage state rides on the labels in `triage-labels.md`
  (`linear issue update <ID> --add-label "..."` / `--remove-label "..."`).
- Comments: `linear issue comment add <ID> --body-file <path>`.

## When a skill says "publish to the issue tracker"

Create the ticket(s) as above, one per ticket/spec item. Dependencies become
native blocking relations (see Wayfinding), never prose.

## When a skill says "fetch the relevant ticket"

`linear issue view <ID> --json --no-download`. The user will normally pass the
identifier (`HJ-123`) directly.

## Picking up work

1. List candidates:
   `linear issue query --team HJ --project chacha20-avx2 --state unstarted --all-assignees --json`
2. Take the lowest-numbered ticket whose blockers are all completed
   (`linear issue relation list <ID>`).
3. Claim it as the first write: `linear issue update <ID> --assignee self`.
4. Record progress/resolution via comments and state changes;
   `linear issue update <ID> --state completed` when done.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a Linear issue labeled `wayfinder:map`
holding the running Notes / Decisions-so-far / Fog body in its description.
Each **child** ticket carries the question in its body plus a type label:
`wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or
`wayfinder:task`.

- **Map + children**: create children with
  `linear issue create ... --parent <MAP-ID> --label wayfinder:<type>`.
  Re-read a map before editing — `--description-file` replaces the body wholesale.
- **Blocking**: `linear issue relation add <BLOCKED> blocked-by <BLOCKER>`;
  verify with `linear issue relation list <BLOCKED>`. Unblocked = every blocker
  completed.
- **Frontier**: project tickets that are unstarted, unassigned, and unblocked;
  lowest number wins.
- **Claim**: re-check the candidate, then `linear issue update <ID> --assignee self`.
- **Resolve**: post the answer (`linear issue comment add <ID> --body-file`),
  set `--state completed`, then append a context pointer (gist + link) to the
  map's Decisions-so-far.

## Relationship to ROADMAP.md

`ROADMAP.md` is the source of truth for phases, waves, and decision gates.
Linear tickets are executable slices of it; each references its wave. If a
ticket contradicts `ROADMAP.md` or `TDD.md`, escalate per AGENTS.md §1 rather
than deviating silently.
