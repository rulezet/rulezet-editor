# Checks panel and external checks (YARA-X, CCCS standard, yaraQA)

The **Checks** button of the toolbar opens a panel with one section per check of the document:

1. **the host's own check** (in Rulezet: its compiler, with the rules the document needs) — the
   one that decides whether the rules can be saved;
2. **the host's external tools** (in Rulezet: YARA-X, the CCCS YARA standard, yaraQA) — advice only,
   never blocking.

A remark with a line jumps there on click. A tool that offers a corrected document (YARA-X
formatting, CCCS metadata) gets an "Apply" button, enabled while the text is still the one that was
checked (the panel says when the document changed since). Rulezet's Create job also has an
**External checks** step, after its own syntax step.

| Tool | Licence | What it gives |
|---|---|---|
| [YARA-X](https://github.com/VirusTotal/yara-x) (VirusTotal) | BSD-3 | diagnostics of the new YARA engine with line/column (unused patterns, always-true conditions…), and its formatter |
| [CCCS YARA](https://github.com/CybercentreCanada/CCCS-Yara) (Canadian Centre for Cyber Security) | MIT | the meta section checked against the CCCS specification (`status`, `sharing`, `source`, `category`, `mitre_att`…); once the required fields are there, a version with the generated `id`, `fingerprint`, `version`, dates and the fields in the canonical order |
| [yaraQA](https://github.com/Neo23x0/yaraQA) (Florian Roth) | GPL-3.0 | logic and performance advice on strings and conditions (short atoms, needless `nocase`, duplicate strings…) |

## Contract

- Host (optional, `HostAdapter`): `validate(language, text)` (already used) and
  `externalChecks(language, text) -> { tool: { available, ok, reason?, errors[], warnings[], fixed_text? } }`;
  an item: `{ message, line?, column?, code?, level, rule?, detail?, element? }`. The panel and its
  toolbar button are shown when the host has either.
- `EditorServerHost.externalChecks` → `POST /external-checks` `{ format, text }` → `{ results }`
  (404 → `{}`: a server without external tools).
- Editor: `toggleChecks(force)`, `runChecks()`; UI in `src/ui/checks.js`, styles `.rze-checks-*`.

## Inside Rulezet

- `POST /editor-api/external-checks` (`app/features/editor/editor.py`): logged-in users who may use
  the editor; formats other than YARA get `{"results": {}}`.
- `app/features/editor/external_checks.py`: `run_checks(text, tools)`, one function per tool;
  a tool that is missing or crashes answers `available: false` with a reason, never an error page.
- Create job: step `external` in `editor_jobs.py` (after the syntax step, before the tests on
  samples), status `ok` / `warning`, the results kept in the job payload (`external`). Never blocks.
- Setting `app/config/editor.external_checks.json`: `{"yarax": true, "cccs": true, "yaraqa": true}`.
- Dependencies: `yara-x` and `cccs-yara` (pip, `requirements.txt`, CCCS pinned to a commit);
  yaraQA is a git submodule `app/modules/yaraQA` (not on PyPI), loaded from its folder — its live
  regex performance test is left out (slow, needs its sample data). CCCS reads the MITRE ATT&CK data
  of the `app/modules/cti` submodule (`MITRE_STIX_DATA_PATH`).
- Security: YARA-X runs with `includes_enabled=False` (no server file read), CCCS and yaraQA only
  parse the text (plyara), documents above 200 kB are not checked, nothing is sent outside.

## Standalone

The Checks panel shows the standalone server's own check (`validate`); external tools appear when
a host implements `externalChecks` (the standalone server has none: `POST /external-checks` → 404).

## Tests

`tests_new/editor/test_editor_external_checks.py` (rulezet-core): each tool on a sample rule,
switched off by the setting, includes never read, other formats, Create job step.
