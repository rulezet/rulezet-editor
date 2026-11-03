# Sigma pack and Sigma editor tab

Sigma rules in the editor, as YARA rules: highlighting, completion, a lint that gives Rulezet's
own verdict, quick fixes, hover, F12 / F2 on search identifiers, rule tools, templates, the
tutorial, the Fields panel, several rules per document (one per YAML document, `---`). In
Rulezet: the "Sigma editor" tab of the create page, with the same Check / Create flow as YARA.

## Contract

- Pack: `src/languages/sigma/` (registered in `src/index.js`, `language: 'sigma'`).
  - `yaml.js`: a small error-tolerant YAML reader keeping the offset of every key and value
    (checked against PyYAML on 3000 real rules: same values).
  - `parser.js`: one rule model per document (title, logsource, search identifiers with their
    fields and modifiers, condition tokens).
  - `lint.js`: errors exactly where Rulezet refuses the rule — its JSON schema (title, logsource,
    detection, one condition string, date format, list keys, tag pattern, no duplicates in tags /
    references / fields / falsepositives) and pySigma (parsing: modifiers, status, level, id, condition
    grammar; HIGH checks: unused search identifier, unknown identifier, `all` without `contains`,
    `base64offset` without `contains`, `windash` with `all`, control characters, custom logsource
    key, Sysmon / Security EventID that has its own category, same id or title twice). pySigma's
    MEDIUM checks are warnings, LOW ones infos.
  - `meta`: the Fields panel reads and writes top-level keys; `mitre_attack` and `cve` are virtual
    keys mapped to the tags (`attack.t1059`, `cve.2024-3094`); Rulezet tags are never written.
  - `splitRules`: one rule per document, named after its title.
  - `selections` (`form.js`): the format's own section of the Fields panel ("Log source &
    detection"), drawn by `src/ui/selections.js`: category / product / service, each search
    identifier as field / modifiers / values rows (keywords as a list; a list of mappings is shown
    as text, edited in the editor), the condition as clauses (shared with YARA: `conditionBlock` in
    `src/ui/fields.js`). Adding a selection appends `or <name>` to the condition, a filter
    `and not <name>`, a rename follows in the condition, a removal takes its clause away: the rule
    stays valid. Each format brings its own section (YARA: `body`, strings + condition).
  - `related:` links: an id of a rule of the document -> hover and F12 to it; any other id -> the
    `external-rule` lookup on the host (Rulezet finds it by uuid / original uuid, offers to insert it
    after a `---`, `ruleSeparator`).
- Server validation: `POST /editor-api/validate { format: 'sigma', content }`. Several rules: each
  document is validated on its own (`rulezet_editor.validators.split_yaml_documents`), messages
  start with `line N:` (the rule's first line).
- Create (Rulezet): `POST /editor-api/sigma/plan`, `/sigma/import`, `/sigma/jobs`,
  `GET /sigma/jobs/<uuid>` — same bodies and answers as the YARA ones (`create-page.md`), no
  `imports`, no `depends_on`.

- `format` (`format.js`, Shift+Alt+F / Format button): SigmaHQ layout — 4 spaces, lists under their
  key, top-level keys in the specification's order, one `---` between rules; values, comments and
  block scalars kept as written; a rule with a YAML error is skipped. Checked on 3000 real rules:
  same YAML values, same lint verdict, idempotent.
- `test` (Test panel, rulezet-tester's `sigma` driver): samples are events (JSON Lines); a hit is one
  event (`where: { kind: 'event', index, fields }`), its `item` the search identifiers that matched
  (highlighted in the rule). The Test panel shows the event number and the fields.

## Inside Rulezet

- `app/features/editor/editor_core.py`:
  - `validate('sigma', …)` splits the documents and runs `rule_core.validate_rule_syntax('sigma', …)`
    on each (`SigmaRule.validate`: schema + pySigma); `sigma_message` makes pySigma's issue text readable.
  - `plan_sigma(rules, progress, user)`: in Rulezet already (same id / original uuid, same content,
    same title), then the syntax; `plan(fmt, …)` / `import_rules(fmt, …)` pick the format.
  - `new_rule_dict` / `import_preview` read the rule with `SigmaRule.parse_metadata` (title, id ->
    original_uuid, author, license, description, CVEs) and the Fields panel's values on top.
  - Update / proposal: same as YARA (`_update`, `_propose`; owner or admin updates, anybody else proposes).
  - `related:`: each id found in the document or in Rulezet (uuid / original uuid) becomes a
    `depends_on` entry (`relation: 'sigma_related'`, `note`: derived, obsolete…); on creation an
    auto `sigma_related` relation is added (Linked rules page: "related (Sigma related:)").
  - `get_rule(fmt, name)`: a uuid is looked up by uuid / original uuid (hover "found on Rulezet").
- `app/features/editor/editor.py`: routes `/<yara|sigma>/plan|import|jobs`.
- `app/features/editor/editor_jobs.py`: one job type (`editor_yara_import`) for both; `payload.format`;
  Sigma steps: existing, syntax, samples (the shipped sample events, setting `editor.test_on_create`), create.
  `test_document(plan, imports, 'sigma')`: the rules joined with `---`.
- Setting `editor.rule_fields`: entry `sigma` (title = the rule's `title:`, original UUID = `id:`,
  ATT&CK / CVE written as tags, version / source / Rulezet tags kept in Rulezet only).
- `app/static/js/rule/YaraEditorPanel.js`, prop `format="sigma"`; tab `sigma_editor` of
  `app/templates/rule/rule.html` (same access as the YARA editor: setting `editor.access`).
  Draft kept under `rulezet-create-sigma`.

## Correlation rules

A correlation rule (`correlation:` — event_count, value_count, temporal, temporal_ordered, value_sum,
value_avg, value_percentile, value_median) combines other Sigma rules, named by their `name:` or `id`.

- Editor lint (`lintCorrelation`): type, rules, timespan (`5m`, `1h`…), group-by list, the condition
  of the counting types (gt / gte / lt / lte / eq / neq, `field` for value_*). A named rule of the
  document: hover / F12 go to it; any other: `external-rule`, looked up on the host (Rulezet finds it
  by uuid / original uuid or by its `name:`, `editor_core.get_rule`).
- Rulezet (`SigmaRule.validate`, `_validate_correlation`): checked by pySigma with the rules it names,
  from the same document (`context`) first, then Rulezet (`SigmaRule.find_referenced_rule`); a rule
  found nowhere is an error. `detect()` recognises them.
- Create (`plan_sigma`): each named rule becomes a `depends_on` entry (`relation: 'sigma_correlation'`,
  note = the type): a rule of the document is written first, then the auto relation is added (a
  dependency: `DEPENDENCY_RELATION_TYPES`, Linked rules page "combines (Sigma correlation)").
- SIEM conversion: converted together with the rules it names; Splunk, ES|QL, EQL, Loki support
  correlations, the others say so (red line).
- Tests on samples: not evaluated (the driver runs detection rules).

## External checks (Checks panel, Create step "external")

Advice next to Rulezet's own check, never a verdict on saving (`app/features/editor/external_checks_sigma.py`,
`POST /editor-api/external-checks { format: 'sigma', text }`, setting `editor.external_checks`, keys `sigma_*`):

| Tool | What it says | Needs |
|---|---|---|
| `siem` | the rule converted by each pySigma backend of `sigma_siem_targets` (Splunk SPL, Elasticsearch Lucene / ES\|QL / EQL, Microsoft Sentinel & Defender KQL, Grafana Loki, Google SecOps…): the query (info), or why it cannot be converted (warning) | the backends Rulezet installs (pyproject) |
| `schemas` | the same backends with their data-model pipelines (Splunk CIM, Elastic ECS, Defender XDR, Sentinel ASIM, Azure Monitor; macOS / Zeek / Okta ones too): green with each field's name in that SIEM (`Image → process.executable`), red when a field is unknown there (the rule would find nothing) | the backends' pipelines |
| `pysigma` | pySigma's MEDIUM (warnings) and LOW (notes) checks — what Rulezet accepts but could be written better (tags, wildcards instead of modifiers, numbers as strings, all of them…) | pySigma |
| `duplicates` | Sigma rules of this Rulezet with the same detection (log source + field / value pairs, names and order ignored: a copy, red) or a very close one (80 %, orange), with a link; fingerprints cached per rule | the database |
| `cost` | what makes the search slow or noisy (leading wildcards, unanchored regex, full-text keywords, long lists, short contains values, no exact value, a lone negation) and an efficiency score | nothing |
| `sigmahq` | the conventions SigmaHQ's repository enforces (`tests/test_rules.py`): title first, one-value lists, "ATT&CK" trademark, Sysmon without EventID, EventID 1 / 4688 with Provider_Name, regex escapes, license as text; plus the file name SigmaHQ would give | nothing |
| `sigmalint` | sigmalint (MIT) findings with their fix hints, and the quality score per dimension | `sigmalint-cli` (pyproject); runs offline in an empty temporary folder |
| `rsigma` | `rsigma rule lint` (Sigma 2.1 specification checks) | the `rsigma` binary (`cargo install rsigma --locked`, or `sigma_rsigma_path`); gets Rulezet's local schema, never downloads it |

Each rule (--- document) is checked on its own; lines point into the whole document. A SIEM is the
tool a SOC searches its logs with (Splunk, Elastic, Microsoft Sentinel…): `siem` shows the rule as
each one's query, green when it converts, red when it cannot.

Every tool answers with the Checks panel's contract (`src/ui/checks.js`): `meta` (name, about, url —
sent by the host, so a new format brings its tools without touching the editor), `errors` / `warnings`
(remarks), `infos` (folded notes), `outputs` (`{ label, ok, detail, text }`: green ✓ / red ✗, the
detail and the start of the text visible, the whole text and Copy when opened), `score`
(`{ value, max, parts }`: a gauge, green from 80 %, orange from 50 %).

## Standalone

- `rulezet-editor serve`: `SigmaValidator` (pySigma, optional: `pip install rulezet-editor[sigma]`)
  validates each document locally; HIGH issues are errors. Without pySigma, the chain falls back
  to the public Rulezet API (`POST /api/rule/public/validate`).
- Everything else (lint, completion, fields, templates) runs in the browser.

## Tests

- `test/sigma.test.js`: model, fixes, completion, navigation, Fields panel, rule tools, several rules.
- `test/sigma-oracle.test.js` + `test/fixtures/sigma-oracle.json`: the lint against Rulezet's verdict.
  Rebuild after adding a case to `scripts/sigma-oracle/cases.py`:
  `node scripts/sigma-oracle/export.mjs && python scripts/sigma-oracle/build.py` (pySigma, PyYAML,
  jsonschema; `sigma_schema.json` is a copy of Rulezet's schema). The export adds the pack's own
  texts (sample, templates as inserted, tutorial, skeleton): they must all be accepted.
- `server/tests/test_server.py`: `split_yaml_documents`, local Sigma validation.
- Rulezet: `tests_new/editor/test_editor_sigma.py`.
