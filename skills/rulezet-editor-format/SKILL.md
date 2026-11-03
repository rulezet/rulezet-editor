---
name: rulezet-editor-format
description: Adds a new rule format (Suricata, Zeek, Wazuh, KQL, Snort, Nuclei, CRS…) to rulezet-editor and wires it into Rulezet with every feature YARA and Sigma have — a complete language pack, a lint that gives Rulezet's real verdict (oracle), the format's own section of the Fields panel, Format, Try, tests on samples (rulezet-tester), Create (plan / job / links), external tools in the Checks panel, the admin access setting, docs and tests. Use it whenever someone asks to "add a format to the editor", "do like YARA / Sigma for X", "a Suricata / Zeek / … editor", or works on a new pack of app/modules/rulezet-editor.
---

# Adding a format to rulezet-editor (and to Rulezet)

Reference: what was done for **YARA** (the reference pack) and then **Sigma**. A new format gets
**the same features**, shaped by **its own** logic. Nothing is done until every step below is done
**and checked**.

Before starting, read `app/modules/rulezet-editor/AGENTS.md`, `docs/language-pack.md`,
`docs/rulezet/sigma.md` (the latest format, closest to the current contracts) and the
`src/languages/sigma/` pack as a model. Tell the user the plan, then go one step at a time.

Conventions all along:
- Commits: `fix: [section] …` (code), `chg: [test section] …` (tests), never `feat:`. Three
  repositories: `rulezet-editor`, `rulezet-tester` (submodules, on their `main`), then `rulezet-core`
  (the submodules' new references).
- No colour in JS or templates (`--rze-*` variables in the CSS, light and dark), UI text in English
  through `src/core/i18n.js`, CSS in its own file (no inline `<style>` in Rulezet).

## 0. Understand the format and its real verdict

1. How **Rulezet** validates the format today: `app/features/rule/rule_format/available_format/<fmt>_format.py`
   (`validate`, `parse_metadata`, `detect`), its schema if any (`schema_format/`), the library it
   uses (yara-python, pySigma, suricataparser, zeekscript…). **The editor's lint must give exactly
   that verdict**: an error only when Rulezet refuses the rule.
2. Get a **real corpus** from a development database (`Rule.query.filter(Rule.format.ilike('<fmt>'))`,
   a few thousand `to_string`) and Rulezet's verdict on each one.
3. Search the web: the specification, the community's **validators**, **linters**, **test** tools,
   **converters**, conventions of the reference repository (SigmaHQ, ET Open, CCCS…), public
   datasets to test on. Cite them.

## 1. The language pack (`app/modules/rulezet-editor/src/languages/<fmt>/`)

Start from `_template/`; complete models: `sigma/`, `yara/`. Usual files:

| File | Role |
|---|---|
| `index.js` | the pack: id, name, extensions, `validateAs`, `detect`, `sample`, and every function below |
| lexer / parser (or `yaml.js` + `parser.js`) | a model with the **offsets** of every element, error-tolerant, **never throws** |
| `lint.js` | diagnostics `{from,to,severity,message,code,fixes}`; errors = Rulezet refuses; warnings / infos = advice; quick fixes that make the rule valid |
| `completion.js` | completion by context (keywords, fields, known values, identifiers) |
| `navigation.js` | hover (help for every keyword / option), definition (F12), references, rename (F2) |
| `highlight.js` | incremental tokenizer (`stream`) |
| `format.js` | **idempotent** formatter, keeps comments, **skips rules with errors** |
| `actions.js` | rule tools (Ctrl+Shift+R): id / uuid, date, author, reference, ATT&CK tag… |
| `templates.js` | "New rule from template" gallery: templates **accepted as they are** by Rulezet |
| `tutorial.js` | "A complete example" in 6 stages, the last one without a warning |
| `credits.js` | the Credits & licences page (Markdown) |
| `data.js` | vocabulary (keys, options, values, help) |
| `form.js` | **the format's own section of the Fields panel** (step 3) |

Pack functions: `parse`, `lint`, `complete`, `hover`, `definition`, `references`, `rename`, `format`,
`splitRules` (several rules per document; unique `name`, `kind`, `children`), `folding`,
`dependencies` (named rules missing from the document → code `external-rule`: the core asks the
host), `meta` (entries / set / remove / skeleton / ruleName / renameRule for the Fields panel),
`actions`, `templates`, `tutorial`, `credits`, `test` (`sampleKind`, `hitLabel`, `locate`), `debug`
when it makes sense (the **Try** panel: the rule evaluated in the browser on a pasted sample, as for
YARA) and `ruleSeparator` when rules are separated by something else than a blank line. Register
the pack in `src/index.js`.

Links between rules: whatever ties rules together in the format (YARA: a rule named in a condition;
Sigma: `related:`, correlation rules; Suricata: `flowbits`; Wazuh: `if_sid`…) → hover / F12 inside
the document, `external-rule` otherwise, and the links created in Rulezet (step 4).

## 2. Check the pack against the real verdict (mandatory)

1. **Parser**: compare it with the official parser on the real corpus (Sigma: its YAML reader against
   PyYAML on 3000 rules, 0 difference). Fix until 0.
2. **Lint vs Rulezet** on the real corpus (0 disagreement) **and on mutations** (condition removed,
   unknown option, invalid value, wrong id, duplicate…). Each gap: fix the lint, or record it as a
   deliberate difference (e.g. a referenced rule not in the text: Rulezet may have it).
3. **Oracle** in the repository: `scripts/<fmt>-oracle/cases.py` (valid and broken cases), `build.py`
   (the verdict computed exactly as Rulezet does), `export.mjs` (sample, skeleton, templates **as
   CodeMirror inserts them**, snippets, tutorial stages → all must be accepted), fixture
   `test/fixtures/<fmt>-oracle.json`, test `test/<fmt>-oracle.test.js`.
4. **Formatter** on the corpus and the mutations: same content (same values for the official parser),
   same lint verdict, idempotent, no exception.
5. Unit tests `test/<fmt>.test.js`: model, each quick fix makes the rule valid, completion by context,
   hover / F12 / rename, Fields panel (set / remove / skeleton), rule tools, several rules, the
   format's form, links. `npm test` (the conformance suite feeds garbage to every pack), then
   **`npm run build`** (`dist/` is committed: Rulezet serves it).

## 3. The format's own section of the Fields panel

Each format has **its** section, after **its** logic: YARA = `pack.body` (strings + condition),
Sigma = `pack.selections` (log source + search identifiers as field / modifiers / values + condition).
A new format: a pack capability (`pack.<name>`) and its rendering in `src/ui/<name>.js`, wired in
`RulezetEditor._renderFields` (callbacks through `_editBody`). The core does not know the format: it
draws what the pack describes. Reuse `conditionBlock` (`src/ui/fields.js`) when the format has a
condition. Every edit made in the form must leave the rule **valid** (an added element joins the
condition, a rename follows, a removal takes its clause away) — test it.

Rulezet's side of the Fields panel: the `<fmt>` entry of the setting `app/config/editor.rule_fields.json`
(title, description, author, license, version, source, original_uuid, cve, attack, tags, related),
with the format's `meta` keys (virtual keys when the value lives elsewhere, e.g. ATT&CK / CVE in the
Sigma tags). Edit the JSON, never a migration.

## 4. Server validation and Create in Rulezet

- `app/features/editor/editor_core.py`: `validate(fmt, content)` → Rulezet's own validation; when the
  format allows several rules per file but the validator reads one, validate **each rule on its own**
  with lines brought back to the rule (`line N:`), and the library's raw messages made readable.
  `get_rule`: find a referenced rule by what the format uses (title, uuid, name…).
- `plan_<fmt>` + `plan(fmt, …)` / `import_rules(fmt, …)`: already in Rulezet (id / uuid, content,
  title), syntax (with the document as context when rules refer to each other), `depends_on`
  (+ `relation`, `note`, `label`) for the links, `preview` (`import_preview` / `new_rule_dict` with
  the format's `parse_metadata`). `create_from_plan` writes in dependency order and adds the auto
  relations (`add_relation(..., d['relation'], note=..., source='auto')`).
- New relation types: labels in `templates/rule/detail_rule/detail_rule_linked_rules.html` (and
  `static/js/rule_relation/dependencyFlow.js` + `DEPENDENCY_RELATION_TYPES` when it is a dependency).
- When Rulezet refused valid rules of the format (e.g. Sigma correlation rules), fix it in
  `<fmt>_format.py` (`validate`, `detect`), resolving references (the document, then the database).
- `editor.py`: routes `/<fmt>/plan|import|jobs` (add the format to `FMT = '<any(yara, sigma, …):fmt>'`).
- `editor_jobs.py`: `STEPS_BY_FORMAT[fmt]` (existing, syntax, external, samples, create), the shared
  job `editor_yara_import` with `payload.format`, `test_document(plan, imports, fmt)`.
- Panel: `static/js/rule/YaraEditorPanel.js` `FORMATS[fmt]` (title, icon, intro, draftKey); tab
  `<fmt>_editor` in `templates/rule/rule.html` (link + panel `format="<fmt>"`,
  `:tests="can_use_tests"`, `VALID_TABS`).

## 5. Admin access (Admin → Settings → Configuration)

- Setting `app/config/editor.<fmt>_access.json` (off / admins / everyone), added to
  `EDITOR_ACCESS_SETTINGS` (`features/rule_tester/sample_test_core.py`), `can_use_<fmt>_editor` in the
  context processor (`app/__init__.py`), its value in `admin_core` (`config.app`), a row in
  `templates/admin/settings.html` (same segmented control as YARA, `setEditorAccess(mode, '<fmt>')`),
  route `/admin/settings/editor_access` with `format`. `editor.py` `before_request` checks the
  access of the request's format (`_request_format`). Check: off → no tab, API answers 403.
- "Rule tests on samples" (`editor.test_access`) applies to the format too: update the text under it.
  External tools: setting `editor.external_checks` (keys `<fmt>_<tool>`).

## 6. Tests on samples (`app/modules/rulezet-tester`)

- A driver in `rulezet_tester/drivers.py` (`format`, `sample_kind`, `module`, `check_rule`, `prepare`,
  `run`, `run_data`) that **reuses the reference engine** (yara-python; for Sigma pySigma's condition
  tree evaluated on events). Hits in the contract's shape (`docs/design.md` §3: the format's own
  `where`, `item` = the part of the rule that matched). Never write a file, no network, timeouts,
  `MAX_HITS`. Be realistic: do what the real engine does (Sigma: log source category → Sysmon /
  Security EventIDs).
- Sample sets in `samples/` (`set.json` with `format`, `samples.json`): **synthetic** (crafted attacks,
  one per template) + **benign** (false positives) + **real public data** under a free licence when it
  exists (OTRF Security-Datasets for Sigma, public pcaps for Suricata…), with a fetch script
  (`scripts/fetch_*.py`). Inert addresses only (`.test` / `.invalid` / `192.0.2.x`,
  `test_shipped_samples_stay_inert`).
- Check: **every template of the editor fires on its synthetic sample and stays clean on the benign
  sets**; real rules of the database fire on the right real data.
- Tests `tests/test_<fmt>.py` (also through the `process` / `bwrap` sandbox); adapt the existing tests
  that used this format as "a format with no engine".
- Editor side: `pack.test` + the rendering of the format's `where` in `src/ui/tests.js`.
- Rulezet side: nothing special (the service reads the shipped sets); the Create's `samples` step.

## 7. External tools (Checks panel + the Create's `external` step)

Module `app/features/editor/external_checks_<fmt>.py` (like `external_checks.py` for YARA,
`external_checks_sigma.py` for Sigma), wired in the `/external-checks` route (per format) and
`editor_jobs._external_checks`. Search the web for what really exists for the format and propose it;
always think of:
- the community's reference linter / validator;
- conformance with the reference repository's conventions (its CI tests, rewritten);
- conversion / compatibility (engines, versions, SIEMs, backends);
- **"Already in Rulezet?"** (exact copy red, very close orange, with a link; a normalised
  fingerprint, the trigram index of `rule.to_string` for big volumes, a cache per rule);
- the rule's cost / performance;
- a quality score when a tool gives one.

A result's contract (`src/ui/checks.js`): `{ available, reason?, meta: { name, about, url, apply? },
errors[], warnings[], infos[]?, outputs[]? ({ label, ok, detail, text }), score? ({ value, max, parts }),
fixed_text? }` — `meta` comes **from the server** (nothing to change in the editor for a new format).
Display: only a failed output is red, and the section turns red when there is one; details visible
even when green; score as a gauge (green ≥ 80 %, orange ≥ 50 %). Remarks = errors + warnings; infos
folded.

Robustness (mandatory): run **every tool** on broken cases (empty, not the format, broken syntax,
several rules with a broken one, unicode, a big document) and hundreds of mutations: no crash, about
1 s per document at most. External programs in a **subprocess** inside an empty temporary folder,
**short timeout** (10 s), never the network (schemas / data kept locally), never feed invalid input to
a tool that may hang (rsigma 0.21 on broken YAML). Python dependencies: `uv add` reformats
`pyproject.toml` → add the line by hand, `uv lock`, regenerate `requirements.txt` (`uv export …`, then
put its header back). A binary: look in the PATH / `~/.cargo/bin` / a setting, else "not available"
with the install command.

## 8. Documentation (a feature without its doc is not done)

- `app/modules/rulezet-editor/docs/rulezet/<fmt>.md` (pack, oracle, form, Create, tools, tests,
  standalone) + its row in `docs/rulezet/README.md`; `AGENTS.md` (layout, the oracle rule); `README.md`
  (formats); `docs/rulezet/create-page.md`, `external-checks.md` when concerned.
- `rulezet-tester/docs/design.md` (driver, `where`, sets).
- Standalone validator in `server/rulezet_editor/validators.py` (optional library, an extra in the
  submodule's `pyproject.toml`) + server tests.
- Rulezet's `CLAUDE.md`: the "Rule editor" line.
- The settings' descriptions (`editor.external_checks`, `editor.rule_fields`, access).

## 9. Done

Sum up what works (with the figures of the checks), what is left (browser not tried, Rulezet's test
suite), the web sources, and wait for the go to commit and push.
