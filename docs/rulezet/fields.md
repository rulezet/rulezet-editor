# Fields panel (the rule's metadata)

A **Fields** button opens a panel next to the editor with the host's fields for the rule under the
cursor (or a chosen rule): title, description, author, licence, version, source, original UUID,
CVE, ATT&CK techniques, tags… Each field can be **written into the rule** (YARA: a `meta:` key) or
**kept outside it** (stored by the host only). The panel also reads the rule: a value the rule
already holds fills the field, and any difference between the two is shown and decided
explicitly.

The panel is **open by default**. With an empty document it still shows the fields: the first
value typed creates the rule, the title names it (`My rule` → `My_rule`) and the rule is written
next to the panel as the fields are filled. Below the fields, **Strings & condition** edits the
rule's strings (id, text / hex / regex, value, modifiers with their arguments) and its condition
as a form — both ways: typing in the editor updates the form, the form writes into the rule.

Field kinds follow Rulezet's manual form, with the panel's look:

| Kind | Same rules as |
|---|---|
| `version` stepper (major.minor, − / +, minor 0–9 with carry, never below 1.0) | `VersionPicker` |
| `select` + `searchable` (type to filter, one choice, clearable) | `LicenseInput` |
| `list` + `formats` + `pattern` + `chipColors` (format menu prefills the prefix, live "Format correct / Invalid format for X", coloured chips) | `VulnerabilityInput` |
| `list` + `browse` + `suggest` (search, or tactics in matrix order, coloured chips) | `AttackInput` |
| `list` + `browse` + `suggest` (search, or Public / Private namespaces, 50 per page) | `TagInput` |
| `list` + `kinds` + `max` (search rules, relation per chip, at most 20) | `RelatedRuleInput` |
| text + `me` (a **Me** button: the user's name) | — |

Tags read from the rule include the header tags (`rule X : a b`, pseudo key `@tags`) and
`meta tags / tag`, as Rulezet's imported-tags detection does. A title field (`fromRuleName`)
starts as the rule's name when a rule is pasted.

All panels (Rules, Fields, Problems, Test) and the editor itself are resizable with the mouse
(sizes remembered per viewer).

Why "outside the rule" matters: in Rulezet, editing a rule's text stops its automatic updates
(e.g. from GitHub). A field kept outside lets the user enrich the rule without touching it.

## Linked rules: Browse and add to the document

A field marked `"picker": true` gets a **Browse** button when the host gives `options.pickValues`:
Rulezet opens its full rule list (filters, search, pagination) in a modal (`static/js/rule_relation/rulePicker.js`,
`pickRules()`); the rules already linked are ticked, **Done** hands the choice back, kept items keep
their relation kind. A field marked `"insertable": true` gets **Add N to the document (locked)**:
each linked rule is fetched (`host.getRule`) and inserted at the top, locked like a dependency
(unlockable by its owner or an admin); rules of another format are skipped with a message. Bounded
by `insertMax` per click (10) and `insertTotalMax` locked rules in the document (30), both in the
field definition (Rulezet: setting `editor.rule_fields`).

## Contract

- Host: `ruleFields(language)` → field definitions; `suggest(language, field, query)` →
  `[{ value, label, detail? }]`. Server: `Backend.fields(fmt)`, `Backend.suggest(fmt, field, q, limit)`
  (`FunctionBackend(fields=, suggest=)`); endpoints `GET /fields?format=`,
  `GET /fields/suggest?format=&field=&q=`; `EditorServerHost.ruleFields()`, `.suggest()`.
- Field definition:
  `{ id, label, type: text | textarea | select | list, help?, required?, placeholder?,
     options?: [{ value, label }], suggest?, free?, pattern?, upper?, report?,
     meta?: { key, aliases?, extract?: 'cve' | 'attack' | 'url', extractFrom?, join? } }`
  — no `meta`: the field lives in the host only (e.g. Rulezet's title, tags).
- Pack: `meta: { entries(model, rule), set(model, rule, key, value), remove(model, rule, key) }`
  (YARA: `src/languages/yara/index.js`). Logic: `src/core/fields.js` (pure, tested in
  `test/fields.test.js`); panel: `src/ui/fields.js`.
- Statuses per field: *in the rule* (written, same value), *same as the rule*, *differs from the
  rule* (to decide: **Use the rule's value** / **Write mine into the rule** / **Keep different**),
  *differs on purpose* (kept; "reconsider" to undo), *not in the rule*, *in the rule only*.
- A written field follows the rule when the user edits the rule text; removing its key from the
  text stops writing it. A locked rule's fields can be read, never written.
- Options: `fields: 'auto' | false`, `fieldsReport` (default true: fields written into the rule by
  default; a definition's `report` wins). Methods: `toggleFields()`, `fieldDefinitions()`,
  `getFieldValues(rule)`, `getAllFieldValues()`, `setFieldValues(rule, values, { report })`.
  Event `fields`.

## Inside Rulezet

- Definitions: setting `app/config/editor.rule_fields.json` (per format; Admin → Configuration),
  read by `editor_core.fields()`; `"options": "licenses"` becomes Rulezet's licence list.
- Suggestions: `editor_core.suggest()` — `tags` from the tag picker search, `attack` from
  `attack_core.search_techniques`.
- Create page (YARA editor tab): `YaraEditorPanel.js` sends each rule's values with plan / jobs;
  `editor_core.clean_fields()` keeps known fields only (size-capped), `apply_fields()` makes them
  win over what `parse_metadata` read, `attach_attack()` links the techniques once the rule exists.
  Default TLP / PAP tags are still attached.
- Check & preview (create page): `plan` returns, for every new rule, `preview` = every field Rulezet
  will store and where each value comes from (`panel`, `rule`, `default`), computed by the same
  `new_rule_dict()` the creation uses; imported tags with `extract_native_tags`.
- Edit page (`YaraEditRulePanel.js`, `fieldsReport: false`): the panel shows the edited rule's
  stored values (`setFromForm` ← the form) and every change goes back to the form (`fields` event →
  `pullPanelToForm` in `edit_rule.html`); ATT&CK is saved at once, as the ATT&CK picker does; the
  rule text is only touched for the fields the user ticks.

## Standalone

No fields unless the backend provides them (`FunctionBackend(fields=...)`): no Fields button.

## Tests

`test/fields.test.js` (logic + YARA meta), `server/tests/test_server.py::test_fields_and_suggestions`,
Rulezet `tests_new/editor/test_editor_yara_import.py` (definitions, suggestions, a created rule
taking the fields).
