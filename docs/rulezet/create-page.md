# YARA editor tab (create page)

`/rule/create_rule?tab=yara_editor`: a full editor for one or several YARA rules, with live
errors (lint checked against libyara + Rulezet's compiler), rule name completion from the
database, rule tools and drafts.

## Contract

- Browser: `RulezetEditor` + `EditorServerHost({ baseUrl: '/editor-api', csrfToken })`, loaded
  from `/editor-api/assets/rulezet-editor.js` the first time the tab is opened.
- Check: `POST /editor-api/yara/plan` `{ imports, rules: [{ name, text }] }` -> one entry per rule:
  `new | exists | error | blocked`, `depends_on` (this document or Rulezet), `existing`, `errors`
  (line inside the rule). Nothing is written.
- Create: `POST /editor-api/yara/import`, same body: checks again, then creates the new rules
  (dependencies first, through `add_rule_core`) and links each to what it needs
  (`yara_condition_ref`, source `auto`). 409 and nothing created when one rule has an error;
  no bad rule is ever saved.

## Inside Rulezet

- `app/features/editor/editor_core.py`: `plan_yara`, `import_yara`. A rule "exists" when an
  active rule has the same meta id, the same content or the same YARA name: it is reused for the
  links, never created again. Each rule keeps only the imports it uses.
- `app/static/js/rule/YaraEditorPanel.js`, used in `app/templates/rule/rule.html`
  (tab `yara_editor`, in `VALID_TABS`).
- Login: the page is `@login_required`, `/editor-api` answers 401 to anonymous users.
- Draft: kept in the browser under `rulezet-create-yara`, cleared on save.
- Ctrl+S saves; errors left in the document ask for a confirmation.

## Standalone

Not applicable (Rulezet page).

## Tests

`tests_new/editor/test_editor_api.py`, `tests_new/editor/test_editor_yara_import.py`.
