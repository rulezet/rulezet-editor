# YARA editor tab (create page)

`/rule/create_rule?tab=yara_editor`: a full editor for one or several YARA rules, with live
errors (lint checked against libyara + Rulezet's compiler), rule name completion from the
database, rule tools and drafts.

## Contract

- Browser: `RulezetEditor` + `EditorServerHost({ baseUrl: '/editor-api', csrfToken })`, loaded
  from `/editor-api/assets/rulezet-editor.js` the first time the tab is opened.
- A rule already in Rulezet (same meta id, same content or same YARA name):
  - same content -> `exists`: not written, used for the links;
  - changed, and the user may edit it (owner or admin, as the edit page) -> `update`: the confirm
    modal warns, then a new version is saved (`edit_rule_core`, history, version bumped);
  - changed, not the user's -> `proposal`: an edit proposal goes to the owner (`propose_edit_core`
    + notification); an open proposal with the same content is not duplicated.
- Check: `POST /editor-api/yara/plan` `{ imports, rules: [{ name, text }] }` -> one entry per rule:
  `new | exists | update | proposal | error | blocked` (after writing: `created | updated | proposed`), `depends_on` (this document or Rulezet), `existing`, `errors`
  (line inside the rule). Nothing is written.
- Create: `POST /editor-api/yara/import`, same body: checks again, then creates the new rules
  (dependencies first, through `add_rule_core`) and links each to what it needs
  (`yara_condition_ref`, source `auto`). 409 and nothing created when one rule has an error;
  no bad rule is ever saved. On success the answer has `result_url`.
- Result page: `/editor/import-result?created=<id>&reused=<id>` lists every rule created or reused
  and its dependency links (Needs / Used by).
- Create (background job `editor_yara_import`, `app/features/editor/editor_jobs.py`):
  `POST /editor-api/yara/jobs` (same body) -> 202 `{ uuid, steps }`, then
  `GET /editor-api/yara/jobs/<uuid>` (creator or admin only) -> `{ status, steps, ok, rules,
  result_url }`. Steps: already in Rulezet, syntax (with dependencies), samples (not yet:
  `skipped`), create. Creation only when the checks pass; otherwise `ok: false`, nothing created.
- UI flow: Create -> quick plan -> modal listing each rule with what will happen (updates
  highlighted) -> "Yes, check and import" -> the steps live (editor read-only) -> created / updated /
  proposed rules (clickable) + summary page, or "Fix the errors". Old flow kept for reference:
  modal listing the rules -> "Yes, check and create" -> the steps live (editor
  read-only) -> created rules (clickable) + summary page, or "Fix the errors": the modal closes,
  errors go to their lines in the editor and on each rule in the rules panel.
- UI: the check result is shown in the editor (`setAnnotations`: badge and notes per rule in the
  rules panel, underlined lines); Check is in the editor toolbar, the big Create button in the
  action bar under the editor.

## Inside Rulezet

- `app/features/editor/editor_core.py`: `plan_yara`, `import_yara`. A rule "exists" when an
  active rule has the same meta id, the same content or the same YARA name: it is reused for the
  links, never created again. Each rule keeps only the imports it uses.
- Samples (later): a step of the job, using `rule_tester` drivers; see `editor_jobs.STEPS`.
- `app/features/editor/editor.py`: `editor_page_blueprint` (`/editor`), result page
  `app/templates/editor/import_result.html` (`import_result()` in `editor_core.py`).
- `app/static/js/rule/YaraEditorPanel.js`, used in `app/templates/rule/rule.html`
  (tab `yara_editor`, in `VALID_TABS`).
- Login: the page is `@login_required`, `/editor-api` answers 401 to anonymous users.
- Draft: kept in the browser under `rulezet-create-yara`, cleared on save.
- Ctrl+S saves; errors left in the document ask for a confirmation.

## Standalone

Not applicable (Rulezet page).

## Tests

`tests_new/editor/test_editor_api.py`, `tests_new/editor/test_editor_yara_import.py`.
