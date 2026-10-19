# YARA editor tab (create page)

`/rule/create_rule?tab=yara_editor`: a full editor for one or several YARA rules, with live
errors (lint checked against libyara + Rulezet's compiler), rule name completion from the
database, rule tools and drafts.

## Contract

- Browser: `RulezetEditor` + `EditorServerHost({ baseUrl: '/editor-api', csrfToken })`, loaded
  from `/editor-api/assets/rulezet-editor.js` the first time the tab is opened.
- Saving: the whole document is posted to `rule.parse_rule` (`format=yara`, `content`), like the
  Parse tab: every rule is created with the metadata of its `meta:` section.

## Inside Rulezet

- `app/static/js/rule/YaraEditorPanel.js`, used in `app/templates/rule/rule.html`
  (tab `yara_editor`, in `VALID_TABS`).
- Login: the page is `@login_required`, `/editor-api` answers 401 to anonymous users.
- Draft: kept in the browser under `rulezet-create-yara`, cleared on save.
- Ctrl+S saves; errors left in the document ask for a confirmation.

## Standalone

Not applicable (Rulezet page).

## Tests

`tests_new/editor/test_editor_api.py::test_create_page_has_the_yara_editor_tab`.
