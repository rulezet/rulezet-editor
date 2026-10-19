# Rule tools and new-rule template

Ctrl+Shift+R (or the toolbar "Rule tools" button, or the palette): add the date (or update
`modified`), an id, tags, author, description, references, ATT&CK techniques, a text string, a PE /
ELF check, a file size limit, toggle `private`. New rules start from a template with
`id = "<uuid4>"`, `author` and `date`.

## Contract

- Pack: `actions(ctx)` in `src/languages/yara/actions.js`; core: `openRuleTools()`,
  `runAction(id, value?)`; `{{uuid}}` / `{{date}}` filled in by the core.
- No server call.

## Inside Rulezet

- `author` option = `current_user.get_username()` (passed by `YaraEditorPanel.js`).
- `meta: id` is what Rulezet stores as `original_uuid` (rulezet-cast `yara_parser.py` reads
  `id` or `uuid`); a duplicate is refused on save (`UUID_DUPLICATE`), the lint warns before.

## Standalone

Same, `author` option given by the page.

## Tests

`test/yara.test.js` (actions), `test/yara-oracle.test.js` (lint).
