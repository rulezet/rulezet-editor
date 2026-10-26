# Integrating features into Rulezet

How the whole editor works, from a keystroke to rules written in Rulezet: [../how-it-works.md](../how-it-works.md).

One file per feature. Each one says how the feature runs **inside Rulezet** (integrated mode,
the priority) and how it runs **standalone** (public Rulezet API). A feature is not done until
its file exists here.

| Feature | File | Rulezet side | Standalone side |
|---|---|---|---|
| Server validation | [validation.md](validation.md) | `rule_core.validate_rule_syntax` | local compiler, then `POST /api/rule/public/validate` |
| Rule lookup (completion, hover, external rules) | [rule-lookup.md](rule-lookup.md) | query on `Rule` via `_active()` | `GET /api/rule/public/searchPage` |
| YARA editor tab (create page) | [create-page.md](create-page.md) | `YaraEditorPanel.js`, saves through `rule.parse_rule` | — |
| Workspace (folders, files) and bundles — **paused**, removed from Rulezet's `editor` branch for now | [workspace.md](workspace.md) | (was `/editor`, `editor_bundle.py`, bundle job step) | — |
| Fields panel (title, CVE, tags… in the rule or not) | [fields.md](fields.md) | `editor_core.fields` / `suggest` / `apply_fields`, setting `editor.rule_fields` | — |
| Tests on samples (Test panel, Create step, Samples tab of the rule page) | [testing.md](testing.md) | `editor_core.tests` (rulezet-tester), `sample_test_core`, `RULE_TESTS_*`, setting `editor.test_on_create` | `serve` + rulezet-tester |
| Rule tools, new-rule template | [rule-tools.md](rule-tools.md) | `author` = logged-in user; `meta: id` read as `original_uuid` | — |

Rulezet side (branch `editor` of rulezet-core):

- `app/modules/rulezet-editor`: this repository, as a submodule, installed with
  `pip install -e` (requirements.txt). install.sh, update.sh, manage.py and launch.sh fetch it.
- `app/features/editor/editor_core.py`: the `FunctionBackend` (Rulezet's functions).
- `app/features/editor/editor.py`: the blueprint on `/editor-api`, logged-in users only.
- `app/static/js/rule/YaraEditorPanel.js`: the "YARA editor" tab of the create page.
- `tests_new/editor/`: endpoint tests.

New feature: copy [_template.md](_template.md).
