# Integration

## Plain page, ES module

```html
<link rel="stylesheet" href="/vendor/rulezet-editor/rulezet-editor.css">
<div id="editor" style="height:520px"></div>
<script type="module">
  import { RulezetEditor } from '/vendor/rulezet-editor/rulezet-editor.js';
  const editor = new RulezetEditor('#editor', { language: 'yara' });
</script>
```

## Plain page, classic script

```html
<script src="/vendor/rulezet-editor/rulezet-editor.iife.js"></script>
<script>
  const { RulezetEditor } = window.RulezetEditorLib;
  new RulezetEditor('#editor', { language: 'yara' });
</script>
```

## Vue 3 (UMD, no build step)

```js
import { createVueComponent, RulezetHost } from '/vendor/rulezet-editor/rulezet-editor.js';

const app = Vue.createApp({
  data: () => ({ content: '', host: new RulezetHost({ baseUrl: '' }) }),
});
app.component('rule-editor', createVueComponent(Vue));
```

```html
<rule-editor v-model="content" language="yara" :host="host" height="520px"
             @diagnostics="d => errors = d.filter(x => x.severity === 'error')"
             @save="submit"></rule-editor>
```

Props: `modelValue`, `language`, `theme`, `readOnly`, `height`, `host`, `options` (any other option).

## Inside Rulezet (main mode)

The editor is a git submodule of `rulezet-core`. Its server part is a Flask blueprint that
Rulezet mounts with its **own functions**: validation and rule lookup run in the Rulezet
process, on its database, with no HTTP call (and never to rulezet.org).

```bash
git submodule add https://github.com/rulezet/rulezet-editor.git app/modules/rulezet-editor
pip install -e app/modules/rulezet-editor
```

```python
# app/__init__.py (create_app)
from rulezet_editor import FunctionBackend, create_blueprint
from app.core.db_class.rule import Rule
from app.features.rule import rule_core

def _search_rules(fmt, query, limit):
    q = rule_core._active().filter(Rule.title.ilike(f'%{query}%'))
    if fmt:
        q = q.filter(Rule.format == fmt)
    return [{'name': r.title, 'uuid': r.uuid, 'description': r.description, 'author': r.author,
             'content': r.to_string, 'url': f'/rule/detail_rule/{r.uuid}'} for r in q.limit(limit)]

editor_backend = FunctionBackend(
    name='Rulezet',
    validate=lambda fmt, content: rule_core.validate_rule_syntax(fmt, content, resolve_dependencies=True),
    search_rules=_search_rules,
)
app.register_blueprint(create_blueprint(editor_backend), url_prefix='/editor-api')
```

`validate_rule_syntax` returns `{ok, errors, warnings}` or `None` for an unknown format: the
blueprint accepts that as is. With `resolve_dependencies=True`, a YARA rule that uses rules stored
in Rulezet is compiled together with them.

In the page:

```js
import { createVueComponent, EditorServerHost } from '/editor-api/assets/rulezet-editor.js';
const host = new EditorServerHost({ baseUrl: '/editor-api', csrfToken });
```

The blueprint serves `dist/` under `/editor-api/assets/`, so no copy is needed after a submodule
update. To keep Rulezet's versioned static URLs instead, copy `dist/` to
`app/static/vendor/rulezet-editor/<version>/` and add it to the import map in `base.html`.

Feature by feature (what Rulezet provides for each one): [docs/rulezet/](rulezet/README.md).

The theme follows Rulezet automatically (`data-bs-theme` / `body.dark-mode`) with `theme: 'auto'`.

## Standalone (without a local Rulezet)

```bash
pip install "rulezet-editor[yara]"     # or: pip install -e . from a clone
rulezet-editor serve                   # http://127.0.0.1:5174/
rulezet-editor serve --rulezet-url https://my-rulezet.example --api-key ...
rulezet-editor serve --offline         # local compilers only
```

Formats with a local compiler (YARA with yara-python) are validated on the machine; the other
formats and the rule lookup go to the public Rulezet API. In Python: `create_app(rulezet_url=...)`,
or build your own chain: `ChainBackend(LocalBackend(), RulezetApiBackend(url))`.

In the page: `new EditorServerHost({ baseUrl: '/editor-api', name: 'rulezet.org' })`.

Without any server at all, `RulezetHost` calls the public Rulezet API straight from the browser
(needs CORS on the Rulezet side).

## Options

| Option | Default | |
|---|---|---|
| `language` | `'auto'` | pack id, or detection from the content |
| `value` | `''` | initial text |
| `theme` | `'auto'` | `light`, `dark`, or follow the page / system |
| `locale` | `'en'` | `en`, `fr` |
| `readOnly` | `false` | |
| `height` | `null` | CSS height; `null` fills the parent |
| `toolbar`, `statusBar` | `true` | |
| `outline` | `'auto'` | rules panel; `auto` opens it when the document has two rules or more |
| `problems` | `false` | problems panel open at start |
| `host` | `null` | host adapter |
| `serverValidation` | `true` | use `host.validate` |
| `serverDelay` | `1200` | ms of idle typing before asking the server |
| `lookupExternalRules` | `true` | ask the host about rules used but not defined |
| `lint`, `format` | `{}` | options for the pack (YARA: `requireMeta`, `performance`; `indent`, `braceOnNewLine`, `alignEquals`, `normalizeHex`) |
| `draftKey` | `null` | autosave drafts under this key |
| `buttons` | `[]` | host page buttons in the toolbar: `{ id, label, icon?, title?, primary?, disabled?(editor), run(editor) }`; `refreshToolbar()` after a state change |
| `author` | `null` | default author offered by the "Set author" rule tool (Rulezet: the logged-in user) |
| `fields` | `'auto'` | Fields panel when the pack has `meta` and the host has `ruleFields`; `false` hides it ([rulezet/fields.md](rulezet/fields.md)) |
| `fieldsOpen` | `true` | the Fields panel is open at start |
| `lockPasted` | `false` | a pasted rule is locked (unlockable): its fields can be filled, its text stays as pasted |
| `toast` | `null` | `(message, tone) => void`: the editor's short messages shown with the host's own notifications (Rulezet: its toasts); tone is `info`, `success`, `warning` or `error` |
| `fieldsReport` | `true` | fields written into the rule by default (a field definition's `report` wins); `false` on an edit page |
| `tests` | `'auto'` | Test panel when the pack has `test` and the host has `startTest`; `false` hides it ([rulezet/testing.md](rulezet/testing.md)) |
| `testPollMs` | `700` | how often a running test is polled |
| `lineWrapping` | `null` | wrap long lines (line numbers stay the real ones); `null` = the viewer's last choice, off by default. Toolbar button, Alt+Z, `setLineWrapping(on)` |

## Methods and events

Methods: `getValue()`, `setValue(text)`, `getLanguage()`, `setLanguage(id)`, `getRules()`,
`getDiagnostics()`, `getModel()`, `format()`, `validate()`, `goTo(pos | {line})`, `insertText(text)`,
`newRule()`, `goToDefinition()`, `startRename()`, `openPalette()`, `execCommand(id)`,
`toggleOutline()`, `toggleProblems()`, `toggleFullscreen()`, `setTheme()`, `setReadOnly()`,
`setAnnotations({ diagnostics, rules, source }, { document })` (host results for the current text: underlines, problems panel, a badge and notes per rule in the rules panel; dropped when the text changes), `clearAnnotations()`, `notify(message)`, `refreshToolbar()`, `openRuleTools()`, several documents: `openDocument(id, { text })`, `closeDocument(id)`, `activeDocument()`, `documentIds()`, `getDocumentText(id)`, `getRulesOf(id)`, `getModelOf(id)`, locks: `lockRule(name, { label, canUnlock, url })`, `lockRuleIn(id, name, info)`, `unlockRule(name)`, `isLocked(name)`, `getLocks()`, `runAction(id, value?)`, `toggleFields()`, `pickFieldsRule(name)`, `fieldDefinitions()`, `getFieldValues(rule)`, `getAllFieldValues()`, `setFieldValues(rule, values, { report })`, `toggleTests()`, `runTest()`, `getTestRun()`, `toggleSearch()`, `setLineWrapping(on)`, `toggleLineWrapping()`, `clearDraft()`, `focus()`, `destroy()`.

Events: `ready`, `change`, `fields`, `test`, `document`, `locks`, `diagnostics`, `validated`, `format`, `save`, `language`, `action`, `annotationsCleared`.

Events (`editor.on(name, fn)`): `ready`, `change`, `diagnostics`, `validated`, `format`, `save`,
`language`.

## Styling

Every color is a CSS variable on `.rze` (`--rze-bg`, `--rze-keyword`, `--rze-error`, ...): override
them in the host page. The light and dark values are in `src/styles/rulezet-editor.css`.
