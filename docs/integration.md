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

## Inside Rulezet

1. Copy `dist/` to `app/static/vendor/rulezet-editor/<version>/` and add the module to the import
   map in `base.html`.
2. `SmartEditor` keeps its props and uses `RulezetEditor` for code formats, so the create / edit
   pages and the edit proposals switch without other changes.
3. `new RulezetHost({ baseUrl: '', csrfToken })`: same origin, no CORS.
4. The theme follows Rulezet automatically (`data-bs-theme` / `body.dark-mode`) with `theme: 'auto'`.

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
| `lineWrapping` | `false` | |

## Methods and events

Methods: `getValue()`, `setValue(text)`, `getLanguage()`, `setLanguage(id)`, `getRules()`,
`getDiagnostics()`, `getModel()`, `format()`, `validate()`, `goTo(pos | {line})`, `insertText(text)`,
`newRule()`, `goToDefinition()`, `startRename()`, `openPalette()`, `execCommand(id)`,
`toggleOutline()`, `toggleProblems()`, `toggleFullscreen()`, `setTheme()`, `setReadOnly()`,
`clearDraft()`, `focus()`, `destroy()`.

Events (`editor.on(name, fn)`): `ready`, `change`, `diagnostics`, `validated`, `format`, `save`,
`language`.

## Styling

Every color is a CSS variable on `.rze` (`--rze-bg`, `--rze-keyword`, `--rze-error`, ...): override
them in the host page. The light and dark values are in `src/styles/rulezet-editor.css`.
