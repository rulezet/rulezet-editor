<p align="center">
  <img src="docs/images/rulezet-editor.svg" width="360" alt="Rulezet Editor">
</p>

# rulezet-editor

A standalone, pluggable editor for detection rules (YARA first; Sigma, Suricata, Zeek, Wazuh, ... next).

It is built for [Rulezet](https://github.com/ngsoti/rulezet-core) but is not tied to it: the same
editor runs in any web page, in MISP, in an internal SOC tool or in a VS Code webview.

> Status: 0.1.0, first working version with the YARA language pack.
> Architecture: [docs/design.md](docs/design.md). How it works inside, step by step: [docs/how-it-works.md](docs/how-it-works.md).

## Try it

```bash
npm install
npm run dev            # http://127.0.0.1:5173/
```

The playground forwards `/api` to a Rulezet instance (default `http://127.0.0.1:7009`) so rules are
also checked by the real YARA compiler and rule names are looked up on Rulezet:

```bash
RULEZET_URL=https://rulezet.org npm run dev
```

## What the YARA pack does

| Area | Features |
|---|---|
| Highlighting | keywords, sections, `$strings`, modifiers, modules, hex strings (bytes, wildcards, jumps), regexes, tags, comments |
| Completion | rule templates, sections, meta keys, string snippets, modifiers valid for the string kind, `$` / `#` / `@` / `!` identifiers, `$prefix*` sets, module members (`pe.sections[0].name`), modules (adds the `import` for you), rules defined above, rules that exist on Rulezet |
| Diagnostics while typing | syntax errors (every rule keeps being checked after one breaks), undefined / unused / duplicate strings, wildcards that match nothing, module used without import, unknown module member, unused import, rule used before its definition, unknown rule, duplicate rule / tag, invalid modifiers and combinations, `xor` range, base64 alphabet, hex string checks (single digit, bad characters, jumps), text escapes, deprecated `entrypoint`, missing meta, performance hints (short atoms, leading wildcards, `.*`) |
| Quick fixes | add the import, add the meta, use or remove an unused string, fix a typo in a string name, replace `entrypoint`, close a rule, insert a rule from Rulezet |
| Server checks | the whole document is compiled by the host (Rulezet: the same check as rule creation), errors mapped to their line |
| Navigation | hover docs (keywords, modules, strings with byte length / hex, rules, rules on Rulezet), go to definition (F12, Ctrl+Click), highlight of every occurrence, rename (F2) |
| Several rules per document | rules panel with status per rule, strings and condition, filter, copy one rule |
| Formatting | Shift+Alt+F: one layout, aligned `=`, comments kept, rules with errors left untouched |
| Tutorial | a guided tour (Tutorial button): each feature highlighted, explained with an example, most with a "Try it" button; only the features the page offers |
| Fields | the host's fields for each rule (title, CVE, ATT&CK, tags…), each written into the rule (`meta:`) or kept outside it; values read back from the rule, differences shown and decided |
| Tests | Test panel: run the rules on sample sets (rulezet-tester), live verdict per sample, false positives, click a hit to select the string |
| Editor | folding per rule and section, multi-cursor, find / replace, command palette (Ctrl+Shift+P), light / dark / auto theme, full screen, drafts kept in the browser, English / French UI |

## Use it in a page

```html
<link rel="stylesheet" href="dist/rulezet-editor.css">
<div id="editor" style="height:520px"></div>
<script type="module">
  import { RulezetEditor, RulezetHost } from './dist/rulezet-editor.js';

  const editor = new RulezetEditor('#editor', {
    language: 'yara',                                   // or 'auto'
    value: 'rule example { condition: true }',
    host: new RulezetHost({ baseUrl: 'https://rulezet.org' }),   // optional
  });
  editor.on('change', value => console.log(value));
  editor.on('diagnostics', list => console.log(list));
</script>
```

Without a module loader: `dist/rulezet-editor.iife.js` exposes `window.RulezetEditorLib`.
With Vue 3: `createVueComponent(Vue)` returns a `v-model` component. Details in
[docs/integration.md](docs/integration.md).

## Keyboard

| Keys | Action |
|---|---|
| Ctrl+Space | suggestions |
| F12 / Ctrl+Click | go to definition (opens the rule on Rulezet when it is not in the document) |
| F2 | rename a `$string` or a rule everywhere |
| Shift+Alt+F | format |
| Ctrl+Shift+P / F1 | command palette |
| Ctrl+Shift+O | rules panel |
| Ctrl+Shift+M | problems panel |
| F8 / Shift+F8 | next / previous problem |
| Ctrl+Enter | validate on the server now |
| Ctrl+Shift+Enter | run the tests |
| Ctrl+S | `save` event for the host page |
| Ctrl+/ | toggle comment |

## Architecture

```
Host application  ->  RulezetEditor (core)  <->  Host adapter (optional: validate, search, drafts)
                              |
             language packs: yara, plain, ... (pure data and functions)
```

- A language pack never calls a server and never touches the DOM: [docs/language-pack.md](docs/language-pack.md).
- A host adapter only does network calls; a missing method hides the matching feature:
  [docs/host-adapter.md](docs/host-adapter.md).
- The engine is CodeMirror 6; no engine type leaks into the pack interface.
- Tests on samples come from [rulezet-tester](https://github.com/rulezet/rulezet-tester) (sandboxed runs,
  one driver per format): `create_blueprint(backend, tests=TestService(...))` mounts its API on
  `/editor-api/test`. Without it, no Test button.

```
src/core/        editor class, registry, theme, events, i18n
src/ui/          rules panel, problems panel, command palette (plain DOM)
src/host/        host adapter base class and the Rulezet adapter
src/wrappers/    Vue 3 component
src/languages/   yara/, plain/, _template/
test/            YARA tests and the conformance suite every pack must pass
playground/      demo page (npm run dev)
dist/            prebuilt files for pages without a build step
```

## Development

```bash
npm run dev      # playground + rebuild on change
npm test         # unit tests + conformance suite
npm run build    # dist/
```

Adding a format: [CONTRIBUTING.md](CONTRIBUTING.md). Repository guide: [AGENTS.md](AGENTS.md).

## Roadmap

1. Engine choice and core (done)
2. YARA pack (done: highlighting, completion, lint, fixes, hover, rename, format, several rules)
3. Integration in Rulezet (create / edit pages, edit proposals)
4. Sigma and Suricata packs
5. Test panel (run the rule on a sample), Rulezy assistant panel (generate, fix, explain)
6. First npm release, VS Code webview demo

## License

GNU Affero General Public License v3.0, see [LICENSE](LICENSE).
