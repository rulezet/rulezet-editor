# rulezet-editor

A standalone, pluggable editor for detection rules (YARA, Sigma, Suricata, Zeek, Wazuh, ...).

It is built for [Rulezet](https://github.com/ngsoti/rulezet-core) but is not tied to it: the same
editor can run in any web page, in MISP, in an internal SOC tool or in a VS Code webview.

> Status: early design. The architecture is described in [docs/design.md](docs/design.md).
> No release yet.

## Idea

One common base for every rule format:

- syntax highlighting, folding, brackets, comment toggle
- completion (keywords, snippets, identifiers, names of existing rules)
- hover documentation
- diagnostics while typing (local lint + real compiler through a backend)
- formatting
- several rules in one document, split and checked one by one
- test panel and AI assistant panel (generate, fix, explain)

Format knowledge comes from **language packs**, server knowledge from an optional **host adapter**:

```
Host application  ->  RulezetEditor (core)  <->  Host adapter (optional: validate, search, test, AI)
                              |
             language packs: yara, sigma, suricata, ...
```

- A language pack is a plain object: pure data and pure functions, no network, no DOM.
- A host adapter only does network calls. Every method is optional; a missing method hides the
  matching feature. Without an adapter the editor works fully offline.

## Planned usage

```html
<div id="editor"></div>
<script type="module">
  import { RulezetEditor } from './dist/core.js';
  import yara from './dist/languages/yara.js';

  RulezetEditor.registerLanguage(yara);
  const editor = new RulezetEditor(document.getElementById('editor'), {
    language: 'yara',
    value: 'rule example { condition: true }',
  });
  editor.on('change', (value) => console.log(value));
</script>
```

## Planned layout

```
src/core/        editor class, language registry, diagnostics, completion, multi-rule
src/ui/          framework-free panels (problems, outline, test, AI)
src/host/        host adapter interface and the Rulezet adapter
src/wrappers/    Vue 3 wrapper
src/languages/   one folder per format, plus _template/ to start a new one
test/            core tests and the conformance suite run against every pack
playground/      demo page
```

## Adding a format

See [CONTRIBUTING.md](CONTRIBUTING.md). A new format never needs a change in the core.

## Roadmap

1. Engine prototype (CodeMirror 6 vs Monaco)
2. Core class, registry, plain pack, playground
3. YARA pack: highlighting, folding, snippets, keywords
4. Diagnostics pipeline and Rulezet adapter
5. Completion and hover
6. Multiple rules per document
7. Integration in Rulezet
8. Template, conformance tests, Sigma and Suricata packs
9. Test panel, AI panel, drafts
10. First release

Details in [docs/design.md](docs/design.md).

## License

GNU Affero General Public License v3.0, see [LICENSE](LICENSE).
