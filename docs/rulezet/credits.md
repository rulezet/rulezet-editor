# Credits & licences page

The ⓘ button of the toolbar (or the palette: "Credits & licences") opens a page listing, in this
order, the language pack's credits (YARA: the language, libyara, the documentation, yara-python,
the YARA Style Guide the templates follow), the host's (Rulezet: rulezet-tester, bubblewrap,
MalwareBazaar…) and the editor's own (CodeMirror 6, Lezer, esbuild, the funding).

## Contract

- Pack: `credits` (Markdown string), e.g. `src/languages/yara/credits.js`.
- Host: option `credits` (Markdown string).
- Core: `openCredits()`; the editor's own section is `src/core/credits.js`.
- Rendering: `src/ui/markdown.js`, a small renderer that builds DOM nodes (headings, paragraphs,
  lists, tables, quotes, code, bold / italic / code / links): it never parses HTML, links are
  http(s) or mailto only and open in a new tab.
- Keep the lists true: what is really shipped or used, with its licence.

## Inside Rulezet

`static/js/editor/editorCredits.js` (`RULEZET_EDITOR_CREDITS`), passed as `credits` by
`YaraEditorPanel.js` and `YaraEditRulePanel.js`.

## Standalone

The pack's and the editor's sections.
