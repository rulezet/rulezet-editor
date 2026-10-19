# AGENTS.md

Guide for anyone (human or automated agent) working on this repository: what it is, how it is
built, where things go and the rules to follow.

## What this is

`rulezet-editor` is a standalone, pluggable code editor for detection rules. It is used by
[Rulezet](https://github.com/ngsoti/rulezet-core) but must stay usable in any web page.
Engine: CodeMirror 6. Plain ES modules, no framework.

## Two modes: Rulezet first

This tool is built first and foremost to live **inside Rulezet** (git submodule of
`rulezet-core`). That is the priority: design every feature for the integrated mode first.

| Mode | Where the data comes from |
|---|---|
| **Integrated** (submodule of Rulezet) | the local Rulezet: its database, its compilers, its future features (AI assistant, ...) called **directly as Python functions** through `FunctionBackend`. Never an HTTP call to rulezet.org. |
| **Standalone** (someone runs the editor on their own) | local compilers when installed (yara-python), everything else through the **public Rulezet API** (`RulezetApiBackend`, rulezet.org by default). |

So a new server feature (validation, rule lookup, AI, ...) is always:
1. a method on `Backend` (`server/rulezet_editor/backends.py`) returning `None` when unavailable,
2. implemented by `FunctionBackend` with a Rulezet function (integrated) and by
   `RulezetApiBackend` with the public API (standalone),
3. exposed by the blueprint (`web.py`) and called by `EditorServerHost` in the browser.

4. documented in `docs/rulezet/<feature>.md` (copy `_template.md`): how it is wired into Rulezet
   (functions used, `FunctionBackend` argument, permissions) and how it runs standalone.
   **A feature without this file is not done.**

The browser code is the same in both modes; only the backend behind `/editor-api` changes.
No database in this repository: in integrated mode the data is Rulezet's.

Three layers, never mixed:

| Layer | Folder | Knows | Never does |
|---|---|---|---|
| Core | `src/core/`, `src/ui/` | the editor engine, panels, themes, events | anything specific to one rule format |
| Language pack | `src/languages/<id>/` | one rule format | network calls, DOM access, engine imports |
| Host adapter | `src/host/` | one backend (editor server, Rulezet API) | parsing rules |
| Server | `server/rulezet_editor/` | validation, rule lookup (Python, Flask) | storing data, parsing for the UI |

Every pack feature is optional and capability-driven: the core shows a feature only when the pack
(or the host) provides the matching function.

## Commands

```bash
npm install
npm run dev      # playground on http://127.0.0.1:5173/, rebuilds dist/ on change,
                 # proxies /api and /rule to RULEZET_URL (default http://127.0.0.1:7009)
npm test         # node --test: YARA tests + conformance suite for every pack
npm run build    # dist/rulezet-editor.js (ESM), dist/rulezet-editor.iife.js, dist/rulezet-editor.css

# server (Python)
uv venv .venv && uv pip install -p .venv -e ".[dev]"
.venv/bin/pytest                       # server tests (no network)
.venv/bin/rulezet-editor serve         # standalone: http://127.0.0.1:5174/, API on /editor-api
```

`npm run dev` forwards `/editor-api` to `EDITOR_SERVER` (default `http://127.0.0.1:5174`).

Run `npm run build` before committing a change to `src/`: `dist/` is committed, because Rulezet
copies it as static files and has no build step.

## Layout

```
src/index.js                 public exports; registers the bundled packs
src/core/RulezetEditor.js    the editor class: options, public API, lint pipeline, completion,
                             hover, server validation, external rule lookup, toolbar/status
src/core/registry.js         registerLanguage / getLanguage / detectLanguage (only global state)
src/core/tokens.js           token kinds a pack may return -> highlight tags
src/core/theme.js            CodeMirror theme built on --rze-* CSS variables
src/core/i18n.js             UI strings (en, fr)
src/core/events.js           tiny event emitter
src/ui/                      rules panel, problems panel, command palette, DOM helpers and icons
src/host/HostAdapter.js      base class + LocalDraftHost (drafts in localStorage)
src/host/HostAdapter.js      also HttpHost: JSON over HTTP, headers, timeout
src/host/EditorServerHost.js the editor server (/editor-api): same in both modes
src/host/RulezetHost.js      Rulezet public API straight from the browser (no editor server)
src/wrappers/vue.js          createVueComponent(Vue) for Vue 3 UMD pages
src/styles/                  rulezet-editor.css (light and dark variables)
src/languages/_template/     starting point for a new pack
src/languages/plain/         fallback pack
src/languages/yara/          reference pack:
    lexer.js                 whole-document tokens with offsets
    parser.js                error-tolerant parser, several rules per document
    analysis.js              condition references, hex checks, helpers
    lint.js                  diagnostics + quick fixes
    completion.js            context-aware completion
    navigation.js            hover, definition, references, rename
    format.js                formatter (keeps comments, skips broken rules)
    highlight.js             incremental tokenizer for highlighting
    keywords.js, modules.js  vocabulary and module members (data only)
server/rulezet_editor/       Python server, no database:
    backends.py              Backend, LocalBackend, RulezetApiBackend, FunctionBackend, ChainBackend
    validators.py            local compilers per format (yara-python), optional
    web.py                   create_blueprint(backend), create_app() for standalone
    cli.py                   rulezet-editor serve
server/tests/                pytest
pyproject.toml               Python package (installable from the submodule)
test/                        *.test.js, run by node --test
playground/                  demo page and samples
scripts/                     build.mjs, dev.mjs
docs/                        design, language-pack reference, host adapter, integration
docs/rulezet/                one file per feature: how it is integrated into Rulezet
```

## Rules

- A pack function must never throw, whatever the input. The conformance suite feeds garbage to
  every pack; keep it passing.
- Positions are character offsets (`from` inclusive, `to` exclusive). Packs return engine-neutral
  data (diagnostics, completion options, hover objects, changes); the core converts them.
- Diagnostics carry a stable `code`. Fixes are `{ label, changes: [{ from, to, insert }] }`; the
  core re-finds the problem by `code` if the document changed before the fix is applied.
- Use the code `external-rule` for references to rules not in the document: the core asks the host.
- The formatter must be idempotent and must leave rules with errors untouched.
- No colors in JS or in templates: add a `--rze-*` variable in the CSS (light and dark).
- New UI text goes through `src/core/i18n.js` (English, French).
- Integrated mode never calls rulezet.org: it uses the local Rulezet through `FunctionBackend`.
  Standalone mode reaches Rulezet only through its public API. No database in this repository.
- A backend method returns `None` when it cannot answer, raises `BackendError` when it failed.
- Keep the bundle lean: no new runtime dependency without a good reason.
- Comments explain why, not what. Match the style of the surrounding code.

## Adding a format

1. Copy `src/languages/_template/` to `src/languages/<id>/` and fill it in
   (reference: `docs/language-pack.md`, example: `src/languages/yara/`).
2. Register it in `src/index.js`.
3. Add `test/<id>.test.js` with valid, invalid and multi-rule samples; `npm test` also runs the
   conformance suite on it.
4. Add a sample to `playground/samples.js`, check it in `npm run dev`.
5. `npm run build`, commit `src/`, `test/` and `dist/` together.

## Commits

Format: `fix: [section] what changed` for a fix, `chg: [section] what changed` otherwise
(sections: `core`, `yara`, `host`, `server`, `ui`, `docs`, `test`, `build`). Never `feat:`.

## Using it in Rulezet

Submodule at `app/modules/rulezet-editor`, installed with `pip install -e app/modules/rulezet-editor`.

- Server: mount the blueprint with Rulezet's own functions (no HTTP, no rulezet.org):
  `app.register_blueprint(create_blueprint(FunctionBackend(validate=..., search_rules=..., get_rule=...)), url_prefix='/editor-api')`.
- Browser: `new EditorServerHost({ baseUrl: '/editor-api', csrfToken })`. The JS and CSS can be
  served by the blueprint (`/editor-api/assets/rulezet-editor.js`) or copied to `app/static/vendor/`.

Full example: `docs/integration.md`.
