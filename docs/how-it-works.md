# How it works

This page follows what happens inside rulezet-editor, from a keystroke to an underlined error,
a completion, a server check, and finally rules written in Rulezet. It is the companion of the
reference pages:

- [design.md](design.md): why the editor is built this way (goals, engine choice, plan);
- [language-pack.md](language-pack.md): the pack interface, field by field;
- [host-adapter.md](host-adapter.md): the adapter interface and the endpoints;
- [integration.md](integration.md): how to put the editor in a page, options, methods, events;
- [rulezet/](rulezet/README.md): what Rulezet provides for each feature.

Read this page first if you want to change the editor or debug it.

## 1. The big picture

```
 Browser                                                     Server (Python, optional)
┌───────────────────────────────────────────────────────┐   ┌──────────────────────────────┐
│ Host page (Rulezet create page, playground, MISP...)  │   │ rulezet_editor blueprint     │
│   new RulezetEditor(el, { language, host, ... })      │   │   POST /validate             │
│                │                                      │   │   GET  /rules?q=             │
│ ┌──────────────▼───────────────┐   ┌────────────────┐ │   │   GET  /rules/<name>         │
│ │ Core: RulezetEditor          │◄─►│ Host adapter   │─┼──►│   GET  /assets/* (dist/)     │
│ │ CodeMirror 6 view, panels,   │   │ EditorServer-  │ │   │            │                 │
│ │ lint merge, completion,      │   │ Host / Rulezet-│ │   │   Backend  ▼                 │
│ │ hover, locks, documents      │   │ Host / custom  │ │   │   Function | Local |         │
│ └──────────────┬───────────────┘   └────────────────┘ │   │   RulezetApi | Chain         │
│                │ registry                             │   └──────────────────────────────┘
│ ┌──────────────▼───────────────┐                      │
│ │ Language pack (yara, plain)  │ pure functions:      │
│ │ parse, lint, complete, hover │ text in, data out    │
│ └──────────────────────────────┘                      │
└───────────────────────────────────────────────────────┘
```

Three layers, one rule each:

| Layer | Knows | Never does |
|---|---|---|
| **Core** (`src/core/`, `src/ui/`) | the editor engine (CodeMirror 6), the DOM, panels, timers, events | parse a format |
| **Language pack** (`src/languages/<id>/`) | one rule format | network, DOM, engine import |
| **Host adapter** (`src/host/`) | one backend | parse a rule |

Because of this split, every pack feature works offline, and every host feature is optional: when
the adapter lacks a method (`host.has('validate')` is false), the matching UI is hidden.

## 2. Repository map

```
src/index.js                  public entry: registers the bundled packs, exports everything
src/core/RulezetEditor.js     the editor class (≈1400 lines, the heart)
src/core/registry.js          registerLanguage / getLanguage / detectLanguage / languageForFile
src/core/tokens.js            shared token kinds -> CodeMirror highlight tags (--rze-<kind> colors)
src/core/theme.js             light / dark / auto (follows data-bs-theme, body.dark-mode, the OS)
src/core/events.js            tiny emitter (on / off / emit)
src/core/i18n.js              en + fr strings of the UI
src/ui/                       rules panel (outline.js), problems panel, command palette, DOM helper
src/host/HostAdapter.js       HostAdapter, LocalDraftHost (drafts in localStorage), HttpHost (fetch + timeout)
src/host/EditorServerHost.js  talks to the editor's own Python server (/editor-api)
src/host/RulezetHost.js       talks to any Rulezet through its public API
src/wrappers/vue.js           createVueComponent(Vue): v-model component
src/languages/yara/           the YARA pack (see §4)
src/languages/plain/          fallback pack: no highlighting, no lint
src/languages/_template/      copy it to start a new pack
src/styles/rulezet-editor.css every color is a CSS variable on .rze
server/rulezet_editor/        Python package: blueprint, backends, local validators, CLI
scripts/build.mjs             esbuild -> dist/ (ESM, IIFE, CSS)
scripts/dev.mjs               playground + rebuild on change (npm run dev)
scripts/yara-modules.mjs      regenerates yara/modules-data.js from libyara's C sources
scripts/yara-oracle/          builds test/fixtures/yara-oracle.json with the real libyara
test/                         conformance suite (every pack), YARA tests, oracle test
playground/                   demo page with samples
dist/                         prebuilt files, committed: hosts without a build step import them
```

`dist/` is committed on purpose: Rulezet has no JS build step, it imports
`/editor-api/assets/rulezet-editor.js` straight from it. **After changing `src/`, run
`npm run build`**, or Rulezet keeps serving the old code.

## 3. Life of the editor

### 3.1 Creation

`new RulezetEditor(element, options)`:

1. Merges `options` with `DEFAULTS` and builds the translator (`locale`).
2. Picks the pack: `options.language`, or `'auto'` → `detectLanguage(text)` asks every registered
   pack's `detect(text)` (score 0..1, the best one ≥ 0.5 wins, else `plain`).
3. Builds the DOM shell: toolbar, editor area, status bar, rules panel, problems panel, toast.
4. Creates the CodeMirror `EditorView` with one list of extensions (`_createView`): line numbers,
   history, folding, bracket matching, auto-close, completion, search, lint gutter, the linter,
   hover tooltips, reference highlighting, rule locks, rename panel, keymap, theme.
   Three *compartments* can be swapped later without rebuilding the view: the language
   (`setLanguage`), read-only (`setReadOnly`) and line wrapping.
5. Renders the toolbar (host buttons can now call `disabled(editor)`), applies the theme and
   watches the page theme, opens the panels asked for, checks for a draft (`draftKey`).
6. Emits `ready` on the next microtask.

### 3.2 The model: parse once per change

Every feature needs the structure of the document. The core asks the pack once per document
version and caches it:

```js
_model(state) {
    if (cache.doc === state.doc && cache.pack === this.pack) return cache.model;   // same text: reuse
    model = this.pack.parse(text);                                                  // pure function
}
```

CodeMirror documents are immutable, so "same object" means "same text". Lint, completion, hover,
folding, the rules panel and the formatter all receive this same model. A pack that throws while
parsing does not break the editor: the core logs it and uses an empty model.

For YARA the model is `{ text, tokens, comments, imports, includes, rules, errors }`, each rule
with its offsets: name, modifiers (`private`, `global`), tags, `meta`, `strings` (kind, modifiers,
identifier range), `condition` tokens, section ranges, braces.

### 3.3 From a keystroke to an underline

```
keystroke
   │
   ├─ updateListener ──► 'change' event, draft saved after 800 ms idle, cursor / active rule refreshed
   │
   └─ CodeMirror linter (300 ms idle) ──► _lintSource(view)
          │
          ├─ 1. local lint      pack.lint(model, options.lint)         instant, offline
          ├─ 2. external rules  'external-rule' diagnostics -> host.getRule(name), cached
          ├─ 3. server check    host.validate(language, text)           only after serverDelay (1.2 s)
          ├─ 4. host results    setAnnotations(...) from the host page  only for the exact same text
          │
          └─ merge, sort, add line/column ─► underlines, gutter, problems panel,
                                             rules panel status, status bar, 'diagnostics' event
```

**1. Local lint.** `pack.lint(model, options)` returns diagnostics
`{ from, to, severity, message, code, fixes }`. Each `fix` becomes a quick-fix action of the
tooltip. When the user applies a fix after the text moved, `_applyFix` runs the lint again and
finds the same problem (same `code`, closest position) before applying the changes, so a fix never
lands in the wrong place.

**2. External rules.** A YARA condition may use a rule that is not in the document. The pack
reports it with `code: 'external-rule'`. If the host has `getRule`, the core asks it once per
name (at most 20 at a time, cached in `_externals`), then relints:

- found → the warning becomes an *info*: "exists on Rulezet (author)", with two actions:
  **Insert from Rulezet** and **Open on Rulezet**;
- missing → the message says "not found on Rulezet".

Insert puts the rule above the rule that uses it, moves its `import` lines to the top (only the
missing ones), and **locks** it (§3.6).

**3. Server check.** The real compiler is the final word, but calling it on every keystroke would
flood the server. Rules:

- never while the local lint still sees a syntax error (`code: 'syntax'` or `'no-condition'`):
  the server would only repeat it;
- only after `serverDelay` ms without typing (default 1200), and a new keystroke cancels the timer;
- the answer is kept with the exact text it was computed on (`_server.text`); it is shown only
  while the document is still that text. Typing again hides it until the next answer.

Server items have a `line` (and maybe a `column`), not offsets. The core places them on that line
and drops duplicates: a server error on a line that already has a local error, or a message that
names a word a local diagnostic already points at (`undefined identifier "$a"` twice is noise).
The status bar shows the server state: `off`, `waiting`, `pending`, `checking`, `ok`, `error`.

**4. Host results.** The host page may run its own checks (Rulezet's "Check" button) and give the
results to the editor with `setAnnotations({ diagnostics, rules, source })`. Same rule as the
server: they are shown only while the text is the one they were computed on; the first change
drops them and emits `annotationsCleared`. `rules` adds a badge and notes per rule in the rules
panel.

After the merge, `_afterLint` recomputes the rules panel (`pack.splitRules(model)` + errors /
warnings counted per rule range + host annotation + lock), the problems panel and the status bar,
then emits `diagnostics`. With `outline: 'auto'` the rules panel opens by itself as soon as the
document has two rules.

### 3.4 Completion

CodeMirror calls `_completionSource` while typing (60 ms) or on Ctrl+Space:

1. `pack.complete({ text, pos, parsed, explicit })` returns `{ from, options, remoteRules }`.
   The YARA pack looks at where the cursor is (top level, `meta:`, `strings:`, after a string,
   condition, after `pe.`…) and only offers what is valid there.
2. Options are converted: a `snippet` becomes a CodeMirror snippet with tab stops (`{{uuid}}` and
   `{{date}}` are filled at insert time, so each new rule gets its own id); `extraChanges` are
   applied with the insert (e.g. choosing `pe.imports` also adds `import "pe"` at the top).
3. If the pack set `remoteRules: 'prefix'` (the cursor is on a rule name in a condition) and the
   host has `searchRules`, the core asks the host. The call is raced against a 1.5 s timeout and
   cached per prefix, so a slow server never freezes the list; remote names come after local ones.

### 3.5 Hover, go to definition, references, rename

- **Hover** (350 ms): `pack.hover(ctx)` returns `{ from, to, title, body, code? }`. For a name not
  in the document the pack returns `ctx.externalRule(name, token)`; the core then waits up to 2 s
  for `host.getRule` and shows that rule's description, author and a link.
- **Go to definition** (F12, Ctrl+Click): `pack.definition(ctx)` → jump; else, if the word is an
  external rule found on the host, open its URL.
- **References**: `pack.references(ctx)` highlights every occurrence of the `$string` or rule under
  the cursor.
- **Rename** (F2): a small panel asks for the new name, `pack.rename(ctx, newName)` returns all the
  changes (or an error such as "name already used"), applied as one undo step.

### 3.6 Locked rules

A rule inserted from the host is a copy of something that lives elsewhere. Editing it by mistake
would create a silent fork, so it is **locked**:

- `lockRule(name, { label, canUnlock, url })` stores the lock by **rule name**, not by position:
  the lock follows the rule when text is added above it or when the document is formatted;
- a widget bar above the rule says where it comes from; its lines are tinted;
- a *transaction filter* refuses any edit strictly inside a locked rule (with a toast). Deleting
  the whole rule is allowed, and the formatter (`userEvent: 'format'`) may change whitespace;
- `canUnlock` comes from the host (`can_edit` in the rule lookup: in Rulezet, owner or admin).
  When true, the bar has an **Unlock to edit** button; the host page will then see the rule as
  changed and can update it.

### 3.7 Several documents

One editor can hold several documents (`openDocument(id, { text })`). Only one is shown; the
others are kept as saved CodeMirror states with their own undo history, locks, host results and
server answer. Switching swaps all of that at once. `getDocumentText(id)`, `getRulesOf(id)` and
`getModelOf(id)` read a hidden document without showing it (they parse its saved text).

### 3.8 Drafts, toolbar, palette

- **Drafts**: with `draftKey`, the text is saved 800 ms after each change through the host's
  `saveDraft` (default: `localStorage`). On the next load, if a draft differs from the initial
  value, the editor offers to restore it. `clearDraft()` after a successful save.
- **Host buttons**: `buttons: [{ id, label, icon, disabled(editor), run(editor) }]` are rendered in
  the toolbar; the host calls `refreshToolbar()` after its own state changes.
- **Rule tools** (Ctrl+Shift+R): `pack.actions(ctx)` (set author, add date / id / tag / string,
  file type check…); each returns changes, the core applies them and fills `{{uuid}}` / `{{date}}`.
- **Command palette** (Ctrl+Shift+P, F1): every core command plus every rule tool.

### 3.9 Tests on samples

The **Test** button exists when the pack has a `test` profile and the host has `startTest`. The
editor never runs a rule itself: the host (in practice the editor server with
[rulezet-tester](https://github.com/rulezet/rulezet-tester) mounted on `/test`) runs it in a
sandbox. `runTest()` sends the whole document and the ticked sets, then polls `testState` every
`testPollMs` (700 ms) and re-renders the panel (`src/ui/tests.js`) on each answer, so samples turn
from *pending* to a verdict one after the other. `pack.test.hitLabel` writes a hit
(`$lic at 0x14`), `pack.test.locate` finds the matched string in the current model for the
click. Changing the text marks the results as stale. Details: [rulezet/testing.md](rulezet/testing.md).

## 4. The YARA pack

`src/languages/yara/index.js` assembles the pack from files that each do one thing:

| File | Role |
|---|---|
| `highlight.js` | incremental tokenizer used by CodeMirror for colors (line by line, fast) |
| `lexer.js` | whole-document tokens with offsets, used by everything else |
| `parser.js` | error-tolerant parser: one broken rule never hides the next ones |
| `analysis.js` | what a condition refers to, where identifiers are defined, hex / regex / escape checks |
| `condition.js` | condition checker following libyara's grammar (`grammar.y`, 4.5): syntax, types, function arguments, loop variables |
| `lint.js` | every check that needs no compiler (see below) and the quick fixes |
| `modules.js` + `modules-data.js` | every module member with its type and overloads, generated from libyara's sources |
| `completion.js` | context-aware suggestions and the rule templates |
| `navigation.js` | hover, definition, references, rename |
| `format.js` | one layout for every rule that parses cleanly; rules with errors are left as they are |
| `actions.js` | rule tools |
| `keywords.js` | keyword docs for hover and completion |

Why two tokenizers: CodeMirror highlights line by line and must be fast on every keystroke
(`highlight.js`); the parser needs the whole document with exact offsets (`lexer.js`).

### What the lint checks without compiling

Syntax (every rule is still checked after one breaks), undefined / unused / duplicate strings,
`$prefix*` wildcards that match nothing, modules used without `import` and unused imports, unknown
module members and wrong function arguments, rules used before their definition, unknown rules
(→ `external-rule`, §3.3), duplicate rules and tags, invalid modifiers and combinations, `xor`
ranges, base64 alphabets, hex strings (single digit, bad characters, jumps), text escapes,
deprecated `entrypoint`, missing `meta` keys (`requireMeta` option), performance hints (short
atoms, leading wildcards, `.*`).

### How we know the lint is right: the oracle

`scripts/yara-oracle/` runs hundreds of small cases (`cases.py`) through the real libyara (4.5.4)
and stores each verdict in `test/fixtures/yara-oracle.json`. `test/yara-oracle.test.js` checks that
the lint reports an error **exactly** when libyara does. The only deliberate differences: an
undefined identifier (it may be a rule on Rulezet), modules missing from some YARA builds
(`macho`, `magic`, `dex`, `cuckoo`), and `include` files (not available to the editor) are
warnings, not errors.

Adding a lint check: add oracle cases first, rebuild the fixture, then make the test pass.

## 5. Host adapters

All adapters extend `HostAdapter`. `has(method)` is true only when a subclass really implements the
method; the core uses it everywhere to decide what to show.

```
HostAdapter                   has()
 └─ LocalDraftHost            drafts in localStorage (safe when storage is blocked)
     └─ HttpHost              fetch + timeout (8 s) + headers (X-API-KEY, X-CSRFToken) + formatMap
         ├─ EditorServerHost  /editor-api: the editor's own Python server (recommended)
         └─ RulezetHost       /api/rule/public/*: any Rulezet instance, from the browser (needs CORS)
```

`HttpHost._request` turns network failures into readable errors ("Rulezet did not answer within
8 s", "Rulezet not reachable: …"); a `400` still returns its body (a validation answer with
errors is not a failure). `formatMap` translates the pack's `validateAs` into the backend's
format name when they differ.

## 6. The Python server

`server/rulezet_editor/` is a small Flask package, **without a database**. It exists so the
browser code is the same everywhere; only the backend behind it changes.

### 6.1 Endpoints (`web.py`, `create_blueprint(backend)`)

| Endpoint | Does |
|---|---|
| `GET /` | `{ name, formats, features }` |
| `POST /validate` `{ format, content }` | `{ format, valid, items: [{ severity, message, line?, column? }] }`; 400 without format / content, 413 above 512 KB, 404 unknown format, 502 backend failure; empty content is valid |
| `GET /rules?format=&q=&limit=` | `{ results, available }` (limit 1–50) |
| `GET /rules/<name>?format=` | one rule or 404 |
| `GET /assets/<file>` | files of `dist/` (the editor JS and CSS) |

### 6.2 Backends (`backends.py`)

A backend answers three questions; **`None` means "I can't answer"** (unknown format, no database),
so backends can be chained. `BackendError` means "I should answer but failed" and is shown to the
user (HTTP 502).

| Backend | Answers with |
|---|---|
| `FunctionBackend(validate=, search_rules=, get_rule=)` | functions of the host application, in its own process (Rulezet) |
| `LocalBackend()` | compilers installed here (`validators.py`: yara-python); no rule lookup |
| `RulezetApiBackend(url, api_key)` | a Rulezet instance over its public API (`urllib`, 8 s timeout) |
| `ChainBackend(a, b)` | the first backend that does not return `None` |

Two helpers normalise whatever the host returns:

- `validation_result(value)` accepts `{ errors, warnings }`, an object with those attributes
  (Rulezet's `validate_rule_syntax`), or a list; messages like `line 3: syntax error` are split
  into `{ line: 3, message: 'syntax error' }` so the browser can place them.
- `rule_item(value)` turns a Rulezet `Rule` (`title`, `to_string`…) or a dict into
  `{ name, uuid, description, author, content, url, can_edit }`.

### 6.3 Standalone mode

```bash
rulezet-editor serve                                  # http://127.0.0.1:5174/
rulezet-editor serve --rulezet-url https://my.rulezet --api-key ...
rulezet-editor serve --offline                        # local compilers only
```

`create_app()` mounts the blueprint on `/editor-api` with
`ChainBackend(LocalBackend(), RulezetApiBackend(url))` and serves the playground on `/`:
YARA is compiled on the machine, rule lookup goes to Rulezet's public API.

## 7. Inside Rulezet

### 7.1 Wiring

- The repository is a git submodule at `app/modules/rulezet-editor`, installed with
  `pip install -e` (requirements.txt). `update.sh` / `manage.py update` move it to its remote
  branch; `launch.sh` / `start-dev` install it when missing.
- `app/features/editor/editor_core.py` builds the backend from Rulezet's own functions, so there
  is never an HTTP call (and never one to rulezet.org):
  - `validate` → `rule_core.validate_rule_syntax(fmt, content, resolve_dependencies=True)`: the
    check a rule goes through on creation; a YARA rule is compiled together with the Rulezet rules
    it uses;
  - `search_rules` / `get_rule` → queries through `_active()` (never deleted rules), with
    `can_edit` = owner or admin of that rule.
- `app/features/editor/editor.py` mounts `create_blueprint(backend)` on `/editor-api`, adds a
  `before_request` that answers 401 to anonymous users, and adds Rulezet's own routes (below).

### 7.2 The "YARA editor" tab of the create page

`/rule/create_rule?tab=yara_editor`, component `app/static/js/rule/YaraEditorPanel.js`.

- The editor JS/CSS is loaded **the first time the tab is opened**
  (`import('/editor-api/assets/rulezet-editor.js')`), not on page load.
- Options: `language: 'yara'`, `outline: true`, `author` = the logged-in user (for the "Set author"
  rule tool), `draftKey: 'rulezet-create-yara'`, host
  `new EditorServerHost({ baseUrl: '/editor-api', csrfToken })`, and one host button **Check**.

The user writes or pastes any number of rules. Then:

**Check** (toolbar button, Ctrl+S) — dry run, nothing written:

```
POST /editor-api/yara/plan   { imports: ["pe", ...], rules: [{ name, text }, ...] }
  -> { ok, rules: [{ name, status, errors, depends_on, existing, ... }] }
```

The answer goes back into the editor with `setAnnotations` (a badge per rule in the rules panel,
errors on their lines). It is ignored if the text changed during the check.

**Create** (button under the editor, enabled when there is at least one rule and no local error):

```
1. POST /editor-api/yara/plan          modal "Create N rules": what will happen to each rule
                                       (if the plan already fails: straight to "Nothing was written")
2. user confirms
3. POST /editor-api/yara/jobs          202 { uuid, steps }   background job 'editor_yara_import'
   editor set read-only                (the job checks this exact text)
4. GET  /editor-api/yara/jobs/<uuid>   polled; the modal shows the steps live
5. done   -> created / updated / proposed / reused rules with links, "See the summary"
             (/editor/import-result?created=..&updated=..&proposed=..&reused=..), draft cleared
   failed -> "Fix the errors": the modal closes, errors are put on their lines (setAnnotations)
             and the cursor goes to the first one
```

### 7.3 What the server decides for each rule (`plan_yara`)

Nothing sent by the browser is trusted: every rule is parsed and compiled again on the server.

1. **Split and name.** Each `text` must start with a rule header; a name used twice in the
   document is an error. Each rule keeps only the `import`s it actually uses.
2. **Already in Rulezet?** (`_existing`) — an active rule with the same `meta: id` / `uuid`, else
   the same content, else the same YARA name. Then:

   | Case | Status | What happens on Create |
   |---|---|---|
   | not in Rulezet | `new` | created (`add_rule_core`, default TLP/PAP tags) |
   | same content (whitespace ignored) | `exists` | not written; reused for the links |
   | changed, user is owner or admin | `update` | new version (`edit_rule_core`, version bumped, history entry) |
   | changed, someone else's rule | `proposal` | edit proposal to the owner + notification; an identical open proposal is not duplicated |

3. **Compile with what it needs.** For each rule to write, the server builds a source:
   needed modules + the rules it references (from the document first, else from Rulezet,
   recursively) + the rule itself, and compiles it with yara-python. On
   `undefined identifier X` it adds `X` (module import, document rule or Rulezet rule) and tries
   again, up to 60 times. Compiler line numbers are brought back to the rule's own lines.
   - error in the rule itself → `error`;
   - error in a rule it needs → `blocked`;
   - name nowhere → `error: Rule "X" is not in the document nor in Rulezet`.
4. **Propagation.** A rule that needs a document rule in `error` / `blocked` becomes `blocked`.
5. `ok` only if every rule is `new`, `exists`, `update` or `proposal`.

**All or nothing**: when `ok` is false, nothing is written; no broken rule is ever saved.

### 7.4 Writing (`create_from_plan`, inside the job)

- Rules are written **dependencies first** (a rule is written after the document rules it needs).
- Then every written rule is linked to each rule it needs with a `yara_condition_ref` relation
  (`source: 'auto'`) — the Dependencies view of the rule page shows them.
- The job (`editor_jobs.py`) keeps its steps in the job payload so the browser can poll them:
  *Already in Rulezet?* → *Syntax* → *Test on samples* (not built yet: `skipped`) →
  *Create, update or propose, and link*. `GET /yara/jobs/<uuid>` is allowed to the creator or an
  admin only and never returns rule texts.

## 8. Debugging checklist

| Symptom | Look at |
|---|---|
| Change in `src/` not visible in Rulezet | `npm run build` (Rulezet serves `dist/`), then hard-reload |
| "could not be loaded … is app/modules/rulezet-editor installed?" | submodule missing or not `pip install -e`'d: `python3 manage.py update` |
| No server errors ever, status bar `off` | the host has no `validate`, or `serverValidation: false` |
| Status bar stays `waiting` | the local lint still sees a syntax error: the server is not asked on purpose |
| Server error shown on the wrong line | the backend message has no `line N:` prefix, or the line counts the compiled prefix (`_line_offset_error`) |
| Lint says error, compiler says OK (or the reverse) | add the case to `scripts/yara-oracle/cases.py`, rebuild the fixture, run `npm test` |
| A rule name never completes | host has no `searchRules`, or the search took more than 1.5 s |
| Can't type inside a rule | it is locked (inserted from the host): unlock it, or it is not yours |
| Check result vanished | normal: host results are dropped on the first change of the text |
| 401 on `/editor-api` | not logged in (Rulezet's `before_request`) |

Tests: `npm test` in the submodule (conformance, YARA, oracle);
`FLASKENV=testing pytest tests_new/editor` in Rulezet (endpoints, plan, import).
