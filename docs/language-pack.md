# Language pack reference

A language pack teaches the editor one rule format. It is a plain object exported by
`src/languages/<id>/index.js`. Only `id` and `name` are required; every other field switches a
feature on.

Rules:

- No network, no DOM, no editor engine import. Pure data and pure functions.
- Positions are character offsets in the document (`from` inclusive, `to` exclusive).
- Functions must not throw, whatever the input (the conformance suite checks it).

Start from `src/languages/_template/`. The YARA pack (`src/languages/yara/`) uses every field.

## Fields

| Field | Type | Enables |
|---|---|---|
| `id`, `name` | string | required |
| `version`, `maturity` | string | shown in docs; maturity is `basic`, `standard` or `full` |
| `extensions` | string[] | `languageForFile()` |
| `detect(text)` | number 0..1 | `language: 'auto'` |
| `validateAs` | string | format name sent to `host.validate()` and `host.searchRules()` (default: `id`) |
| `sample` | string | conformance tests, demos |
| `stream` | tokenizer | highlighting, comment toggle, auto-close brackets |
| `indentUnit` | string | indentation (default four spaces) |
| `snippets` | option[] | "New rule" button and top-level completion |
| `parse(text)` | model | called once per change; every function below receives this model |
| `lint(model, options)` | diagnostic[] | underlines, gutter, problems panel, rules panel status |
| `complete(ctx)` | result | suggestions |
| `hover(ctx)` | hover | tooltips |
| `definition(ctx)` | range | F12, Ctrl+Click |
| `references(ctx)` | refs | highlight of occurrences |
| `rename(ctx, newName)` | changes | F2 |
| `format(model, options)` | result | Shift+Alt+F |
| `splitRules(model)` | rule[] | rules panel, `getRules()`, status bar count |
| `folding(model)` | range[] | fold markers |
| `dependencies(model)` | ref[] | rules used but not defined (host lookup) |

## Tokenizer (`stream`)

```js
stream: {
  startState() { return {}; },
  copyState(state) { return { ...state }; },          // optional
  token(stream, state) { /* advance the stream, return a token kind or null */ },
  languageData: { commentTokens: { line: '//', block: { open: '/*', close: '*/' } } },
}
```

`stream` offers `match(regexOrString, consume = true)`, `next()`, `peek()`, `eat()`, `eatWhile()`,
`eatSpace()`, `skipToEnd()`, `current()`, `eol()`, `sol()`. `token` must always advance.

Token kinds (`src/core/tokens.js`): `keyword`, `section`, `string`, `regexp`, `escape`, `number`,
`atom`, `comment`, `variable`, `name`, `definition`, `property`, `function`, `module`, `modifier`,
`type`, `tag`, `operator`, `bracket`, `punctuation`, `hex`, `hexJump`, `hexWildcard`, `invalid`,
`meta`, `heading`. Each kind has a `--rze-<kind>` color in the theme.

## Diagnostics

```js
{
  from, to,
  severity: 'error' | 'warning' | 'info' | 'hint',
  message: 'String $a is never used in the condition',
  code: 'unused-string',                 // stable id, used to re-find the problem before a fix
  fixes: [{ label: 'Remove $a', changes: [{ from, to, insert: '' }] }],
}
```

Use the code `external-rule` for a reference to something not defined in the document: the core
then asks the host (`getRule`) and turns the warning into "exists on Rulezet" with an insert action.

## Completion

`complete(ctx)` with `ctx = { text, pos, parsed, explicit }` returns `null` or:

```js
{
  from,                                 // start of the word being completed
  options: [{
    label, type, detail, info,          // type: keyword, function, variable, property, module, rule, modifier, section, snippet, constant
    apply: 'text to insert',            // optional, default label
    snippet: 'rule ${name}\n{\n}',      // optional, ${...} are tab stops
    extraChanges: [{ from, to, insert }], // optional, applied together (e.g. add an import)
    boost: 0,
  }],
  remoteRules: 'prefix' | null,         // ask the host for rule names starting with this
}
```

## Hover, definition, references, rename

- `hover(ctx)` returns `{ from, to, title, body, code? }`; `body` is plain text where `` `code` `` spans
  are rendered as code. `ctx.externalRule(name, token)` may be returned for a name not in the
  document: the core looks it up on the host.
- `definition(ctx)` returns `{ from, to }`.
- `references(ctx)` returns `{ kind, name, ranges: [{ from, to }] }`; the first range is the definition.
- `rename(ctx, newName)` returns `{ changes }` or `{ error }`.

## Format

`format(model, options)` returns `{ text, formatted, skipped }` (`skipped`: names of rules left as
they were, usually because they have errors). Formatting must be idempotent.

## Several rules per document

`splitRules(model)` returns one entry per rule:

```js
{ name, from, to, kind, tags: [], detail, text, children: [{ name, from, to, kind }] }
```

The core adds `errors`, `warnings`, `infos` and `line` from the diagnostics.

## Tests

`npm test` runs `test/conformance.test.js` on every folder of `src/languages/`. Add your own
tests next to it (`test/<id>.test.js`), with valid, invalid and multi-rule samples.
