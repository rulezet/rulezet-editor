# Try panel (a sample, strings and condition explained)

**Try** in the toolbar (Ctrl+Shift+Y) opens a panel under the editor: type or paste a small sample
— text (UTF-8, with `\x4D` for any byte, `\n`, `\r`, `\t`, `\\`) or hex bytes (`4D 5A 90 00`) —
and the rule under the cursor (or the one picked in the list) is evaluated on it, in the browser:

- every string: found or not, how many times, at which offsets; a click on `$a` selects it in the
  rule. Text strings with `nocase`, `ascii`, `wide`, `fullword`, `xor`; hex strings with `??`,
  `4?`, `~00`, jumps `[2-4]` `[0-]`, alternatives `( 90 | 91 )`; regexes with `i` / `s`
  (JavaScript's engine);
- the condition as a tree: each `and`, `or`, `not`, `N of`, `#a > 3`, `$a at 0`, `$a in (a..b)`,
  `@a[1]`, `filesize`, `uint16(0)`… with its value;
- the verdict: matches, does not match, or cannot be decided.

What a sample cannot decide shows `?` with the reason: module values (`pe.…`, `math.…`), other
rules, `for` loops, `entrypoint`, `base64` strings, text operators on module values. The logic is
three-valued: `? and false` is false, `? or true` is true, so the verdict stays right when it can.
The panel is a reading aid; the Test panel runs the real engine.

## Contract

- Pack: `debug = { inputBytes(value, mode), evaluate(model, ruleName, bytes) }`
  (`src/languages/yara/debug.js`): `evaluate` returns
  `{ rule, size, verdict: 'match' | 'no_match' | 'unknown', strings: [{ id, kind, hits: [{ offset, length }], unsupported?, note? }], condition }`,
  `condition` being a tree of `{ text, value, kind, note?, children? }`.
- Core: `toggleTry(force)`; panel `src/ui/try.js`. Limits: 1 MB of sample, 50 hits per string,
  a work budget for hex jumps.
- No server call, nothing stored.

## Inside Rulezet

Nothing to wire: the YARA editor tab of the create and edit pages shows it.

## Standalone

Same.

## Tests

`test/debug.test.js`: text modifiers and escapes, hex wildcards / jumps / alternatives / negation,
regexes, the condition tree, three-valued logic.
