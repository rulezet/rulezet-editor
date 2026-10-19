# Contributing

## Add a new language pack

1. Copy `src/languages/_template` to `src/languages/<format>`.
2. Fill `index.js`: `id`, `name`, `extensions`, `detect`, `comments`.
3. Add highlighting: start with simple token rules, move to a Lezer grammar when a syntax tree
   is needed (multi-rule split, outline, go to definition).
4. Add `keywords.json`, `snippets.json` and `docs.json` (hover text).
5. Optional functions, each one enables a feature: `complete`, `hover`, `lint`, `format`,
   `splitRules`, `outline`, `definitions`, `references`, `dependencies`.
6. Add samples in `test/fixtures/<format>/`: valid rules, invalid rules, a multi-rule file.
7. Run `npm test`. The conformance suite checks every pack: it loads, detects its own fixtures,
   does not throw on garbage input, `splitRules` covers the whole text, lint ranges stay inside
   the text, no network and no DOM access.
8. Run `npm run playground`, try it, open a pull request.

The full pack interface is described in [docs/design.md](docs/design.md#6-language-pack-interface).

## Pack maturity

- basic: highlighting, comments, folding
- standard: plus completion and lint
- full: plus formatting, multiple rules per document, definitions

## Rules

- A language pack never calls a server and never touches the DOM.
- A host adapter never parses a rule.
- No engine-specific type in the pack interface.
