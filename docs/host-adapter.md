# Host adapters

A host adapter is how the editor reaches a backend. It never parses rules: it sends text and
returns plain data. Every method is optional; the editor hides the matching feature when a
method is missing, and works fully offline without an adapter.

```js
import { HostAdapter } from 'rulezet-editor';

class MyHost extends HostAdapter {
  name = 'My SOC';

  // Real compiler / validator. Called after typing stops (serverDelay, default 1.2 s),
  // never while the local lint still sees syntax errors.
  async validate(language, text) {
    return [{ severity: 'error', message: 'syntax error', line: 3, column: 5 }];
  }

  // Rule names for completion (prefix typed in a condition).
  async searchRules(language, query) {
    return [{ name: 'Some_Rule', description: '...', author: '...', url: 'https://...', content: 'rule Some_Rule {...}' }];
  }

  // One rule by exact name: hover, "exists on ..." diagnostics, insert action, Ctrl+Click.
  async getRule(language, name) { return null; }

  // Drafts (default: the browser's localStorage).
  async loadDraft(key) { return { text, savedAt }; }
  async saveDraft(key, text) {}           // text === null removes the draft
}
```

`language` is the pack's `validateAs` (or its `id`).

## EditorServerHost (recommended)

Talks to the editor's server (`server/rulezet_editor`), mounted inside Rulezet or run standalone
(see [integration.md](integration.md)). Same browser code in both modes.

```js
new EditorServerHost({ baseUrl: '/editor-api', csrfToken, name: 'Rulezet', formatMap: {} });
```

| Method | Endpoint |
|---|---|
| `validate` | `POST /validate` `{ format, content }` -> `{ valid, items }` |
| `searchRules` | `GET /rules?format=&q=&limit=` -> `{ results }` |
| `getRule` | `GET /rules/<name>?format=` -> rule or 404 |

Server side, a `Backend` answers each call (`None` = not available, `BackendError` = failed):
`FunctionBackend` (host functions, Rulezet), `LocalBackend` (local compilers),
`RulezetApiBackend` (public API), `ChainBackend` (first answer wins).

## RulezetHost

`RulezetHost` talks to any Rulezet instance through the public API (no account needed):

| Method | Endpoint |
|---|---|
| `validate` | `POST /api/rule/public/validate` `{ format, content }` |
| `searchRules`, `getRule` | `GET /api/rule/public/searchPage?search=&rule_type=&per_page=` |

```js
new RulezetHost({
  baseUrl: '',                 // '' inside Rulezet (same origin), or 'https://rulezet.org'
  apiKey: null,                // X-API-KEY header, optional
  csrfToken: null,             // X-CSRFToken header, optional
  timeout: 8000,
  formatMap: { yara: 'yara' }, // editor language id -> Rulezet format name, when they differ
});
```

From another origin the browser needs CORS on the Rulezet side; the playground avoids it with a
local proxy (`npm run dev`).
