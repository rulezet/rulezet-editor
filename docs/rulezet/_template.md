# <Feature name>

What the user sees, in one or two sentences.

## Contract

- Backend method: `name(args) -> result | None` (`server/rulezet_editor/backends.py`)
- Endpoint: `METHOD /editor-api/...` (`web.py`)
- Browser: `EditorServerHost.method()` and where the editor uses it

## Inside Rulezet

- Rulezet function(s) used (file, name), or the function to add in `rulezet-core`.
- `FunctionBackend(...)` argument to pass in Rulezet's `create_app`.
- Permissions, CSRF, settings (`app/config/<key>.json`), activity log, if any.
- Never an HTTP call to rulezet.org.

## Standalone

- Public API endpoint used (`RulezetApiBackend`), or local implementation.
- What happens when it is not available (feature hidden, `None`).

## Tests

- `server/tests/...` (no network), `test/...` for the browser part.
