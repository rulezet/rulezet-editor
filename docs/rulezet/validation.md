# Server validation

The editor sends the document after typing stops (`serverDelay`) or on Ctrl+Enter; errors and
warnings from the real compiler appear in the gutter and the problems panel, next to the local lint.

## Contract

- Backend: `validate(fmt, content) -> { valid, items: [{ severity, message, line?, column? }] } | None`
- Endpoint: `POST /editor-api/validate` `{ format, content }` (400 missing field, 404 unknown format,
  413 over 512 KB, 502 backend failure)
- Browser: `EditorServerHost.validate()`, called by `RulezetEditor._runServer`

## Inside Rulezet

Code: `app/features/editor/editor_core.py` (rulezet-core, branch `editor`).

```python
from app.features.rule import rule_core
FunctionBackend(
    validate=lambda fmt, content: rule_core.validate_rule_syntax(fmt, content, resolve_dependencies=True),
    ...
)
```

- `validate_rule_syntax` (`app/features/rule/rule_core.py`) is the check a rule goes through at
  creation: same result in the editor and on save. `None` for an unknown format -> 404.
- `resolve_dependencies=True` compiles a YARA rule with the Rulezet rules it references.
- Messages `line N: ...` are placed on the line by `message_item`.
- CSRF: the page passes `csrfToken` to `EditorServerHost` (header `X-CSRFToken`).

## Standalone

`ChainBackend(LocalBackend(), RulezetApiBackend(url))`: YARA compiled here with yara-python when
installed, other formats sent to `POST /api/rule/public/validate`. `--offline`: local only, other
formats answer 404 and the editor keeps its local lint.

## Tests

`server/tests/test_server.py`: local YARA, chain fallback, host function, endpoint errors.
