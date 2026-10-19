# Rule lookup

Rules that are not in the document: names in completion, hover card, "exists on Rulezet"
diagnostic for `external-rule`, Ctrl+Click to open, insert the rule in the document.

## Contract

- Backend: `search_rules(fmt, query, limit) -> [rule] | None`, `get_rule(fmt, name) -> rule | None`
- Rule: `{ name, uuid, description, author, content, url }` (`rule_item` also accepts Rulezet's `title`)
- Endpoints: `GET /editor-api/rules?format=&q=&limit=` (`limit` max 50),
  `GET /editor-api/rules/<name>?format=` (404 when missing)
- Browser: `EditorServerHost.searchRules()` / `getRule()`

## Inside Rulezet

Code: `app/features/editor/editor_core.py` (rulezet-core, branch `editor`).

```python
from app.core.db_class.rule import Rule
from app.features.rule import rule_core

def _search_rules(fmt, query, limit):
    q = rule_core._active().filter(Rule.title.ilike(f'%{query}%'))
    if fmt:
        q = q.filter(Rule.format == fmt)
    return [{'name': r.title, 'uuid': r.uuid, 'description': r.description, 'author': r.author,
             'content': r.to_string, 'url': f'/rule/detail_rule/{r.uuid}'} for r in q.limit(limit)]

FunctionBackend(search_rules=_search_rules, ...)
```

- Always `_active()`, never `Rule.query`: deleted rules must not show up.
- Without `get_rule`, `FunctionBackend` takes the exact name from `search_rules`. Pass a
  `get_rule` (exact title, `_active()`) if the search gets slow.
- Private rules: filter here once Rulezet has visibility rules for the current user.

## Standalone

`RulezetApiBackend.search_rules` -> `GET /api/rule/public/searchPage?search=&rule_type=&per_page=`,
`url` built as `<base>/rule/detail_rule/<uuid>`. `--offline`: no lookup, `{ results: [], available: false }`.

## Tests

`server/tests/test_server.py`: API search and exact match, host function, endpoints.
