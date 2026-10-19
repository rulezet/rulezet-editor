# Integrating features into Rulezet

One file per feature. Each one says how the feature runs **inside Rulezet** (integrated mode,
the priority) and how it runs **standalone** (public Rulezet API). A feature is not done until
its file exists here.

| Feature | File | Rulezet side | Standalone side |
|---|---|---|---|
| Server validation | [validation.md](validation.md) | `rule_core.validate_rule_syntax` | local compiler, then `POST /api/rule/public/validate` |
| Rule lookup (completion, hover, external rules) | [rule-lookup.md](rule-lookup.md) | query on `Rule` via `_active()` | `GET /api/rule/public/searchPage` |

New feature: copy [_template.md](_template.md).
