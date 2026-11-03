"""Rebuilds test/fixtures/sigma-oracle.json: each case with Rulezet's verdict on it — the same
check as Rulezet's SigmaRule.validate: its JSON schema (sigma_schema.json, a copy of Rulezet's
app/features/rule/rule_format/schema_format/sigma_format.json), then pySigma's parsing, then
pySigma's validators, HIGH issues refused.

    node scripts/sigma-oracle/export.mjs          # the pack's own texts (templates, tutorial…)
    .venv/bin/python scripts/sigma-oracle/build.py   # needs pysigma, pyyaml, jsonschema
"""
import json
import pathlib
import sys

import yaml
from jsonschema.validators import validator_for
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validators.core import validators as core_validators

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from cases import C  # noqa: E402

schema = json.loads((HERE / 'sigma_schema.json').read_text())
schema_check = validator_for(schema)(schema)


def verdict(text):
    try:
        rule = yaml.safe_load(text)
        if not isinstance(rule, dict):
            return 'Empty or invalid YAML content or not a single rule object.'
        if isinstance(rule.get('correlation'), dict):
            # Rulezet: a correlation rule is checked by pySigma with the rules it names (none here:
            # Rulezet would look them up in its database — the editor says "not in this document")
            if not rule.get('title') or not (rule['correlation'].get('rules') or []):
                return 'A correlation rule needs a title and correlation.rules'
            try:
                SigmaCollection.from_yaml(text).resolve_rule_references()
            except Exception as e:
                return str(e)[:300]
            return None
        schema_check.validate(json.loads(json.dumps(rule, default=str)))
    except Exception as e:          # yaml / schema
        return str(getattr(e, 'message', e))[:300]
    try:
        collection = SigmaCollection.from_yaml(text)
        issues = SigmaValidator(validators=core_validators.values()).validate_rules(collection)
    except Exception as e:
        return str(e)[:300]
    high = [str(i)[:300] for i in issues if i.severity == SigmaValidationIssueSeverity.HIGH]
    return high[0] if high else None


out = [{'text': t, 'error': verdict(t)} for t in C]
gen = HERE / 'generated.json'
if gen.exists():
    for g in json.loads(gen.read_text()):
        out.append({'text': g['text'], 'error': verdict(g['text']), 'name': g['name']})
dest = HERE.parents[1] / 'test' / 'fixtures' / 'sigma-oracle.json'
dest.write_text(json.dumps(out, indent=1) + '\n')
print(f"{len(out)} cases ({sum(1 for o in out if o['error'])} refused) -> {dest}")
for o in out:
    if o.get('name') and o['error']:
        print(f"  NOT ACCEPTED: {o['name']}: {o['error']}")
