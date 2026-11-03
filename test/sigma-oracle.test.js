// Lint vs Rulezet's own validation of Sigma rules (JSON schema + pySigma, HIGH issues refused):
// every case of fixtures/sigma-oracle.json carries that verdict (scripts/sigma-oracle/build.py).
// The lint must report an error exactly when Rulezet refuses the rule.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import sigma from '../src/languages/sigma/index.js';

const cases = JSON.parse(readFileSync(new URL('./fixtures/sigma-oracle.json', import.meta.url), 'utf8'));

// on purpose: several rules (--- documents) in one text are checked one by one by the editor and
// by Rulezet's /editor-api (validate splits the documents); SigmaRule.validate alone reads one
// and a correlation rule naming rules that are not in the text: Rulezet looks them up in its
// database (the editor says "not in this document" and asks the host)
const DELIBERATE = /expected a single document|not found in rule collection/;

test('lint agrees with Rulezet (schema + pySigma) on every oracle case', () => {
    const disagreements = [];
    for (const c of cases) {
        if (c.error && DELIBERATE.test(c.error)) continue;
        const errors = sigma.lint(sigma.parse(c.text)).filter(d => d.severity === 'error');
        if (!!c.error !== errors.length > 0) {
            disagreements.push(`${c.name || c.text.trim().slice(-120)}\n    rulezet: ${c.error}\n    lint: ${errors[0] ? errors[0].message : '-'}`);
        }
    }
    assert.equal(disagreements.length, 0, disagreements.join('\n'));
});

test('the pack\'s own texts (sample, templates, tutorial, skeleton) are accepted by Rulezet', () => {
    const own = cases.filter(c => c.name);
    assert.ok(own.length >= 15);
    for (const c of own) assert.equal(c.error, null, `${c.name}: ${c.error}`);
});
