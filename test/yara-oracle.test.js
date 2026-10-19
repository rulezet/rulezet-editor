// Lint vs the real compiler: every case in fixtures/yara-oracle.json carries libyara 4.5.4's
// verdict (error message or null). Our lint must report an error exactly when YARA does,
// except for the deliberate differences below.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yara from '../src/languages/yara/index.js';

const cases = JSON.parse(readFileSync(new URL('./fixtures/yara-oracle.json', import.meta.url), 'utf8'));

// warnings on purpose: the rule may come from Rulezet, the module from another YARA build,
// the included file is not available to the editor
const DELIBERATE = /undefined identifier|unknown module "(macho|magic|dex|cuckoo)"|can't open include file/;

test('lint agrees with libyara on every oracle case', () => {
    const disagreements = [];
    for (const c of cases) {
        if (c.error && DELIBERATE.test(c.error)) continue;
        const errors = yara.lint(yara.parse(c.text), { requireMeta: [] }).filter(d => d.severity === 'error');
        if (!!c.error !== errors.length > 0) {
            disagreements.push(`${c.text.trim().slice(-90)}\n    yara: ${c.error}\n    lint: ${errors[0] ? errors[0].message : '-'}`);
        }
    }
    assert.equal(disagreements.length, 0, disagreements.join('\n'));
});
