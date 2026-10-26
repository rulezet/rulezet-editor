// Fields panel logic (src/core/fields.js) with the YARA pack's meta read / write.
import test from 'node:test';
import assert from 'node:assert/strict';
import yara from '../src/languages/yara/index.js';
import { fieldStatus, initialState, readField, sameValue, toMetaValue, validItem } from '../src/core/fields.js';

const CVE = { id: 'cve', label: 'CVE', type: 'list', pattern: '^CVE-\\d{4}-\\d{4,}$', upper: true,
              meta: { key: 'cve', aliases: ['cve_id'], extract: 'cve', extractFrom: ['reference', 'description'] } };
const AUTHOR = { id: 'author', label: 'Author', type: 'text', meta: { key: 'author', aliases: ['creator'] } };
const TITLE = { id: 'title', label: 'Title', type: 'text' };       // host only: never written into the rule

const RULE = `rule r
{
    meta:
        creator = "Alice"
        reference = "https://nvd.nist.gov/vuln/detail/cve-2024-3094"
        cve_id = "CVE-2021-44228, CVE-2024-3094"
    strings:
        $a = "x"
    condition:
        $a
}
`;
const entries = (text) => yara.meta.entries(yara.parse(text), 'r');
const apply = (t, ch) => [...ch].sort((a, b) => b.from - a.from).reduce((s, c) => s.slice(0, c.from) + c.insert + s.slice(c.to), t);

test('reads a field through its aliases and extracts CVE ids from other keys', () => {
    assert.equal(readField(AUTHOR, entries(RULE)), 'Alice');
    assert.deepEqual(readField(CVE, entries(RULE)).map(i => i.value).sort(), ['CVE-2021-44228', 'CVE-2024-3094']);
    assert.equal(readField(TITLE, entries(RULE)), null);
    assert.equal(readField(AUTHOR, entries('rule r { condition: true }')), null);
});

test('initial state is filled from the rule; host-only fields are never reported', () => {
    const s = initialState([CVE, AUTHOR, TITLE], entries(RULE), true);
    assert.equal(s.values.author, 'Alice');
    assert.equal(s.values.cve.length, 2);
    assert.deepEqual(s.report, { cve: true, author: true, title: false });
    assert.equal(initialState([AUTHOR], entries(RULE), false).report.author, false);
});

test('statuses: synced, conflict, kept, host only, rule only', () => {
    const e = entries(RULE);
    const s = initialState([AUTHOR, TITLE], e, true);
    assert.equal(fieldStatus(AUTHOR, s, readField(AUTHOR, e)), 'synced');
    s.values.author = 'Bob'; s.report.author = false;
    assert.equal(fieldStatus(AUTHOR, s, readField(AUTHOR, e)), 'conflict');
    s.keep.author = true;
    assert.equal(fieldStatus(AUTHOR, s, readField(AUTHOR, e)), 'kept');
    s.values.title = 'My title';
    assert.equal(fieldStatus(TITLE, s, null), 'host');
    s.values.author = '';
    assert.equal(fieldStatus(AUTHOR, s, readField(AUTHOR, e)), 'rule');
});

test('lists compare as sets and are written joined', () => {
    const a = [{ value: 'CVE-1', label: 'CVE-1' }, { value: 'CVE-2', label: 'CVE-2' }];
    assert.ok(sameValue(CVE, a, [...a].reverse()));
    assert.ok(!sameValue(CVE, a, a.slice(1)));
    assert.equal(toMetaValue(CVE, a), 'CVE-1, CVE-2');
    assert.ok(validItem(CVE, 'cve-2024-12345') && !validItem(CVE, 'hello'));
});

test('write then read gives the same value back', () => {
    let text = 'rule r\n{\n    condition:\n        true\n}\n';
    const value = [{ value: 'CVE-2024-3094', label: 'CVE-2024-3094' }];
    text = apply(text, yara.meta.set(yara.parse(text), 'r', 'cve', toMetaValue(CVE, value)));
    assert.ok(sameValue(CVE, readField(CVE, entries(text)), value));
    assert.equal(yara.lint(yara.parse(text), { requireMeta: [] }).filter(d => d.severity === 'error').length, 0);
    text = apply(text, yara.meta.remove(yara.parse(text), 'r', 'cve'));
    assert.equal(readField(CVE, entries(text)), null);
});

test('ATT&CK ids are pulled out of the key and of tags, words dropped', () => {
    const ATTACK = { id: 'attack', type: 'list', meta: { key: 'mitre_attack', extract: 'attack', extractFrom: ['tags'] } };
    const e = [{ key: 'mitre_attack', value: 'T1059.001, PowerShell' }, { key: 'tags', value: 'loader T1105' }];
    assert.deepEqual(readField(ATTACK, e).map(i => i.value).sort(), ['T1059.001', 'T1105']);
});

test('version stepper follows the Rulezet picker: minor 0..9 with carry, never below 1.0', async () => {
    const { stepVersion } = await import('../src/core/fields.js');
    assert.equal(stepVersion('1.0', 1), '1.1');
    assert.equal(stepVersion('1.9', 1), '2.0');
    assert.equal(stepVersion('2.0', -1), '1.9');
    assert.equal(stepVersion('1.0', -1), '1.0');
    assert.equal(stepVersion('', 1), '1.1');
    assert.equal(stepVersion('3', 1), '3.1');
});

test('chip colours: item colour first, then prefix; readable text', async () => {
    const { chipColor, textOn } = await import('../src/core/fields.js');
    const def = { chipColors: [{ prefix: 'CVE-', color: '#dc3545' }, { prefix: 'GHSA-', color: '#ffc107' }] };
    assert.equal(chipColor(def, { label: 'CVE-2024-1' }), '#dc3545');
    assert.equal(chipColor(def, { label: 'ghsa-xxxx' }), '#ffc107');
    assert.equal(chipColor(def, { label: 'x', color: '#000000' }), '#000000');
    assert.equal(textOn('#ffc107'), '#1f2328');
    assert.equal(textOn('#dc3545'), '#ffffff');
});

test('tags: header tags and meta tags are read; the title starts as the rule name', async () => {
    const TAGS = { id: 'tags', type: 'list', meta: { key: 'tags', aliases: ['tag', '@tags'], split: '[,;\\s]+' } };
    const TITLE = { id: 'title', type: 'text', fromRuleName: true };
    const text = 'rule r : apt loader\n{\n    meta:\n        tags = "tlp:clear, family_x"\n    condition:\n        true\n}\n';
    const e = yara.meta.entries(yara.parse(text), 'r');
    assert.deepEqual(readField(TAGS, e).map(i => i.value).sort(), ['apt', 'family_x', 'loader', 'tlp:clear']);
    const s = initialState([TAGS, TITLE], e, false, 'r');
    assert.equal(s.values.title, 'r');
});
