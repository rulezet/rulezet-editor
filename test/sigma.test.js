// Sigma pack: parsing, lint fixes, completion, navigation, Fields panel, rule tools, several rules.
import test from 'node:test';
import assert from 'node:assert/strict';
import sigma from '../src/languages/sigma/index.js';
import { parseYaml } from '../src/languages/sigma/yaml.js';

const U = '929a690e-bef0-4204-a928-ef5e620d6fcc';
const RULE = `title: Test rule
id: ${U}
status: test
description: A test
date: 2026-01-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\evil.exe'
    filter_main:
        User: admin
    condition: selection and not filter_main
level: medium
`;

const P = (t) => sigma.parse(t);
const errors = (t) => sigma.lint(P(t)).filter(d => d.severity === 'error');
const fill = (s) => s.replace(/\{\{uuid\}\}/g, U).replace(/\{\{date\}\}/g, '2026-11-03');
function apply(text, changes) {
    const sorted = [...changes].sort((a, b) => b.from - a.from);
    for (const c of sorted) text = text.slice(0, c.from) + fill(c.insert) + text.slice(c.to);
    return text;
}
const fixOf = (text, code, i = 0) => {
    const d = sigma.lint(P(text)).find(x => x.code === code);
    assert.ok(d, `no ${code} in\n${text}`);
    return apply(text, d.fixes[i].changes);
};

test('a good rule has no error and no warning', () => {
    const d = sigma.lint(P(RULE)).filter(x => x.severity !== 'info');
    assert.deepEqual(d, []);
});

test('the model: title, logsource, searches with fields and modifiers, condition tokens', () => {
    const r = P(RULE).rules[0];
    assert.equal(r.name, 'Test rule');
    assert.equal(r.logsource.category.value, 'process_creation');
    assert.deepEqual(r.detection.searches.map(s => s.name), ['selection', 'filter_main']);
    const it = r.detection.searches[0].items[0];
    assert.equal(it.field, 'Image');
    assert.deepEqual(it.modifiers.map(m => m.name), ['endswith']);
    assert.equal(it.values[0].value, '\\evil.exe');
    assert.equal(RULE.slice(it.modifiers[0].from, it.modifiers[0].to), 'endswith');
    assert.deepEqual(r.detection.condition[0].tokens.map(t => t.type), ['ident', 'and', 'not', 'ident']);
});

test('yaml: block scalars, flow lists, quotes, comments, multi-line condition', () => {
    const [d] = parseYaml("a: |\n    x\n    y\nb: [1, 'two', \"th\\\"ree\"]\nc: 'it''s' # comment\nd:\n    e and\n    f\n");
    const js = Object.fromEntries(d.root.entries.map(e => [e.key, e.value.type === 'seq' ? e.value.items.map(i => i.value) : e.value.value]));
    assert.deepEqual(js, { a: 'x\ny\n', b: ['1', 'two', 'th"ree'], c: "it's", d: 'e and f' });
});

test('fixes make the rule valid: unused search, unknown identifier, missing condition, bad modifier, bad status, all without contains', () => {
    const unused = RULE.replace('selection and not filter_main', 'selection');
    assert.equal(errors(unused)[0].code, 'unused-search');
    assert.deepEqual(errors(fixOf(unused, 'unused-search')), []);
    assert.match(fixOf(unused, 'unused-search'), /condition: selection and not filter_main/);

    const typo = RULE.replace('selection and not', 'selectoin and not');
    assert.deepEqual(errors(fixOf(typo, 'unknown-search')), []);

    const noCond = RULE.replace(/\n    condition: .*/, '');
    assert.ok(errors(fixOf(noCond, 'condition-required')).every(e => e.code === 'unused-search' || e.code === 'condition-required') );

    const mod = RULE.replace('|endswith', '|endswiht');
    assert.deepEqual(errors(fixOf(mod, 'unknown-modifier')), []);

    const status = RULE.replace('status: test', 'status: tset');
    assert.deepEqual(errors(fixOf(status, 'status-value')), []);

    const all = RULE.replace("Image|endswith: '\\evil.exe'", "Image|all:\n            - a\n            - b");
    assert.deepEqual(errors(fixOf(all, 'all-without-contains')), []);

    const id = RULE.replace(U, 'nope');
    assert.deepEqual(errors(fixOf(id, 'id-uuid')), []);
});

test('condition syntax errors are placed on the token', () => {
    const t = RULE.replace('selection and not filter_main', 'selection and and filter_main');
    const e = errors(t).find(x => x.code === 'condition-syntax');
    assert.equal(t.slice(e.from, e.to), 'and');
    assert.equal(errors(RULE.replace('selection and not filter_main', '2 of selection or filter_main'))[0].code, 'condition-quantifier');
});

test('completion: top keys, logsource values, modifiers, condition identifiers, tags', () => {
    const at = (text, marker = '|') => {
        const pos = text.indexOf('§');
        const t = text.replace('§', '');
        return sigma.complete({ text: t, pos, parsed: P(t), explicit: true });
    };
    const labels = (r) => r.options.map(o => o.label);
    assert.ok(labels(at('title: x\n§')).includes('logsource'));
    assert.ok(!labels(at('title: x\n§')).includes('title'));
    assert.ok(labels(at('title: x\nlogsource:\n    category: proc§')).includes('process_creation'));
    assert.ok(labels(at('title: x\nlogsource:\n    product: windows\n    §')).includes('service'));
    const m = at(RULE.replace("Image|endswith: '\\evil.exe'", 'Image|end§'));
    assert.ok(labels(m).includes('endswith'));
    const c = at(RULE.replace('condition: selection and not filter_main', 'condition: selection and not §'));
    assert.ok(labels(c).includes('filter_main'));
    assert.ok(labels(at(RULE.replace('    - attack.t1059', '    - attack.exe§'))).includes('attack.execution'));
    assert.ok(labels(at(RULE.replace('status: test', 'status: §'))).includes('experimental'));
    assert.ok(labels(at(RULE.replace("        Image|endswith: '\\evil.exe'", '        Comm§'))).includes('CommandLine'));
});

test('hover, definition, references and rename of a search identifier', () => {
    const pos = RULE.lastIndexOf('filter_main') + 2;
    assert.match(sigma.hover({ text: RULE, pos, parsed: P(RULE) }).title, /filter_main/);
    const def = sigma.definition({ text: RULE, pos, parsed: P(RULE) });
    assert.equal(RULE.slice(def.from, def.to), 'filter_main');
    assert.ok(def.from < pos);
    const res = sigma.rename({ text: RULE, pos, parsed: P(RULE) }, 'filter_admin');
    const renamed = apply(RULE, res.changes);
    assert.match(renamed, /filter_admin:\n/);
    assert.match(renamed, /not filter_admin/);
    assert.deepEqual(errors(renamed), []);
    assert.match(sigma.hover({ text: RULE, pos: RULE.indexOf('endswith') + 1, parsed: P(RULE) }).body, /ends with/);
});

test('Fields panel: entries, set / remove (ATT&CK and CVE go to the tags), skeleton, rename', () => {
    const m = P(RULE);
    const e = sigma.meta.entries(m, 'Test rule');
    assert.ok(e.some(x => x.key === 'mitre_attack' && x.value === 'T1059'));
    assert.ok(e.some(x => x.key === 'description' && x.value === 'A test'));

    let t = apply(RULE, sigma.meta.set(m, 'Test rule', 'mitre_attack', 'T1059, T1105.001'));
    assert.match(t, /- attack\.t1105\.001/);
    assert.match(t, /- attack\.execution/);
    t = apply(t, sigma.meta.set(P(t), 'Test rule', 'cve', 'CVE-2024-3094'));
    assert.match(t, /- cve\.2024-3094/);
    t = apply(t, sigma.meta.set(P(t), 'Test rule', 'author', 'Me: myself'));
    assert.match(t, /\nauthor: 'Me: myself'\n/);
    assert.ok(t.indexOf('author:') < t.indexOf('date:'), 'author goes before date (spec order)');
    t = apply(t, sigma.meta.set(P(t), 'Test rule', 'references', 'https://a.example, https://b.example'));
    assert.match(t, /references:\n    - https:\/\/a\.example\n    - https:\/\/b\.example/);
    assert.deepEqual(errors(t), []);
    t = apply(t, sigma.meta.remove(P(t), 'Test rule', 'mitre_attack'));
    assert.doesNotMatch(t, /attack\.t1/);
    assert.match(t, /attack\.execution/);
    assert.deepEqual(errors(t), []);

    const sk = fill(sigma.meta.skeleton('My new rule'));
    assert.deepEqual(errors(sk), []);
    assert.equal(P(sk).rules[0].name, 'My new rule');
    const renamed = apply(sk, sigma.meta.renameRule(P(sk), 'My new rule', 'Renamed: rule'));
    assert.equal(P(renamed).rules[0].name, 'Renamed: rule');
});

test('rule tools', () => {
    const ctx = (text) => ({ text, pos: 5, parsed: P(text), author: 'Me' });
    const run = (id, text, value) => sigma.actions(ctx(text)).find(a => a.id === id).run(ctx(text), value);
    const noId = RULE.replace(`id: ${U}\n`, '');
    const withId = apply(noId, run('sigma.id', noId));
    assert.match(withId, /^title: Test rule\nid: 929a/);
    assert.ok(run('sigma.id', RULE).error);
    assert.match(apply(RULE, run('sigma.date', RULE)), /modified: 2026-11-03/);
    const tagged = apply(RULE, run('sigma.attack', RULE, 'T1105'));
    assert.match(tagged, /    - attack\.t1059\n    - attack\.t1105\n/);
    const filtered = apply(RULE, run('sigma.filter', RULE, 'filter_optional_x'));
    assert.match(filtered, /condition: selection and not filter_main and not filter_optional_x/);
    assert.deepEqual(errors(filtered), []);
    const newId = apply(RULE, run('sigma.newId', RULE));
    assert.match(newId, new RegExp(`related:\\n    - id: ${U}\\n      type: derived`));
});

test('several rules: one per --- document, duplicates refused', () => {
    const two = RULE + '---\n' + RULE.replace('Test rule', 'Other rule').replace(U, '0f0b2b8a-0f0e-4c63-9a5c-3d6b1c2e4f10');
    const rules = sigma.splitRules(P(two));
    assert.deepEqual(rules.map(r => r.name), ['Test rule', 'Other rule']);
    assert.equal(rules[1].text.trim(), two.split('---\n')[1].trim());
    assert.deepEqual(errors(two), []);
    const dup = RULE + '---\n' + RULE;
    const codes = errors(dup).map(e => e.code);
    assert.ok(codes.includes('duplicate-id') && codes.includes('duplicate-title'));
    assert.ok(sigma.folding(P(RULE)).length >= 4);
});

test('correlation rules: checked like pySigma, the rules they name looked for in the document', () => {
    const base = RULE.replace('title: Test rule', 'title: Test rule\nname: test_rule');
    const corr = (body) => `title: Many hits\nid: 0f0b2b8a-0f0e-4c63-9a5c-3d6b1c2e4f10\ncorrelation:\n${body}\nlevel: high\n`;
    const good = corr('    type: event_count\n    rules:\n        - test_rule\n    group-by:\n        - User\n    timespan: 5m\n    condition:\n        gte: 10');
    assert.deepEqual(errors(base + '---\n' + good), []);
    const two = P(base + '---\n' + good);
    assert.equal(sigma.splitRules(two)[1].kind, 'correlation (event_count)');
    const pos = (base + '---\n' + good).lastIndexOf('- test_rule') + 4;
    const def = sigma.definition({ text: base + '---\n' + good, pos, parsed: two });
    assert.ok(def && def.from < base.length, 'F12 goes to the rule it names');
    const alone = sigma.lint(P(good));
    assert.ok(alone.some(d => d.code === 'external-rule' && d.severity === 'info'));
    assert.ok(!alone.some(d => d.severity === 'error'));
    assert.equal(errors(corr('    type: evnt_count\n    rules:\n        - test_rule\n    timespan: 5m\n    condition:\n        gte: 10'))[0].code, 'correlation-type');
    assert.equal(errors(corr('    type: event_count\n    rules:\n        - test_rule\n    timespan: 5m'))[0].code, 'correlation-condition');
    assert.equal(errors(corr('    type: value_count\n    rules:\n        - test_rule\n    timespan: 5m\n    condition:\n        gte: 10'))[0].code, 'correlation-condition');
    assert.deepEqual(errors(corr('    type: temporal\n    rules:\n        - test_rule\n        - other\n    timespan: 1h')), []);
    assert.equal(errors(corr('    type: event_count\n    rules:\n        - test_rule\n    timespan: 1hour\n    condition:\n        gte: 10'))[0].code, 'correlation-timespan');
});

test('form (selections): read, then every edit keeps the rule valid', () => {
    const S = sigma.selections;
    const data = S.read(P(RULE), 'Test rule');
    assert.deepEqual(data.logsource, { category: 'process_creation', product: 'windows', service: '' });
    assert.deepEqual(data.searches.map(s => [s.name, s.kind]), [['selection', 'fields'], ['filter_main', 'fields']]);
    assert.deepEqual(data.searches[0].items[0], { field: 'Image', modifiers: ['endswith'], values: ['\\evil.exe'] });
    assert.equal(data.condition, 'selection and not filter_main');

    let t = apply(RULE, S.setLogsource(P(RULE), 'Test rule', 'category', 'image_load'));
    assert.match(t, /\n    category: image_load\n/);
    t = apply(t, S.setLogsource(P(t), 'Test rule', 'service', 'sysmon'));
    assert.match(t, /    product: windows\n    service: sysmon\n/);
    t = apply(t, S.setLogsource(P(t), 'Test rule', 'service', ''));
    assert.doesNotMatch(t, /service/);
    assert.deepEqual(errors(t), []);

    // a search changed and renamed: the condition follows
    const sel = { ...data.searches[0], name: 'selection_img', items: [{ field: 'Image', modifiers: ['endswith'], values: ['\\a.exe', "\\it's.exe"] }, { field: 'CommandLine', modifiers: ['contains', 'all'], values: ['-x', '-y'] }] };
    t = apply(RULE, S.setSearch(P(RULE), 'Test rule', 0, sel));
    assert.match(t, /    selection_img:\n        Image\|endswith:\n            - '\\a\.exe'\n            - '\\it''s\.exe'\n        CommandLine\|contains\|all:\n/);
    assert.match(t, /condition: selection_img and not filter_main/);
    assert.deepEqual(errors(t), []);
    assert.deepEqual(S.read(P(t), 'Test rule').searches[0].items[1].values, ['-x', '-y']);

    // added: a selection joins with or, a filter with and not, keywords too
    t = apply(t, S.setSearch(P(t), 'Test rule', null, { name: 'selection_2', kind: 'fields', items: [{ field: 'User', modifiers: [], values: ['bob'] }] }));
    t = apply(t, S.setSearch(P(t), 'Test rule', null, { name: 'filter_main_2', kind: 'fields', items: [{ field: 'ParentImage', modifiers: ['endswith'], values: ['\\ok.exe'] }] }));
    t = apply(t, S.setSearch(P(t), 'Test rule', null, { name: 'keywords', kind: 'keywords', keywords: ['evil'] }));
    assert.deepEqual(errors(t), []);
    assert.match(t, /condition: \(selection_img and not filter_main or selection_2\) and not filter_main_2 or keywords/);
    assert.equal(S.setSearch(P(t), 'Test rule', null, { name: 'keywords', kind: 'keywords', keywords: ['x'] }), null, 'name taken');

    // removed: its line and its clause go
    t = apply(t, S.removeSearch(P(t), 'Test rule', S.read(P(t), 'Test rule').searches.findIndex(s => s.name === 'keywords')));
    assert.doesNotMatch(t, /keywords/);
    assert.deepEqual(errors(t), []);

    t = apply(t, S.setCondition(P(t), 'Test rule', '1 of selection* and not 1 of filter_*'));
    assert.match(t, /condition: 1 of selection\* and not 1 of filter_\*\n/);
    assert.deepEqual(errors(t), []);
    assert.deepEqual(S.splitCondition('a and (b or c) or not d').map(p => [p.op, p.text]), [[null, 'a'], ['and', '(b or c)'], ['or', 'not d']]);
    assert.ok(S.clauses(S.read(P(t), 'Test rule').searches).some(c => c.text === 'not 1 of filter_main_*'));
});

test('related: a rule of the document (hover, F12) or one to look up on the host', () => {
    const OTHER = '0f0b2b8a-0f0e-4c63-9a5c-3d6b1c2e4f10';
    const linked = RULE.replace('status: test', `related:\n    - id: ${OTHER}\n      type: derived\nstatus: test`);
    const ext = sigma.lint(P(linked)).find(d => d.code === 'external-rule');
    assert.equal(linked.slice(ext.from, ext.to), OTHER);
    assert.deepEqual(sigma.dependencies(P(linked)).map(d => d.name), [OTHER]);

    const two = linked + '---\n' + RULE.replace('Test rule', 'Other rule').replace(U, OTHER);
    assert.ok(!sigma.lint(P(two)).some(d => d.code === 'external-rule'));
    const pos = two.indexOf(OTHER) + 3;
    assert.match(sigma.hover({ text: two, pos, parsed: P(two) }).title, /Other rule/);
    const def = sigma.definition({ text: two, pos, parsed: P(two) });
    assert.ok(def.from > two.indexOf('---'));
    assert.equal(sigma.ruleSeparator, '---\n');
});

test('format: SigmaHQ layout, same content, idempotent, rules with YAML errors left alone', () => {
    const messy = `logsource:\n  product: windows\n  category: process_creation\ntitle: Messy   \ndetection:\n  selection:\n    Image|endswith:\n    - '\\\\a.exe'\n    - '\\\\b.exe'\n  condition: selection\nrelated:\n- id: ${U}\n  type: derived\ndescription: |\n  line one:\n  - not a list\n---\n\n---\ntitle: Broken\n  bad: indentation\n`;
    const res = sigma.format(P(messy));
    assert.deepEqual(res.skipped, ['Broken']);
    const [first] = res.text.split('---\n');
    assert.equal(first, `title: Messy\nrelated:\n    - id: ${U}\n      type: derived\ndescription: |\n    line one:\n    - not a list\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        Image|endswith:\n            - '\\\\a.exe'\n            - '\\\\b.exe'\n    condition: selection\n`);
    assert.equal(sigma.format(P(res.text)).text, res.text);
    assert.equal((res.text.match(/^---$/gm) || []).length, 1);
    assert.match(res.text, /title: Broken\n  bad: indentation\n$/);
});
