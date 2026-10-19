import { test } from 'node:test';
import assert from 'node:assert/strict';
import yara from '../src/languages/yara/index.js';

const lintOf = (src, opts) => yara.lint(yara.parse(src), { requireMeta: [], ...opts });
const codes = (src, opts) => lintOf(src, opts).map(d => d.code);

test('a clean rule has no problem', () => {
    const src = 'import "pe"\nrule ok : t\n{\n    meta:\n        author = "a"\n    strings:\n        $a = "abcd" wide ascii\n        $h = { 4D 5A ?? 00 [2-4] 50 }\n        $r = /ab+cd/i\n    condition:\n        pe.is_pe and any of them\n}\n';
    assert.deepEqual(lintOf(src), []);
});

test('several rules are parsed, one broken rule does not hide the others', () => {
    const m = yara.parse('rule a { condition: true }\nrule b { strings: $x = "zzzz" condition: $x and ( }\nrule c { condition: a }');
    assert.deepEqual(m.rules.map(r => r.name), ['a', 'b', 'c']);
    assert.equal(m.rules[2].errors.length, 0);
});

test('undefined, unused and duplicate strings', () => {
    const c = codes('rule r { strings: $a = "abcd" $a = "efgh" $b = "ijkl" condition: $a and $z }');
    assert.ok(c.includes('duplicate-string'));
    assert.ok(c.includes('unused-string'));
    assert.ok(c.includes('undefined-string'));
});

test('wildcards and them count as uses', () => {
    assert.deepEqual(codes('rule r { strings: $s1 = "abcd" $s2 = "efgh" condition: any of ($s*) }'), []);
    assert.deepEqual(codes('rule r { strings: $s1 = "abcd" condition: all of them }'), []);
    assert.deepEqual(codes('rule r { strings: $a = "abcd" condition: for any i in (1..#a) : ( @a[i] < 10 ) }'), []);
});

test('modules must be imported, with a fix', () => {
    const d = lintOf('rule r { condition: pe.is_pe }').find(x => x.code === 'module-not-imported');
    assert.ok(d);
    assert.equal(d.fixes[0].changes[0].insert, 'import "pe"\n\n');
});

test('unknown module member and unused import', () => {
    const c = codes('import "pe"\nimport "math"\nrule r { condition: pe.nope }');
    assert.ok(c.includes('unknown-member'));
    assert.ok(c.includes('unused-import'));
});

test('rule order and external rules', () => {
    const c = codes('rule a { condition: b and other }\nrule b { condition: true }');
    assert.ok(c.includes('rule-order'));
    assert.ok(c.includes('external-rule'));
    const deps = yara.dependencies(yara.parse('rule a { condition: other }'));
    assert.deepEqual(deps.map(d => d.name), ['other']);
});

test('modifiers: kind, conflicts, xor range, base64 alphabet', () => {
    const c = codes('rule r { strings: $a = "abcd" nocase xor $h = { 4D 5A 90 } wide $x = "abcd" xor(1-300) $b = "abcd" base64("abc") condition: all of them }');
    assert.ok(c.includes('modifier-conflict'));
    assert.ok(c.includes('modifier-kind'));
    assert.ok(c.includes('xor-range'));
    assert.ok(c.includes('base64-alphabet'));
});

test('hex strings', () => {
    const c = codes('rule r { strings: $a = { 4D 5 } $b = { [2] 4D 5A 90 } $c = { 4D 5A [4-2] 90 } $d = { 4D GG 5A 90 } condition: all of them }');
    assert.equal(c.filter(x => x === 'hex').length, 4);
});

test('text escapes and empty strings', () => {
    const c = codes('rule r { strings: $a = "ab\\qcd" $b = "" condition: all of them }');
    assert.ok(c.includes('escape'));
    assert.ok(c.includes('empty-string'));
});

test('missing meta is an info with a fix', () => {
    const d = yara.lint(yara.parse('rule r { condition: true }')).find(x => x.code === 'missing-meta');
    assert.equal(d.severity, 'info');
    assert.ok(d.fixes[0].changes[0].insert.includes('author = ""'));
});

test('formatter keeps comments and aligns', () => {
    const src = 'rule x : t {\nmeta:\n author="a" // who\nstrings:\n// lead\n $a="x" wide\n $long={4D   5A}\ncondition: $a or $long\n}';
    const out = yara.format(yara.parse(src)).text;
    assert.match(out, /^rule x : t\n\{\n    meta:\n        author = "a" \/\/ who\n/);
    assert.match(out, /        \/\/ lead\n        \$a    = "x" wide\n        \$long = \{ 4D 5A \}/);
    assert.match(out, /    condition:\n        \$a or \$long\n\}\n$/);
    // idempotent
    assert.equal(yara.format(yara.parse(out)).text, out);
});

test('formatter leaves broken rules untouched', () => {
    const src = 'rule ok{condition:true}\nrule bad { condition: ( }\n';
    const res = yara.format(yara.parse(src));
    assert.deepEqual(res.skipped, ['bad']);
    assert.ok(res.text.includes('rule bad { condition: ( }'));
});

test('completion: modules, members, strings, modifiers', () => {
    const at = (src) => yara.complete({ text: src, pos: src.length, parsed: yara.parse(src) });
    assert.ok(at('rule r {\n condition:\n  pe.sec').options.some(o => o.label === 'sections'));
    assert.ok(at('rule r {\n condition:\n  pe.sections[0].').options.some(o => o.label === 'name'));
    assert.deepEqual(at('rule r {\n strings:\n  $abc = "x"\n condition:\n  $').options.map(o => o.label), ['$abc']);
    assert.ok(at('rule r {\n strings:\n  $a = "x" ').options.some(o => o.label === 'wide'));
    assert.ok(!at('rule r {\n strings:\n  $a = { 4D } ').options.some(o => o.label === 'wide'));
    assert.ok(at('import "').options.some(o => o.label === 'pe'));
    const mod = at('rule r {\n condition:\n  ma').options.find(o => o.label === 'math');
    assert.equal(mod.extraChanges[0].insert, 'import "math"\n\n');
});

test('rename a string and a rule', () => {
    const src = 'rule a { condition: true }\nrule b { strings: $x = "abcd" condition: $x and #x > 1 and a }';
    const m = yara.parse(src);
    const r1 = yara.rename({ text: src, pos: src.indexOf('$x and') + 1, parsed: m }, 'name');
    assert.equal(r1.changes.length, 3);
    const r2 = yara.rename({ text: src, pos: src.indexOf(' a }') + 1, parsed: m }, 'base');
    assert.equal(r2.changes.length, 2);
    assert.ok(yara.rename({ text: src, pos: 0, parsed: m }, 'x').error);
});

test('definition and hover', () => {
    const src = 'import "pe"\nrule b { strings: $x = "abcd" condition: $x and pe.is_dll() }';
    const m = yara.parse(src);
    const def = yara.definition({ text: src, pos: src.lastIndexOf('$x') + 1, parsed: m });
    assert.equal(src.slice(def.from, def.to), '$x');
    const h = yara.hover({ text: src, pos: src.indexOf('is_dll') + 1, parsed: m });
    assert.match(h.title, /is_dll\(\)/);
});

test('rule tools: date, id, tag, string, PE check, private', () => {
    const apply = (t, changes) => {
        for (const c of [...changes].sort((a, b) => b.from - a.from)) t = t.slice(0, c.from) + c.insert + t.slice(c.to);
        return t.replace('{{uuid}}', '123e4567-e89b-42d3-a456-426614174000').replace(/\{\{date\}\}/g, '2026-10-19');
    };
    const run = (t, id, value) => {
        const ctx = { text: t, pos: 10, parsed: yara.parse(t), author: 'me' };
        const action = yara.actions(ctx).find(a => a.id === id);
        const res = action.run(ctx, value);
        assert.ok(Array.isArray(res), `${id}: ${res && res.error}`);
        return apply(t, res);
    };
    let t = 'rule demo\n{\n    strings:\n        $a = "evil"\n    condition:\n        $a or uint8(0) == 1\n}';
    t = run(t, 'yara.date');
    assert.match(t, /meta:\n        date = "2026-10-19"/);
    t = run(t, 'yara.date');
    assert.match(t, /modified = "2026-10-19"/);
    t = run(t, 'yara.id');
    t = run(t, 'yara.tag', 'apt ransomware');
    t = run(t, 'yara.string', 'bad.com');
    t = run(t, 'yara.pe');
    t = run(t, 'yara.private');
    assert.match(t, /^private rule demo : apt ransomware/);
    assert.match(t, /\$s1 = "bad.com"/);
    assert.match(t, /uint16\(0\) == 0x5A4D and \(\$a or uint8\(0\) == 1 or \$s1\)/);
    const errors = yara.lint(yara.parse(t), { requireMeta: [] }).filter(d => d.severity !== 'info');
    assert.deepEqual(errors, []);
    const ctx = { text: t, pos: 10, parsed: yara.parse(t) };
    assert.ok(yara.actions(ctx).find(a => a.id === 'yara.tag').run(ctx, '1bad').error);
});
