import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from '../src/languages/yara/parser.js';
import { evaluate, inputBytes, parseHex } from '../src/languages/yara/debug.js';

const run = (rule, input, mode = 'text') => {
    const model = parse(rule);
    return evaluate(model, model.rules[0].name, inputBytes(input, mode).bytes);
};
const str = (res, id) => res.strings.find(s => s.id === id);

test('text strings: nocase, wide, fullword, xor, escapes', () => {
    const r = run(`rule t { strings:
        $a = "evil" nocase
        $w = "abc" wide
        $f = "cmd" fullword
        $x = "hi" xor
        $e = "A\\x00B"
      condition: any of them }`, 'xx EVIL a\\x00b\\x00c\\x00 cmd.exe xcmdx \\x29\\x28 A\\x00B');
    assert.equal(str(r, '$a').hits[0].offset, 3);
    assert.equal(str(r, '$w').hits.length, 1);
    assert.equal(str(r, '$f').hits.length, 1);                 // "cmd." yes, "xcmdx" no
    assert.ok(str(r, '$x').hits.length >= 1);                   // "hi" xor 0x41
    assert.equal(str(r, '$e').hits.length, 1);
    assert.equal(r.verdict, 'match');
});

test('hex strings: wildcards, nibbles, jumps, alternatives, negation', () => {
    assert.equal(parseHex('{ 4D 5A [2-4] ( 90 | 91 ) ?? ~00 }').length, 6);
    const r = run(`rule t { strings:
        $h = { 4D 5A [2-4] ( 90 | 91 ) ?? ~00 }
        $n = { 4? 5A }
      condition: $h and $n at 0 }`, '4D 5A 00 00 00 91 FF 01', 'hex');
    assert.deepEqual(str(r, '$h').hits[0], { offset: 0, length: 8 });
    assert.equal(r.verdict, 'match');
});

test('regex strings', () => {
    const r = run('rule t { strings: $r = /https?:\\/\\/[a-z]{3,10}\\.bin/i condition: $r }', 'get HTTP://evil.bin now');
    assert.equal(str(r, '$r').hits[0].offset, 4);
    assert.equal(r.verdict, 'match');
});

test('condition tree: and / or / not, counts, offsets, quantifiers, filesize, uint16', () => {
    const rule = `rule t { strings: $a1 = "aa" $a2 = "bb" $c = "cc"
      condition: uint16(0) == 0x5A4D and filesize < 1KB and (2 of ($a*) or #c > 3) and not $c and @a1[1] == 2 }`;
    const r = run(rule, 'MZaabb');
    assert.equal(r.verdict, 'match');
    const tree = r.condition;
    assert.equal(tree.kind, 'and');
    assert.equal(tree.children.length, 5);
    const q = tree.children[2];
    assert.equal(q.kind, 'or');
    assert.equal(q.children[0].note, '2 of 2 found, 2 needed');
    assert.equal(run(rule, 'MZaa').verdict, 'no_match');
});

test('three-valued logic: what a sample cannot decide', () => {
    const r = run('import "pe"\nrule t { strings: $a = "x" condition: pe.is_dll() and $a }', 'nothing');
    assert.equal(r.verdict, 'no_match');                          // unknown and false = false
    assert.equal(r.condition.children[0].value, null);
    const u = run('import "pe"\nrule t { strings: $a = "x" condition: pe.is_dll() and $a }', 'x');
    assert.equal(u.verdict, 'unknown');                           // unknown and true = unknown
    const b = run('rule t { strings: $b = "x" base64 condition: $b }', 'x');
    assert.equal(b.verdict, 'unknown');
    assert.match(str(b, '$b').unsupported, /base64/);
});
