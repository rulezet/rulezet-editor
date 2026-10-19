/**
 * Every language pack must pass this suite: it loads, detects its own sample,
 * never throws on garbage, and returns well-formed data.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';

/** Minimal StringStream with the methods packs may use. */
class FakeStream {
    constructor(string) { this.string = string; this.pos = 0; this.start = 0; }
    eol() { return this.pos >= this.string.length; }
    sol() { return this.pos === 0; }
    peek() { return this.string.charAt(this.pos) || undefined; }
    next() { if (this.pos < this.string.length) return this.string.charAt(this.pos++); }
    eat(m) { const c = this.string.charAt(this.pos); const ok = typeof m === 'string' ? c === m : c && (m instanceof RegExp ? m.test(c) : m(c)); if (ok) { this.pos++; return c; } }
    eatWhile(m) { const s = this.pos; while (this.eat(m)); return this.pos > s; }
    eatSpace() { const s = this.pos; while (/[\s ]/.test(this.string.charAt(this.pos))) this.pos++; return this.pos > s; }
    skipToEnd() { this.pos = this.string.length; }
    current() { return this.string.slice(this.start, this.pos); }
    match(pattern, consume = true) {
        if (typeof pattern === 'string') {
            if (this.string.substr(this.pos, pattern.length) === pattern) { if (consume) this.pos += pattern.length; return true; }
            return null;
        }
        const m = this.string.slice(this.pos).match(pattern);
        if (m && m.index > 0) return null;
        if (m && consume) this.pos += m[0].length;
        return m;
    }
}

const dirs = readdirSync(new URL('../src/languages/', import.meta.url), { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name);
const GARBAGE = ['', ' ', '{{{{', '}}}}', '"unterminated', '/* open', 'rule', 'rule {', '$ = = =', '\u0000\u0001', 'x'.repeat(5000), '\u{1F642} \u00fcn\u00efcode', '\n\n\n', 'import', 'rule a : { condition: }'];

for (const dir of dirs) {
    const pack = (await import(`../src/languages/${dir}/index.js`)).default;

    test(`[${dir}] has id and name`, () => {
        assert.ok(pack.id && typeof pack.id === 'string');
        assert.ok(pack.name && typeof pack.name === 'string');
    });

    if (pack.sample && pack.detect) {
        test(`[${dir}] detects its own sample`, () => assert.ok(pack.detect(pack.sample) >= 0.5));
    }

    test(`[${dir}] never throws on garbage`, () => {
        for (const text of GARBAGE.concat(pack.sample ? [pack.sample, pack.sample.slice(0, pack.sample.length / 2)] : [])) {
            const model = pack.parse ? pack.parse(text) : { text };
            for (const d of pack.lint ? pack.lint(model) : []) {
                assert.ok(d.from >= 0 && d.to <= text.length + 1 && d.from <= d.to, `bad range for ${JSON.stringify(text.slice(0, 20))}`);
                assert.ok(['error', 'warning', 'info', 'hint'].includes(d.severity));
                assert.ok(d.message);
            }
            for (let pos = 0; pos <= Math.min(text.length, 60); pos++) {
                if (pack.complete) pack.complete({ text, pos, parsed: model, explicit: true });
                if (pack.hover) pack.hover({ text, pos, parsed: model });
                if (pack.definition) pack.definition({ text, pos, parsed: model });
            }
            if (pack.format) assert.equal(typeof pack.format(model).text, 'string');
            if (pack.splitRules) for (const r of pack.splitRules(model)) assert.ok(r.from <= r.to && r.to <= text.length);
            if (pack.folding) for (const f of pack.folding(model)) assert.ok(f.from <= f.to);
        }
    });

    if (pack.stream) {
        test(`[${dir}] tokenizer always advances`, () => {
            for (const text of GARBAGE.concat(pack.sample ? [pack.sample] : [])) {
                let state = pack.stream.startState();
                for (const line of text.split('\n')) {
                    const s = new FakeStream(line);
                    let guard = 0;
                    while (!s.eol()) {
                        const before = s.pos;
                        s.start = s.pos;
                        pack.stream.token(s, state);
                        assert.ok(s.pos > before, `tokenizer stuck at ${before} in ${JSON.stringify(line.slice(0, 30))}`);
                        assert.ok(guard++ < 10000);
                    }
                }
            }
        });
    }
}

