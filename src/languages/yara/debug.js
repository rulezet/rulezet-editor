/**
 * "Try" panel of the YARA pack: run one rule's strings and condition on a small sample typed or
 * pasted in the editor, in the browser, to understand and debug a rule while writing it.
 *
 *   evaluate(model, ruleName, bytes) -> { strings: [...], condition: node, verdict }
 *
 * It follows YARA closely for what a sample can show — text strings (escapes, nocase, ascii, wide,
 * fullword, xor), hex strings (wildcards ?? 4? ?A, ~ negation, jumps [n] [n-m] [n-] [-],
 * alternatives (a|b)), regexes (JavaScript's engine on the bytes, i and s flags), and in the
 * condition: and / or / not, $a, $a at N, $a in (a..b), #a, @a[i], !a[i], N of / any of / all of /
 * none of (them | ($a*, $b)), filesize, int and uint functions, numbers (KB, MB, hex), arithmetic,
 * comparisons. What a sample cannot decide (modules such as pe.*, other rules, for loops,
 * base64 strings, entrypoint…) is "unknown": three-valued logic, so "unknown and false" is false
 * and the panel says why. It is a help to read a rule, not a replacement for libyara (the Test
 * panel runs the real engine).
 */
import { T } from './lexer.js';

const MAX_HITS = 50;
const MAX_DATA = 1024 * 1024;

// ── Sample input ────────────────────────────────────────────────────────────

/** The panel's input as bytes: text (UTF-8; \xNN \n \r \t \\ escapes give raw bytes) or hex ("4D 5A 90"). */
export function inputBytes(value, mode) {
    if (mode === 'hex') {
        const clean = String(value || '').replace(/[^0-9a-fA-F]/g, '');
        if (clean.length % 2) return { error: 'Odd number of hex digits' };
        const out = new Uint8Array(clean.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
        return { bytes: out.slice(0, MAX_DATA) };
    }
    return { bytes: Uint8Array.from(escapedBytes(String(value || ''))).slice(0, MAX_DATA) };
}

/** Text with YARA-like escapes -> bytes: \xNN raw, \n \r \t \" \\, everything else UTF-8. */
function escapedBytes(body) {
    const out = [];
    const enc = new TextEncoder();
    for (let i = 0; i < body.length; i++) {
        const c = body[i];
        if (c === '\\' && i < body.length - 1) {
            const n = body[i + 1];
            if (n === 'x' && /^[0-9a-fA-F]{2}$/.test(body.substr(i + 2, 2))) { out.push(parseInt(body.substr(i + 2, 2), 16)); i += 3; continue; }
            const map = { n: 10, r: 13, t: 9, '"': 34, '\\': 92 };
            if (n in map) { out.push(map[n]); i += 1; continue; }
        }
        const cp = body.codePointAt(i);
        const ch = String.fromCodePoint(cp);
        for (const byte of enc.encode(ch)) out.push(byte);
        if (cp > 0xFFFF) i += 1;
    }
    return out;
}

/** Bytes of a YARA text string ("..." with its escapes). */
function stringBytes(raw) {
    return escapedBytes(raw.slice(1, raw.endsWith('"') && raw.length > 1 ? -1 : undefined));
}

// ── Strings ─────────────────────────────────────────────────────────────────

const isAlnum = (b) => (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122);
const lower = (b) => (b >= 65 && b <= 90 ? b + 32 : b);

function modifierSet(s) {
    const m = {};
    for (const mod of s.modifiers || []) m[mod.name] = mod.args ?? true;
    return m;
}

function xorKeys(arg) {
    if (arg === true || arg == null) return Array.from({ length: 256 }, (_, i) => i);
    const range = String(arg).match(/^\s*(\d+|0x[0-9a-f]+)\s*-\s*(\d+|0x[0-9a-f]+)\s*$/i);
    if (range) {
        const a = Number(range[1]), b = Number(range[2]);
        return Array.from({ length: Math.max(0, b - a + 1) }, (_, i) => a + i);
    }
    return [Number(String(arg).trim())].filter(Number.isFinite);
}

function findBytes(data, pattern, { nocase, fullword }, hits, wide) {
    const n = pattern.length;
    if (!n) return;
    const eq = nocase ? (a, b) => lower(a) === lower(b) : (a, b) => a === b;
    outer: for (let i = 0; i + n <= data.length && hits.length < MAX_HITS; i++) {
        for (let j = 0; j < n; j++) if (!eq(data[i + j], pattern[j])) continue outer;
        if (fullword) {
            const before = i - (wide ? 2 : 1), after = i + n;
            if (before >= 0 && isAlnum(data[before])) continue;
            if (after < data.length && isAlnum(data[after])) continue;
        }
        if (!hits.some(h => h.offset === i)) hits.push({ offset: i, length: n });
    }
}

function textMatcher(s) {
    const m = modifierSet(s);
    if (m.base64 || m.base64wide) return { unsupported: 'base64 strings are not simulated here: the Test panel runs them for real' };
    const plain = stringBytes(s.raw);
    const forms = [];
    if (!m.wide || m.ascii) forms.push({ bytes: plain, wide: false });
    if (m.wide) forms.push({ bytes: plain.flatMap(b => [b, 0]), wide: true });
    const keys = m.xor ? xorKeys(m.xor) : [0];
    return {
        match(data) {
            const hits = [];
            for (const form of forms) {
                for (const k of keys) {
                    findBytes(data, k ? form.bytes.map(b => b ^ k) : form.bytes, { nocase: !!m.nocase, fullword: !!m.fullword }, hits, form.wide);
                    if (hits.length >= MAX_HITS) break;
                }
            }
            return hits.sort((a, b) => a.offset - b.offset);
        },
    };
}

/** Hex string -> a sequence of { byte, mask, not } | { jump: [min, max] } | { alt: [sequences] }. */
export function parseHex(raw) {
    const src = raw.replace(/^\{|\}$/g, '').replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, ' ');
    let i = 0;
    function seq(stopAt) {
        const out = [];
        while (i < src.length) {
            const c = src[i];
            if (/\s/.test(c)) { i++; continue; }
            if (stopAt.includes(c)) break;
            if (c === '(') {
                i++;
                const alts = [seq(['|', ')'])];
                while (src[i] === '|') { i++; alts.push(seq(['|', ')'])); }
                if (src[i] !== ')') throw new Error('Unclosed (');
                i++;
                out.push({ alt: alts });
                continue;
            }
            if (c === '[') {
                const end = src.indexOf(']', i);
                if (end < 0) throw new Error('Unclosed [');
                const body = src.slice(i + 1, end).replace(/\s/g, '');
                i = end + 1;
                let m;
                if ((m = body.match(/^(\d+)$/))) out.push({ jump: [Number(m[1]), Number(m[1])] });
                else if ((m = body.match(/^(\d*)-(\d*)$/))) out.push({ jump: [m[1] ? Number(m[1]) : 0, m[2] ? Number(m[2]) : Infinity] });
                else throw new Error(`Bad jump [${body}]`);
                continue;
            }
            const not = c === '~';
            if (not) i++;
            const pair = src.substr(i, 2);
            if (!/^[0-9a-fA-F?]{2}$/.test(pair)) throw new Error(`Bad byte "${pair}"`);
            i += 2;
            const hi = pair[0] === '?' ? 0 : parseInt(pair[0], 16), lo = pair[1] === '?' ? 0 : parseInt(pair[1], 16);
            out.push({ byte: (hi << 4) | lo, mask: (pair[0] === '?' ? 0 : 0xF0) | (pair[1] === '?' ? 0 : 0x0F), not });
        }
        return out;
    }
    const tree = seq([]);
    if (i < src.length) throw new Error(`Unexpected "${src[i]}"`);
    return tree;
}

function hexMatcher(s) {
    let tree;
    try { tree = parseHex(s.raw); } catch (e) { return { unsupported: `Cannot read this hex string: ${e.message}` }; }
    let budget = 0;
    // every end position the sequence can reach from `pos` (bounded work: jumps can explode)
    function ends(sq, k, pos, data, out) {
        if (budget++ > 200000) return;
        if (k === sq.length) { out.add(pos); return; }
        const el = sq[k];
        if (el.jump) {
            const max = Math.min(el.jump[1], data.length - pos);
            for (let j = el.jump[0]; j <= max; j++) ends(sq, k + 1, pos + j, data, out);
            return;
        }
        if (el.alt) {
            for (const a of el.alt) {
                const mid = new Set();
                ends(a, 0, pos, data, mid);
                for (const p of mid) ends(sq, k + 1, p, data, out);
            }
            return;
        }
        if (pos >= data.length) return;
        const ok = (data[pos] & el.mask) === (el.byte & el.mask);
        if (ok !== el.not) ends(sq, k + 1, pos + 1, data, out);
    }
    return {
        match(data) {
            const hits = [];
            budget = 0;
            for (let i = 0; i < data.length && hits.length < MAX_HITS && budget <= 200000; i++) {
                const out = new Set();
                ends(tree, 0, i, data, out);
                if (out.size) hits.push({ offset: i, length: Math.min(...out) - i || 1 });
            }
            return budget > 200000 ? Object.assign(hits, { truncated: true }) : hits;
        },
    };
}

function regexMatcher(s) {
    const m = s.raw.match(/^\/([\s\S]*)\/([is]*)$/);
    if (!m) return { unsupported: 'Cannot read this regular expression' };
    const mods = modifierSet(s);
    let re;
    try {
        re = new RegExp(m[1], 'g' + (m[2].includes('i') || mods.nocase ? 'i' : '') + (m[2].includes('s') ? 's' : ''));
    } catch (e) {
        return { unsupported: `JavaScript cannot run this regex (${e.message}); the Test panel uses YARA's engine` };
    }
    const latin1 = (data, step, start) => {
        let out = '';
        for (let i = start; i < data.length; i += step) out += String.fromCharCode(data[i]);
        return out;
    };
    return {
        note: 'Regexes run with JavaScript\'s engine here (YARA\'s differs in rare cases)',
        match(data) {
            const hits = [];
            const scan = (text, toOffset, factor) => {
                re.lastIndex = 0;
                let r;
                while ((r = re.exec(text)) && hits.length < MAX_HITS) {
                    if (r[0] === '') { re.lastIndex++; continue; }
                    hits.push({ offset: toOffset(r.index), length: r[0].length * factor });
                }
            };
            if (!mods.wide || mods.ascii) scan(latin1(data, 1, 0), i => i, 1);
            if (mods.wide) {
                // UTF-16LE text: read every other byte where the high byte is 0
                for (const start of [0, 1]) scan(latin1(data, 2, start), i => start + i * 2, 2);
            }
            return hits.sort((a, b) => a.offset - b.offset);
        },
    };
}

export function stringMatcher(s) {
    if (s.kind === 'text') return textMatcher(s);
    if (s.kind === 'hex') return hexMatcher(s);
    if (s.kind === 'regex') return regexMatcher(s);
    return { unsupported: 'Unknown string kind' };
}

// ── Condition ───────────────────────────────────────────────────────────────

const INT_READ = {
    int8: [1, true, false], int16: [2, true, false], int32: [4, true, false],
    uint8: [1, false, false], uint16: [2, false, false], uint32: [4, false, false],
    int8be: [1, true, true], int16be: [2, true, true], int32be: [4, true, true],
    uint8be: [1, false, true], uint16be: [2, false, true], uint32be: [4, false, true],
};

function readInt(data, offset, [size, signed, be]) {
    if (!Number.isInteger(offset) || offset < 0 || offset + size > data.length) return null;
    let v = 0;
    for (let k = 0; k < size; k++) v = v * 256 + data[offset + (be ? k : size - 1 - k)];
    if (signed && v >= 2 ** (size * 8 - 1)) v -= 2 ** (size * 8);
    return v;
}

function and3(values) { return values.includes(false) ? false : values.includes(null) ? null : true; }
function or3(values) { return values.includes(true) ? true : values.includes(null) ? null : false; }

/**
 * Evaluates a condition's tokens. Returns a tree of { text, value, kind, note?, children? } —
 * value true / false / a number / null (unknown here).
 */
export function evaluateCondition(tokens, text, ctx) {
    let i = 0;
    const peek = (k = 0) => tokens[i + k];
    const isW = (t, w) => t && (t.type === T.IDENT || t.type === T.PUNCT) && t.value === w;
    const node = (from, to, value, kind, extra = {}) => ({ text: text.slice(from, to).replace(/\s+/g, ' ').trim(), value, kind, ...extra });
    const startOf = () => (peek() ? peek().from : text.length);
    const endOf = () => (tokens[i - 1] ? tokens[i - 1].to : startOf());

    function parseOr() {
        const from = startOf();
        const parts = [parseAnd()];
        while (isW(peek(), 'or')) { i++; parts.push(parseAnd()); }
        return parts.length === 1 ? parts[0] : node(from, endOf(), or3(parts.map(p => truthy(p.value))), 'or', { children: parts });
    }
    function parseAnd() {
        const from = startOf();
        const parts = [parseNot()];
        while (isW(peek(), 'and')) { i++; parts.push(parseNot()); }
        return parts.length === 1 ? parts[0] : node(from, endOf(), and3(parts.map(p => truthy(p.value))), 'and', { children: parts });
    }
    function parseNot() {
        if (isW(peek(), 'not')) {
            const from = startOf();
            i++;
            const inner = parseNot();
            const v = truthy(inner.value);
            return node(from, endOf(), v === null ? null : !v, 'not', { children: [inner] });
        }
        return parseCompare();
    }
    function parseCompare() {
        const from = startOf();
        const left = parseSum();
        const op = peek();
        if (op && ['==', '!=', '<', '<=', '>', '>='].includes(op.value) && op.type === T.PUNCT) {
            i++;
            const right = parseSum();
            const a = left.value, b = right.value;
            let v = null;
            if (typeof a === 'number' && typeof b === 'number') {
                v = { '==': a === b, '!=': a !== b, '<': a < b, '<=': a <= b, '>': a > b, '>=': a >= b }[op.value];
            }
            return node(from, endOf(), v, 'compare', { children: [left, right] });
        }
        if (op && op.type === T.IDENT && ['contains', 'icontains', 'startswith', 'istartswith', 'endswith', 'iendswith', 'iequals', 'matches'].includes(op.value)) {
            i++;
            parseSum();
            return node(from, endOf(), null, 'unknown', { note: 'Text operators on module values cannot be evaluated on a sample here' });
        }
        return left;
    }
    function parseSum() {
        const from = startOf();
        let left = parsePrimary();
        while (peek() && peek().type === T.PUNCT && ['+', '-', '*', '\\', '%', '&', '|', '^', '<<', '>>'].includes(peek().value)) {
            const op = peek().value;
            i++;
            const right = parsePrimary();
            const a = left.value, b = right.value;
            let v = null;
            if (typeof a === 'number' && typeof b === 'number') {
                v = { '+': a + b, '-': a - b, '*': a * b, '\\': b ? Math.trunc(a / b) : null, '%': b ? a % b : null,
                      '&': a & b, '|': a | b, '^': a ^ b, '<<': a << b, '>>': a >> b }[op];
            }
            left = node(from, endOf(), v, 'arith', { children: [left, right] });
        }
        return left;
    }
    function number(t) {
        const m = t.value.match(/^(0x[0-9a-f]+|0o[0-7]+|\d+)(KB|MB)?$/i);
        if (!m) return Number(t.value);
        const n = Number(m[1].toLowerCase().startsWith('0o') ? parseInt(m[1].slice(2), 8) : m[1]);
        return n * (m[2] ? (m[2].toUpperCase() === 'KB' ? 1024 : 1048576) : 1);
    }
    function stringSet() {
        // them | ($a, $b*, $)
        if (isW(peek(), 'them')) { i++; return ctx.strings.map(s => s.id); }
        if (!isW(peek(), '(')) return null;
        i++;
        const ids = [];
        while (peek() && !isW(peek(), ')')) {
            const t = peek();
            if (t.type === T.STRING_ID) {
                const pat = t.value.endsWith('*') ? t.value.slice(0, -1) : null;
                ctx.strings.forEach(s => { if (pat !== null ? s.id.startsWith(pat) : s.id === t.value) ids.push(s.id); });
            }
            i++;
        }
        if (isW(peek(), ')')) i++;
        return [...new Set(ids)];
    }
    function hitsOf(id) {
        const id2 = id === '$' ? ctx.current : id;
        const s = ctx.results[id2];
        return s ? s : null;
    }
    function rangeArg() {
        // ( a .. b )
        if (!isW(peek(), '(')) return null;
        i++;
        const a = parseSum();
        if (isW(peek(), '..')) i++;
        const b = parseSum();
        if (isW(peek(), ')')) i++;
        return [a.value, b.value];
    }
    function skipChunk(from, reason) {
        // a construct this panel cannot evaluate: consume it whole (balanced), report unknown
        let depth = 0;
        while (peek()) {
            const t = peek();
            if (depth === 0 && (isW(t, 'and') || isW(t, 'or') || isW(t, ')') || (t.type === T.PUNCT && ['==', '!=', '<', '<=', '>', '>='].includes(t.value)))) break;
            if (isW(t, '(')) depth++;
            if (isW(t, ')')) depth--;
            i++;
        }
        return node(from, endOf(), null, 'unknown', { note: reason });
    }
    function parsePrimary() {
        const from = startOf();
        const t = peek();
        if (!t) return node(from, from, null, 'unknown', { note: 'Incomplete condition' });
        if (isW(t, '(')) {
            i++;
            const inner = parseOr();
            if (isW(peek(), ')')) i++;
            return { ...inner, text: text.slice(from, endOf()).replace(/\s+/g, ' ').trim() };
        }
        // quantifiers: any | all | none | N | N% of <set> [in (a..b) | at n]
        const quant = isW(t, 'any') || isW(t, 'all') || isW(t, 'none') || t.type === T.NUMBER;
        if (quant && (isW(peek(1), 'of') || (t.type === T.NUMBER && isW(peek(1), '%') && isW(peek(2), 'of')))) {
            i += isW(peek(1), '%') ? 3 : 2;
            const ids = stringSet();
            if (!ids) return skipChunk(from, 'A rule set (any of (rule1, rule2)) cannot be evaluated here');
            let pick = (r) => r.hits.length > 0;
            if (isW(peek(), 'in')) {
                i++;
                const [a, b] = rangeArg() || [null, null];
                pick = (r) => typeof a === 'number' && typeof b === 'number' ? r.hits.some(h => h.offset >= a && h.offset <= b) : null;
            } else if (isW(peek(), 'at')) {
                i++;
                const at = parseSum();
                pick = (r) => typeof at.value === 'number' ? r.hits.some(h => h.offset === at.value) : null;
            }
            const kids = ids.map(id => {
                const r = hitsOf(id);
                const v = !r || r.unsupported ? null : pick(r);
                return { text: id, value: v, kind: 'string', string: id, note: r && r.unsupported ? r.unsupported : '' };
            });
            const yes = kids.filter(k => k.value === true).length;
            const unknown = kids.filter(k => k.value === null).length;
            const total = kids.length;
            let need;
            if (isW(t, 'any')) need = 1;
            else if (isW(t, 'all')) need = total;
            else if (isW(t, 'none')) need = 0;
            else need = tokens[tokens.indexOf(t) + 1] && tokens[tokens.indexOf(t) + 1].value === '%' ? Math.ceil(number(t) * total / 100) : number(t);
            let v;
            if (isW(t, 'none')) v = yes > 0 ? false : unknown ? null : true;
            else v = yes >= need ? true : yes + unknown >= need ? null : false;
            return node(from, endOf(), v, 'quantifier', { children: kids, note: `${yes} of ${total} found, ${isW(t, 'none') ? 'none' : need} needed` });
        }
        if (isW(t, 'true') || isW(t, 'false')) { i++; return node(from, endOf(), t.value === 'true', 'bool'); }
        if (isW(t, 'filesize')) { i++; return node(from, endOf(), ctx.data.length, 'number', { note: `the sample is ${ctx.data.length} bytes` }); }
        if (t.type === T.NUMBER) { i++; return node(from, endOf(), number(t), 'number'); }
        if (t.type === T.IDENT && INT_READ[t.value] && isW(peek(1), '(')) {
            i += 2;
            const off = parseSum();
            if (isW(peek(), ')')) i++;
            const v = typeof off.value === 'number' ? readInt(ctx.data, off.value, INT_READ[t.value]) : null;
            return node(from, endOf(), v, 'number', { note: v === null ? 'outside the sample' : `0x${(v >>> 0).toString(16).toUpperCase()}` });
        }
        if (t.type === T.STRING_ID) {
            i++;
            const id = t.value;
            const r = hitsOf(id);
            if (!r) return node(from, endOf(), null, 'unknown', { note: `${id} is not a string of this rule` });
            if (r.unsupported) return node(from, endOf(), null, 'unknown', { note: r.unsupported, string: id });
            if (isW(peek(), 'at')) {
                i++;
                const at = parseSum();
                const v = typeof at.value === 'number' ? r.hits.some(h => h.offset === at.value) : null;
                return node(from, endOf(), v, 'string', { string: id });
            }
            if (isW(peek(), 'in')) {
                i++;
                const [a, b] = rangeArg() || [null, null];
                const v = typeof a === 'number' && typeof b === 'number' ? r.hits.some(h => h.offset >= a && h.offset <= b) : null;
                return node(from, endOf(), v, 'string', { string: id });
            }
            return node(from, endOf(), r.hits.length > 0, 'string', { string: id, note: r.hits.length ? `${r.hits.length} match${r.hits.length === 1 ? '' : 'es'}` : 'no match' });
        }
        if (t.type === T.COUNT || t.type === T.OFFSET || t.type === T.LENGTH) {
            i++;
            const id = '$' + t.value.slice(1);
            const r = hitsOf(id);
            let index = 1;
            if (isW(peek(), '[')) { i++; const ix = parseSum(); index = ix.value; if (isW(peek(), ']')) i++; }
            if (t.type === T.COUNT && isW(peek(), 'in')) {
                i++;
                const [a, b] = rangeArg() || [null, null];
                const v = r && !r.unsupported && typeof a === 'number' && typeof b === 'number' ? r.hits.filter(h => h.offset >= a && h.offset <= b).length : null;
                return node(from, endOf(), v, 'number');
            }
            if (!r || r.unsupported) return node(from, endOf(), null, 'unknown', { note: r ? r.unsupported : `${id} is not a string of this rule` });
            if (t.type === T.COUNT) return node(from, endOf(), r.hits.length, 'number', { string: id });
            const h = typeof index === 'number' ? r.hits[index - 1] : null;
            return node(from, endOf(), h ? (t.type === T.OFFSET ? h.offset : h.length) : null, 'number',
                { string: id, note: h ? '' : `no match number ${index}` });
        }
        if (isW(t, 'for')) return skipChunk(from, 'for loops are not evaluated here: the Test panel runs them');
        if (isW(t, 'entrypoint')) return skipChunk(from, 'entrypoint needs a parsed executable: not available here');
        if (t.type === T.IDENT && isW(peek(1), '.')) return skipChunk(from, `Module values (${t.value}.…) need the real engine: the Test panel runs them`);
        if (t.type === T.IDENT) { i++; return node(from, endOf(), null, 'unknown', { note: `"${t.value}": another rule or a module function, not evaluated here` }); }
        if (t.type === T.TEXT) { i++; return node(from, endOf(), t.value, 'text'); }
        i++;
        return node(from, endOf(), null, 'unknown', { note: `"${t.value}" is not understood here` });
    }
    function truthy(v) { return v === null ? null : typeof v === 'number' ? v !== 0 : !!v; }

    const root = tokens.length ? parseOr() : node(0, 0, null, 'unknown', { note: 'Empty condition' });
    if (i < tokens.length) root.note = (root.note ? root.note + ' · ' : '') + 'part of the condition was not understood';
    return root;
}

// ── One rule on one sample ──────────────────────────────────────────────────

export function evaluate(model, ruleName, data) {
    const rule = (model.rules || []).find(r => r.name === ruleName);
    if (!rule) return null;
    const results = {};
    const strings = rule.strings.map(s => {
        const matcher = stringMatcher(s);
        const r = matcher.unsupported ? { unsupported: matcher.unsupported, hits: [] } : { hits: matcher.match(data), note: matcher.note };
        results[s.id] = r;
        return { id: s.id, kind: s.kind, raw: s.raw, modifiers: (s.modifiers || []).map(m => m.name + (m.args ? `(${m.args})` : '')),
                 from: s.idFrom, ...r };
    });
    const tokens = rule.condition ? rule.condition.tokens : [];
    const condition = evaluateCondition(tokens, model.text, { data, strings: rule.strings, results, current: null });
    const v = condition.value;
    const verdict = v === null ? 'unknown' : (typeof v === 'number' ? v !== 0 : !!v) ? 'match' : 'no_match';
    return { rule: ruleName, strings, condition, verdict, size: data.length };
}
