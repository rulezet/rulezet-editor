/**
 * Semantic helpers on top of the parser: what a condition refers to,
 * where every identifier is defined, hex string checks.
 */
import { T } from './lexer.js';
import { CONDITION_KEYWORDS } from './keywords.js';
import { MODULES } from './modules.js';

const LOOP_QUANTIFIERS = new Set(['any', 'all', 'none']);

/**
 * Everything a rule's condition refers to.
 * @returns {{
 *   strings: Array<{tok, name, wildcard, prefix}>,   // $a #a @a !a  ($ alone has name '')
 *   them: Array<tok>,
 *   paths: Array<{tok, parts: string[], from, to, call: boolean}>,  // pe.sections[0].name
 *   idents: Array<tok>,                               // plain identifiers: rule names
 *   loopVars: Set<string>,
 *   deprecated: Array<tok>,
 * }}
 */
export function conditionRefs(rule) {
    const out = { strings: [], them: [], paths: [], idents: [], loopVars: new Set(), deprecated: [] };
    const toks = rule.condition ? rule.condition.tokens : [];
    // loop / with variables: "for any i, j in", "with a = ..."
    for (let k = 0; k < toks.length; k++) {
        const t = toks[k];
        if (t.type === T.IDENT && t.value === 'for') {
            let j = k + 1;
            if (toks[j] && (toks[j].type === T.NUMBER || LOOP_QUANTIFIERS.has(toks[j].value))) j++;
            while (toks[j] && toks[j].type === T.IDENT && toks[j].value !== 'in' && toks[j].value !== 'of') {
                out.loopVars.add(toks[j].value);
                j++;
                if (toks[j] && toks[j].value === ',') j++;
            }
        }
        if (t.type === T.IDENT && t.value === 'with') {
            let j = k + 1;
            while (toks[j] && toks[j].type === T.IDENT && toks[j + 1] && toks[j + 1].value === '=') {
                out.loopVars.add(toks[j].value);
                // skip the expression up to the next "," at depth 0 or ":"
                let depth = 0;
                j += 2;
                while (toks[j] && !(depth === 0 && (toks[j].value === ',' || toks[j].value === ':'))) {
                    if (toks[j].value === '(') depth++;
                    if (toks[j].value === ')') depth--;
                    j++;
                }
                if (toks[j] && toks[j].value === ',') j++;
            }
        }
    }

    for (let k = 0; k < toks.length; k++) {
        const t = toks[k];
        if (t.type === T.STRING_ID || t.type === T.COUNT || t.type === T.OFFSET || t.type === T.LENGTH) {
            out.strings.push({ tok: t, name: t.name, wildcard: !!t.wildcard, sigil: t.value[0] });
            continue;
        }
        if (t.type !== T.IDENT) continue;
        const prev = toks[k - 1];
        if (prev && prev.type === T.PUNCT && prev.value === '.') continue;   // member, part of a path
        if (t.value === 'them') { out.them.push(t); continue; }
        if (t.value === 'entrypoint') { out.deprecated.push(t); continue; }
        if (CONDITION_KEYWORDS[t.value] || t.value === 'with') continue;
        if (out.loopVars.has(t.value)) continue;
        // a dotted path: ident ( [ ... ] )? ( . ident ( [ ... ] )? )*
        const next = toks[k + 1];
        const isPath = MODULES[t.value] || (next && next.type === T.PUNCT && (next.value === '.' || next.value === '['));
        if (isPath) {
            const parts = [t.value];
            let j = k + 1;
            let end = t.to;
            for (;;) {
                if (toks[j] && toks[j].value === '[') {
                    let depth = 0;
                    while (toks[j]) {
                        if (toks[j].value === '[') depth++;
                        if (toks[j].value === ']') { depth--; if (depth === 0) { end = toks[j].to; j++; break; } }
                        j++;
                    }
                    continue;
                }
                if (toks[j] && toks[j].value === '.' && toks[j + 1] && toks[j + 1].type === T.IDENT) {
                    parts.push(toks[j + 1].value);
                    end = toks[j + 1].to;
                    j += 2;
                    continue;
                }
                break;
            }
            const call = !!(toks[j] && toks[j].value === '(');
            out.paths.push({ tok: t, parts, from: t.from, to: end, call });
            continue;
        }
        out.idents.push(t);
    }
    return out;
}

/** Does a condition string reference ($a, $a*, $) point at this string id? */
export function refMatches(ref, stringName) {
    if (ref.wildcard) return stringName.startsWith(ref.name);
    return ref.name === stringName;
}

/**
 * Checks a hex string, with libyara's rules: bytes are two adjacent digits or "?", "~" sticks to
 * a byte that is not "??", groups and alternatives are never empty and never start or end with a
 * jump, unbounded jumps stay out of groups, [0] is refused.
 * Returns {errors: [{offset, length, message}], bytes, fixedBytes, leadingWildcard};
 * offsets are relative to the raw token (including braces).
 */
export function checkHex(raw) {
    const errors = [];
    const err = (offset, length, message) => { if (!errors.length) errors.push({ offset, length, message }); };
    const closed = raw.endsWith('}');
    const body = raw.slice(1, closed ? -1 : undefined);
    const base = 1;
    const isNibble = (c) => /[0-9a-fA-F?]/.test(c || '');

    // tokens: byte | jump | ( | ) | "|"
    const toks = [];
    let i = 0;
    while (i < body.length) {
        const c = body[i];
        if (/\s/.test(c)) { i++; continue; }
        if (body.startsWith('//', i)) { while (i < body.length && body[i] !== '\n') i++; continue; }
        if (body.startsWith('/*', i)) { const e = body.indexOf('*/', i + 2); i = e === -1 ? body.length : e + 2; continue; }
        if (c === '~') {
            if (!isNibble(body[i + 1]) || !isNibble(body[i + 2]) || body.slice(i + 1, i + 3) === '??') {
                err(base + i, 1, '"~" must be followed by a byte, like ~41 or ~4?, and not by ??');
                i++;
                continue;
            }
            toks.push({ t: 'byte', at: i, wild: body.slice(i + 1, i + 3).includes('?'), not: true });
            i += 3;
            continue;
        }
        if (isNibble(c)) {
            if (!isNibble(body[i + 1])) { err(base + i, 1, 'Hex byte with a single digit: bytes are two digits, like 0F'); i++; continue; }
            toks.push({ t: 'byte', at: i, wild: body.slice(i, i + 2).includes('?') });
            i += 2;
            continue;
        }
        if (c === '[') {
            const e = body.indexOf(']', i);
            if (e === -1) { err(base + i, 1, 'Unclosed jump "["'); break; }
            const range = body.slice(i + 1, e).trim();
            const m = range.match(/^(\d*)\s*(-\s*(\d*))?$/);
            const len = e - i + 1;
            if (!m || (!m[1] && !m[2])) err(base + i, len, `Invalid jump "[${range}]": use [n], [n-m], [n-] or [-]`);
            else if (m[1] && m[3] && Number(m[1]) > Number(m[3])) err(base + i, len, `Invalid jump "[${range}]": lower bound above upper bound`);
            else if (!m[2] && Number(m[1]) === 0) err(base + i, len, 'Invalid jump "[0]": a jump of zero bytes');
            toks.push({ t: 'jump', at: i, len, unbounded: !!(m && m[2] && !m[3]) });
            i = e + 1;
            continue;
        }
        if (c === '(' || c === ')' || c === '|') { toks.push({ t: c, at: i }); i++; continue; }
        let j = i + 1;
        while (j < body.length && !/[\s0-9a-fA-F?~[\]()|]/.test(body[j])) j++;
        err(base + i, j - i, `Invalid character${j - i > 1 ? 's' : ''} "${body.slice(i, j)}" in hex string`);
        i = j;
    }

    // structure: seq := (byte | jump | "(" seq ("|" seq)* ")")+
    let k = 0;
    let groupDepth = 0;
    const where = (tk) => (tk ? base + tk.at : raw.length - 1);
    function seq(endAt) {
        const items = [];
        while (k < toks.length && !endAt.includes(toks[k].t)) {
            const tk = toks[k];
            if (tk.t === ')') { err(where(tk), 1, 'Unbalanced ")"'); k++; continue; }
            if (tk.t === '|') { err(where(tk), 1, '"|" outside of an alternative ( a | b )'); k++; continue; }
            if (tk.t === '(') {
                k++;
                groupDepth++;
                for (;;) {
                    const inner = seq(['|', ')']);
                    if (!inner.length) err(where(toks[k] || tk), 1, 'Empty alternative in ( ... | ... )');
                    if (k >= toks.length) { err(where(tk), 1, 'Unbalanced "(": missing ")"'); break; }
                    const sep = toks[k++];
                    if (sep.t === ')') break;
                }
                groupDepth--;
                items.push({ t: 'group', at: tk.at });
                continue;
            }
            if (tk.t === 'jump' && groupDepth > 0 && tk.unbounded) err(base + tk.at, tk.len, 'Unbounded jumps are not allowed inside ( ... )');
            items.push(tk);
            k++;
        }
        if (items.length && items[0].t === 'jump') err(base + items[0].at, items[0].len, groupDepth ? 'An alternative cannot start with a jump' : 'A hex string cannot start with a jump');
        const last = items[items.length - 1];
        if (items.length && last.t === 'jump') err(base + last.at, last.len, groupDepth ? 'An alternative cannot end with a jump' : 'A hex string cannot end with a jump');
        return items;
    }
    const top = seq([]);
    if (!toks.length && !errors.length) err(0, raw.length, 'Empty hex string');
    void top;

    const bytes = toks.filter(t => t.t === 'byte');
    return {
        errors,
        bytes: bytes.length,
        fixedBytes: bytes.filter(b => !b.wild).length,
        leadingWildcard: !!(toks[0] && toks[0].t === 'byte' && toks[0].wild),
    };
}

/** Text string escapes: returns [{offset, length, message}] relative to raw. */
export function checkTextEscapes(raw) {
    const errors = [];
    for (let i = 1; i < raw.length - 1; i++) {
        if (raw[i] !== '\\') continue;
        const e = raw[i + 1];
        if (e === 'x') {
            if (!/^[0-9a-fA-F]{2}$/.test(raw.slice(i + 2, i + 4))) errors.push({ offset: i, length: 2, message: 'Invalid escape: \\x needs two hex digits' });
            i += 3;
        } else if ('ntr\\"'.includes(e)) {
            i++;
        } else {
            errors.push({ offset: i, length: 2, message: `Invalid escape "\\${e}" (allowed: \\n \\t \\r \\\\ \\" \\xNN)` });
            i++;
        }
    }
    return errors;
}

/** Map of rule name -> rule, first definition wins. */
export function ruleIndex(parsed) {
    const map = new Map();
    for (const r of parsed.rules) if (r.name && !map.has(r.name)) map.set(r.name, r);
    return map;
}

/** The rule containing an offset (body or header), or null. */
export function ruleAt(parsed, pos) {
    return parsed.rules.find(r => pos >= r.from && pos <= r.to) || null;
}

/** Which section of a rule an offset is in: 'header' | 'meta' | 'strings' | 'condition' | 'body' */
export function sectionAt(rule, pos) {
    if (rule.openBrace == null || pos <= rule.openBrace) return 'header';
    let best = 'body';
    let bestFrom = -1;
    for (const [name, sec] of Object.entries(rule.sections)) {
        if (pos >= sec.bodyFrom && sec.from > bestFrom) { best = name; bestFrom = sec.from; }
    }
    return best;
}

/**
 * Regular expression body (between the slashes), with libyara's rules: no (?...) groups, no
 * backreferences, no empty group or leading "|", one quantifier per atom (a lazy "?" aside),
 * {n,m} with n <= m, ordered class ranges, \x with two hex digits.
 * Returns [{offset, length, message}] relative to the body.
 */
export function checkRegex(body) {
    const errors = [];
    const err = (offset, length, message) => { if (!errors.length) errors.push({ offset, length, message }); };
    const stack = [];            // open groups: { at, empty }
    let atom = false;            // something a quantifier can apply to
    let quantified = false;      // last item already has a quantifier
    let altEmpty = true;         // current alternative has nothing yet
    const greedy = [null, null]; // first greedy / lazy quantifier seen
    let justOpened = false;      // right after "("
    let i = 0;
    const n = body.length;
    while (i < n && !errors.length) {
        const c = body[i];
        const afterOpen = justOpened;
        justOpened = false;
        if (c === '\\') {
            const e = body[i + 1];
            if (e === undefined) { err(i, 1, 'Regular expression ends with "\\"'); break; }
            if (/[0-9]/.test(e)) err(i, 2, 'Backreferences are not allowed in YARA regular expressions');
            if (e === 'x' && !/^[0-9a-fA-F]{2}$/.test(body.slice(i + 2, i + 4))) err(i, 2, 'Invalid escape: \\x needs two hex digits');
            i += e === 'x' ? 4 : 2;
            atom = e !== 'b' && e !== 'B';      // word boundaries cannot be repeated
            quantified = false; altEmpty = false;
            continue;
        }
        if (c === '[') {
            const start = i;
            i++;
            if (body[i] === '^') i++;
            if (body[i] === ']') i++;                 // "]" first is a literal
            let prev = null;                          // last single char, for ranges
            let closed = false;
            while (i < n) {
                const d = body[i];
                if (d === ']') { closed = true; i++; break; }
                let ch = d;
                let len = 1;
                if (d === '\\') {
                    const e = body[i + 1];
                    if (e === 'x') {
                        if (!/^[0-9a-fA-F]{2}$/.test(body.slice(i + 2, i + 4))) { err(i, 2, 'Invalid escape: \\x needs two hex digits'); break; }
                        ch = String.fromCharCode(parseInt(body.slice(i + 2, i + 4), 16)); len = 4;
                    } else if (/[wWsSdD]/.test(e || '')) { ch = null; len = 2; }
                    else { ch = { n: '\n', t: '\t', r: '\r', f: '\f', a: '\x07' }[e] ?? e; len = 2; }
                }
                if (prev !== null && body[i] === '-' && body[i + 1] !== ']' && i + 1 < n) {
                    // range prev-next
                    let j = i + 1;
                    let hi = body[j];
                    let hlen = 1;
                    if (hi === '\\') {
                        const e = body[j + 1];
                        if (e === 'x') { hi = String.fromCharCode(parseInt(body.slice(j + 2, j + 4), 16)); hlen = 4; }
                        else if (/[wWsSdD]/.test(e || '')) { hi = null; hlen = 2; }
                        else { hi = { n: '\n', t: '\t', r: '\r', f: '\f', a: '\x07' }[e] ?? e; hlen = 2; }
                    }
                    if (hi !== null && hi !== undefined && hi < prev) err(start, j + hlen - start, 'Bad character range: the first character comes after the second');
                    i = j + hlen;
                    prev = null;
                    continue;
                }
                prev = ch;
                i += len;
            }
            if (errors.length) break;
            if (!closed) { err(start, 1, 'Missing "]" to close the character class'); break; }
            atom = true; quantified = false; altEmpty = false;
            continue;
        }
        if (c === '(') {
            if (body[i + 1] === '?') { err(i, 2, '"(?" groups (non-capturing, flags, lookaround) are not supported by YARA'); break; }
            stack.push({ at: i, altEmpty });
            altEmpty = true; atom = false; quantified = false; justOpened = true;
            i++;
            continue;
        }
        if (c === ')') {
            const open = stack.pop();
            if (!open) { err(i, 1, 'Unbalanced ")"'); break; }
            if (altEmpty && body[i - 1] === '(') { err(open.at, i - open.at + 1, 'Empty group "()"'); break; }
            altEmpty = false; atom = true; quantified = false;
            i++;
            continue;
        }
        if (c === '|') {
            if (i === 0 || afterOpen) { err(i, 1, '"|" needs an expression on its left'); break; }
            altEmpty = true; atom = false; quantified = false;
            i++;
            continue;
        }
        if (c === '*' || c === '+' || c === '?' || (c === '{' && /^\{(\d+|\d*,\d+|\d+,)\}/.test(body.slice(i)))) {
            const m = c === '{' ? body.slice(i).match(/^\{(\d*)(,?)(\d*)\}/) : null;
            const len = m ? m[0].length : 1;
            if (c === '?' && quantified === true) {
                // lazy marker after a quantifier
                quantified = 'lazy';
                i++;
                continue;
            }
            if (!atom || quantified) { err(i, len, `Nothing to repeat before "${body.slice(i, i + len)}"`); break; }
            if (m && m[1] && m[3] && Number(m[1]) > Number(m[3])) { err(i, len, `Bad repeat interval ${m[0]}: the minimum is above the maximum`); break; }
            if (m && (Number(m[1] || 0) > 32767 || Number(m[3] || 0) > 32767)) { err(i, len, `Repeat interval ${m[0]} too large (max 32767)`); break; }
            const lazy = body[i + len] === '?';
            if (greedy[lazy ? 1 : 0] === null) greedy[lazy ? 1 : 0] = i;
            if (greedy[0] !== null && greedy[1] !== null) { err(i, len + (lazy ? 1 : 0), 'Greedy and lazy (?) quantifiers cannot be mixed in one regular expression'); break; }
            quantified = true;
            i += len;
            continue;
        }
        atom = c !== '^' && c !== '$';      // anchors cannot be repeated
        quantified = false; altEmpty = false;
        i++;
    }
    if (!errors.length && stack.length) err(stack[stack.length - 1].at, 1, 'Missing ")"');
    return errors;
}
