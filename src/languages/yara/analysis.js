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
 * Checks a hex string body. Returns {errors: [{offset, length, message}], bytes, leadingWildcard}
 * offsets are relative to the raw token (including braces).
 */
export function checkHex(raw) {
    const errors = [];
    const closed = raw.endsWith('}');
    const body = raw.slice(1, closed ? -1 : undefined);
    const base = 1;
    let nibbles = 0;
    let bytes = 0;
    let fixedBytes = 0;
    let items = [];        // 'byte' | 'wild' | 'jump' | 'alt'
    let i = 0;
    let depth = 0;
    while (i < body.length) {
        const c = body[i];
        if (/\s/.test(c)) { i++; continue; }
        if (body.startsWith('//', i)) { while (i < body.length && body[i] !== '\n') i++; continue; }
        if (body.startsWith('/*', i)) { const e = body.indexOf('*/', i + 2); i = e === -1 ? body.length : e + 2; continue; }
        if (/[0-9a-fA-F?~]/.test(c)) {
            if (c === '~') { i++; continue; }      // negation: applies to the next byte
            nibbles++;
            if (nibbles % 2 === 0) {
                const pair = body.slice(i - 1, i + 1);
                bytes++;
                if (!pair.includes('?')) fixedBytes++;
                items.push(pair.includes('?') ? 'wild' : 'byte');
            }
            i++;
            continue;
        }
        if (nibbles % 2 === 1) {
            errors.push({ offset: base + i - 1, length: 1, message: 'Hex byte with a single digit' });
            nibbles++;
        }
        if (c === '[') {
            const e = body.indexOf(']', i);
            if (e === -1) { errors.push({ offset: base + i, length: 1, message: 'Unclosed jump "["' }); break; }
            const range = body.slice(i + 1, e).trim();
            const m = range.match(/^(\d*)\s*(-\s*(\d*))?$/);
            if (!m || (!m[1] && !m[2])) errors.push({ offset: base + i, length: e - i + 1, message: `Invalid jump "[${range}]": use [n], [n-m], [n-] or [-]` });
            else if (m[1] && m[3] && Number(m[1]) > Number(m[3])) errors.push({ offset: base + i, length: e - i + 1, message: `Invalid jump "[${range}]": lower bound above upper bound` });
            if (depth > 0 && m && (!m[3] && m[2])) errors.push({ offset: base + i, length: e - i + 1, message: 'Unbounded jumps are not allowed inside alternatives' });
            items.push('jump');
            i = e + 1;
            continue;
        }
        if (c === '(') { depth++; items.push('alt'); i++; continue; }
        if (c === ')') { depth--; if (depth < 0) errors.push({ offset: base + i, length: 1, message: 'Unbalanced ")"' }); i++; continue; }
        if (c === '|') { if (depth === 0) errors.push({ offset: base + i, length: 1, message: '"|" outside of an alternative ( a | b )' }); i++; continue; }
        let j = i + 1;
        while (j < body.length && !/[\s0-9a-fA-F?~[\]()|]/.test(body[j])) j++;
        errors.push({ offset: base + i, length: j - i, message: `Invalid character${j - i > 1 ? 's' : ''} "${body.slice(i, j)}" in hex string` });
        i = j;
    }
    if (nibbles % 2 === 1) errors.push({ offset: base + body.length - 1, length: 1, message: 'Hex byte with a single digit' });
    if (depth > 0) errors.push({ offset: 0, length: 1, message: 'Unbalanced "(": missing ")"' });
    if (!items.length && !errors.length) errors.push({ offset: 0, length: raw.length, message: 'Empty hex string' });
    if (items[0] === 'jump') errors.push({ offset: 0, length: 1, message: 'A hex string cannot start with a jump' });
    if (items[items.length - 1] === 'jump') errors.push({ offset: raw.length - 1, length: 1, message: 'A hex string cannot end with a jump' });
    return { errors, bytes, fixedBytes, leadingWildcard: items[0] === 'wild' };
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
