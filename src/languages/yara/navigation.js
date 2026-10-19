/**
 * Hover, go to definition, references and rename for YARA (engine-neutral).
 * Hover result: { from, to, title, body, code? }  (body: plain text, `code` spans allowed)
 */
import { T } from './lexer.js';
import { CONDITION_KEYWORDS, META_KEYS, MODIFIERS, RULE_KEYWORDS, SECTIONS } from './keywords.js';
import { MODULES, resolvePath } from './modules.js';
import { checkHex, refMatches } from './analysis.js';
import { ruleForPos } from './completion.js';
import { unquote } from './parser.js';

function tokenAt(parsed, pos) {
    return parsed.tokens.find(t => pos >= t.from && pos <= t.to && t.to > t.from) || null;
}

/** Dotted path ending at token index k: ["pe","sections","name"] */
function pathAt(parsed, tok) {
    const toks = parsed.tokens;
    let k = toks.indexOf(tok);
    const parts = [tok.value];
    let start = tok.from;
    let j = k - 1;
    while (j >= 1 && toks[j].value === '.') {
        let m = j - 1;
        if (toks[m] && toks[m].value === ']') {           // skip an index
            let depth = 0;
            while (m >= 0) {
                if (toks[m].value === ']') depth++;
                if (toks[m].value === '[') { depth--; if (depth === 0) { m--; break; } }
                m--;
            }
        }
        if (!toks[m] || toks[m].type !== T.IDENT) break;
        parts.unshift(toks[m].value);
        start = toks[m].from;
        j = m - 1;
    }
    return { parts, from: start };
}

export function hover(ctx) {
    const { parsed, pos, text } = ctx;
    const tok = tokenAt(parsed, pos);
    if (!tok) return null;
    const rule = ruleForPos(parsed, pos);

    if (tok.type === T.STRING_ID || tok.type === T.COUNT || tok.type === T.OFFSET || tok.type === T.LENGTH) {
        if (!rule) return null;
        const what = { '$': 'match', '#': 'number of matches', '@': 'offset of a match', '!': 'length of a match' }[tok.value[0]];
        const hits = rule.strings.filter(s => refMatches({ name: tok.name, wildcard: tok.wildcard }, s.name));
        if (!hits.length) return { from: tok.from, to: tok.to, title: tok.value, body: `Not defined in rule ${rule.name}.` };
        const isDef = hits.some(s => s.idFrom === tok.from);
        const uses = countUses(rule, hits[0].name);
        return {
            from: tok.from, to: tok.to,
            title: `${tok.value}  (${what})`,
            code: hits.map(s => text.slice(s.from, s.to)).join('\n'),
            body: hits.length === 1 ? describeString(hits[0]) + (isDef ? `\nUsed ${uses} time${uses === 1 ? '' : 's'} in the condition.` : '')
                : `${hits.length} strings match ${tok.value}.`,
        };
    }

    if (tok.type === T.TEXT) {
        const s = rule && rule.strings.find(x => x.valueFrom === tok.from);
        const bytes = unquote(tok.value);
        if (s || (rule && pos > (rule.sections.strings || { from: Infinity }).from)) {
            return { from: tok.from, to: tok.to, title: 'Text string', body: `${bytes.length} bytes\nHex: ${toHex(bytes)}` };
        }
        return null;
    }
    if (tok.type === T.HEX) {
        const h = checkHex(tok.value);
        return { from: tok.from, to: tok.to, title: 'Hex string', body: `${h.bytes} bytes (${h.fixedBytes} fixed)` + (h.errors.length ? `\n${h.errors.length} problem(s)` : '') + `\nASCII: ${hexToAscii(tok.value)}` };
    }
    if (tok.type === T.REGEX) {
        return { from: tok.from, to: tok.to, title: 'Regular expression', body: 'Flags: i = case-insensitive, s = dot matches newline.' };
    }
    if (tok.type !== T.IDENT) return null;
    const w = tok.value;

    // module path
    const { parts, from } = pathAt(parsed, tok);
    if (MODULES[parts[0]]) {
        const node = resolvePath(parts);
        if (parts.length === 1) return { from: tok.from, to: tok.to, title: `module ${w}`, body: MODULES[w].doc + (parsed.imports.some(i => i.name === w) ? '' : `\nNot imported: add import "${w}".`) };
        if (node) {
            return {
                from, to: tok.to,
                title: node.kind === 'function' ? `${parts.slice(0, -1).join('.')}.${node.sig}` : `${parts.join('.')}: ${node.type || node.kind}`,
                body: node.doc || '',
            };
        }
        return { from, to: tok.to, title: parts.join('.'), body: `Unknown member of module ${parts[0]}.` };
    }

    // rule name (definition or reference)
    const target = parsed.rules.find(r => r.name === w);
    if (target && (!rule || !rule.meta.some(m => m.keyFrom === tok.from))) {
        const desc = target.meta.find(m => m.key === 'description');
        const author = target.meta.find(m => m.key === 'author');
        const head = text.slice(target.from, target.openBrace ?? target.nameTo).trim();
        return {
            from: tok.from, to: tok.to,
            title: head,
            body: [desc && desc.value, author && `Author: ${author.value}`, `${target.strings.length} string(s)`, target.condition ? `Condition: ${target.condition.text.replace(/\s+/g, ' ').slice(0, 160)}` : ''].filter(Boolean).join('\n'),
        };
    }

    if (rule && rule.meta.some(m => m.keyFrom === tok.from)) {
        return META_KEYS[w] ? { from: tok.from, to: tok.to, title: `meta: ${w}`, body: META_KEYS[w] } : null;
    }
    const doc = CONDITION_KEYWORDS[w] || RULE_KEYWORDS[w] || SECTIONS[w] || (MODIFIERS[w] && MODIFIERS[w].doc);
    if (doc) return { from: tok.from, to: tok.to, title: w, body: doc };
    if (ctx.externalRule) return ctx.externalRule(w, tok);
    return null;
}

/** Definition of the symbol at pos: { from, to } or null. */
export function definition(ctx) {
    const { parsed, pos } = ctx;
    const tok = tokenAt(parsed, pos);
    if (!tok) return null;
    const rule = ruleForPos(parsed, pos);
    if ([T.STRING_ID, T.COUNT, T.OFFSET, T.LENGTH].includes(tok.type) && rule) {
        const s = rule.strings.find(x => refMatches({ name: tok.name, wildcard: tok.wildcard }, x.name));
        return s ? { from: s.idFrom, to: s.idTo } : null;
    }
    if (tok.type !== T.IDENT) return null;
    if (MODULES[tok.value]) {
        const imp = parsed.imports.find(i => i.name === tok.value);
        return imp ? { from: imp.from, to: imp.to } : null;
    }
    const r = parsed.rules.find(x => x.name === tok.value);
    return r ? { from: r.nameFrom, to: r.nameTo } : null;
}

/**
 * All occurrences of the symbol at pos, for highlight and rename.
 * Returns { kind: 'string'|'rule', name, ranges: [{from,to}] } (ranges cover the name only, sigil excluded).
 */
export function references(ctx) {
    const { parsed, pos } = ctx;
    const tok = tokenAt(parsed, pos);
    if (!tok) return null;
    if ([T.STRING_ID, T.COUNT, T.OFFSET, T.LENGTH].includes(tok.type)) {
        const rule = ruleForPos(parsed, pos);
        if (!rule || !tok.name || tok.wildcard) return null;
        const ranges = [];
        for (const s of rule.strings) if (s.name === tok.name) ranges.push({ from: s.idFrom + 1, to: s.idTo });
        for (const t of rule.condition ? rule.condition.tokens : []) {
            if ([T.STRING_ID, T.COUNT, T.OFFSET, T.LENGTH].includes(t.type) && t.name === tok.name && !t.wildcard) ranges.push({ from: t.from + 1, to: t.to });
        }
        return { kind: 'string', name: tok.name, ranges };
    }
    if (tok.type === T.IDENT && parsed.rules.some(r => r.name === tok.value)) {
        const ranges = [];
        for (const r of parsed.rules) {
            if (r.name === tok.value) ranges.push({ from: r.nameFrom, to: r.nameTo });
            for (const t of r.condition ? r.condition.tokens : []) {
                const prev = r.condition.tokens[r.condition.tokens.indexOf(t) - 1];
                if (t.type === T.IDENT && t.value === tok.value && !(prev && prev.value === '.')) ranges.push({ from: t.from, to: t.to });
            }
        }
        return { kind: 'rule', name: tok.value, ranges };
    }
    return null;
}

/** Changes to rename the symbol at pos, or {error}. */
export function rename(ctx, newName) {
    const refs = references(ctx);
    if (!refs) return { error: 'Nothing to rename here (place the cursor on a $string or a rule name).' };
    const clean = newName.replace(/^[$#@!]/, '');
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(clean) && !(refs.kind === 'string' && /^[A-Za-z0-9_]+$/.test(clean)))
        return { error: `"${newName}" is not a valid identifier` };
    return { changes: refs.ranges.map(r => ({ from: r.from, to: r.to, insert: clean })) };
}

function countUses(rule, name) {
    let n = 0;
    for (const t of rule.condition ? rule.condition.tokens : []) {
        if ([T.STRING_ID, T.COUNT, T.OFFSET, T.LENGTH].includes(t.type) && refMatches({ name: t.name, wildcard: t.wildcard }, name)) n++;
        if (t.type === T.IDENT && t.value === 'them') n++;
    }
    return n;
}

function describeString(s) {
    const mods = s.modifiers.map(m => m.name).join(' ') || 'no modifier';
    if (s.kind === 'text') return `Text string, ${unquote(s.raw).length} bytes, ${mods}.`;
    if (s.kind === 'hex') { const h = checkHex(s.raw); return `Hex string, ${h.bytes} bytes (${h.fixedBytes} fixed), ${mods}.`; }
    return `Regular expression, ${mods}.`;
}

function toHex(str) {
    return Array.from(str.slice(0, 48), c => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()).join(' ') + (str.length > 48 ? ' ...' : '');
}

function hexToAscii(raw) {
    const pairs = raw.slice(1, -1).replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '').match(/[0-9a-fA-F?]{2}|\[[^\]]*\]/g) || [];
    return pairs.slice(0, 64).map(p => {
        if (p.startsWith('[')) return '…';
        if (p.includes('?')) return '?';
        const c = parseInt(p, 16);
        return c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
    }).join('');
}
