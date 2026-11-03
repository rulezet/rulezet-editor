/**
 * Hover, definition, references and rename for Sigma: search identifiers (defined under
 * detection:, used in the condition), keys, modifiers, logsource values, tags.
 */
import { TOP_KEYS, STATUS, LEVEL, RELATED_TYPES, LOGSOURCE_KEYS, MODIFIERS, CONDITION_KEYWORDS, TACTICS, TAG_NAMESPACES } from './data.js';
import { ruleAt, matchSearches } from './parser.js';
import { CORRELATION_TYPES } from './lint.js';

function relatedEntries(rule) {
    const e = rule.root.entries.find(x => x.key === 'related');
    if (!e || !e.value || e.value.type !== 'seq') return [];
    const out = [];
    for (const it of e.value.items) {
        if (it.type !== 'map') continue;
        const id = it.entries.find(x => x.key === 'id');
        const type = it.entries.find(x => x.key === 'type');
        if (id && id.value && id.value.type === 'scalar') out.push({ id: String(id.value.value || '').trim(), type: type && type.value ? String(type.value.value || '') : '', from: id.value.from, to: id.value.to });
    }
    return out;
}

const TOP_DOC = Object.fromEntries(TOP_KEYS.map(k => [k.key, k.doc]));
const inside = (pos, r) => r && pos >= r.from && pos <= r.to;

/** What is under pos: { kind, rule, ... } or null. */
function locate(model, pos) {
    const rule = ruleAt(model, pos);
    if (!rule || !rule.root) return null;
    const det = rule.detection;
    if (det) {
        for (const s of det.searches) {
            if (inside(pos, s)) return { kind: 'search', rule, search: s, from: s.from, to: s.to };
            for (const it of s.items) {
                for (const m of it.modifiers) if (inside(pos, m)) return { kind: 'modifier', rule, name: m.name, from: m.from, to: m.to };
                if (it.field && pos >= it.fieldFrom && pos <= it.fieldTo) return { kind: 'field', rule, name: it.field, from: it.fieldFrom, to: it.fieldTo, item: it, search: s };
            }
        }
        for (const c of det.condition) {
            for (const t of c.tokens) {
                if (!inside(pos, t)) continue;
                if (t.type === 'ident' || t.type === 'pattern' || t.type === 'them') return { kind: 'ref', rule, token: t, from: t.from, to: t.to };
                if (CONDITION_KEYWORDS[t.value.toLowerCase()] || t.type === 'quantifier' || t.type === 'number') return { kind: 'keyword', rule, word: t.value.toLowerCase(), from: t.from, to: t.to };
            }
        }
    }
    for (const t of rule.tags) if (inside(pos, t)) return { kind: 'tag', rule, value: t.value, from: t.from, to: t.to };
    if (rule.correlation) {
        for (const r of rule.correlation.rules) {
            if (!inside(pos, r)) continue;
            const target = model.rules.find(x => (x.yamlName && x.yamlName.value.trim() === r.value.trim()) || (x.id && x.id.value.trim() === r.value.trim()));
            return { kind: 'related', rule, id: r.value, type: 'combined', from: r.from, to: r.to, target };
        }
        if (rule.correlation.type && inside(pos, rule.correlation.type)) return { kind: 'corrtype', rule, value: rule.correlation.type.value, from: rule.correlation.type.from, to: rule.correlation.type.to };
    }
    for (const r of relatedEntries(rule)) {
        if (inside(pos, r)) return { kind: 'related', rule, id: r.id, type: r.type, from: r.from, to: r.to, target: model.rules.find(x => x.id && x.id.value.trim() === r.id) || null };
    }
    for (const e of rule.root.entries) {
        if (pos >= e.keyFrom && pos <= e.keyTo) return { kind: 'key', rule, key: e.key, from: e.keyFrom, to: e.keyTo };
    }
    if (rule.logsource && rule.logsource.node && rule.logsource.node.type === 'map') {
        for (const e of rule.logsource.node.entries) {
            if (pos >= e.keyFrom && pos <= e.keyTo) return { kind: 'logsource-key', rule, key: e.key, from: e.keyFrom, to: e.keyTo };
        }
    }
    for (const k of ['status', 'level']) {
        const v = rule[k];
        if (inside(pos, v)) return { kind: k, rule, value: v.value, from: v.from, to: v.to };
    }
    return null;
}

/** One line per item of a search identifier: "Image|endswith: \\evil.exe (+2)". */
function summary(search) {
    return search.items.slice(0, 6).map(it => {
        const vals = it.values.map(v => String(v.value ?? ''));
        const head = it.field !== null ? `${it.field}${it.modifiers.map(m => '|' + m.name).join('')}: ` : '';
        return `\`${head}${vals[0] ?? ''}\`${vals.length > 1 ? ` (+${vals.length - 1})` : ''}`;
    }).join('\n') + (search.items.length > 6 ? `\n… ${search.items.length - 6} more` : '');
}

export function hover(ctx) {
    const at = locate(ctx.parsed, ctx.pos);
    if (!at) return null;
    const range = { from: at.from, to: at.to };
    switch (at.kind) {
        case 'search': {
            const used = at.rule.detection.condition.some(c => c.tokens.some(t => matchSearches(at.rule, t).includes(at.search)));
            return { ...range, title: `search identifier ${at.search.name}`, body: (summary(at.search) || 'empty') + (used ? '' : '\n\nNot used in the condition.') };
        }
        case 'ref': {
            const hits = matchSearches(at.rule, at.token);
            if (!hits.length) return { ...range, title: at.token.value, body: 'No search identifier of this rule matches.' };
            if (at.token.type === 'ident') return { ...range, title: `search identifier ${hits[0].name}`, body: summary(hits[0]) };
            return { ...range, title: at.token.value, body: `Matches ${hits.length} search identifier${hits.length > 1 ? 's' : ''}: ${hits.map(h => '`' + h.name + '`').join(', ')}` };
        }
        case 'modifier': return MODIFIERS[at.name] ? { ...range, title: `|${at.name}`, body: MODIFIERS[at.name] } : { ...range, title: `|${at.name}`, body: 'Unknown modifier.' };
        case 'keyword': return { ...range, title: at.word, body: CONDITION_KEYWORDS[at.word] || CONDITION_KEYWORDS.of };
        case 'key': return TOP_DOC[at.key] ? { ...range, title: at.key, body: TOP_DOC[at.key] } : null;
        case 'logsource-key': return LOGSOURCE_KEYS[at.key] ? { ...range, title: `logsource ${at.key}`, body: LOGSOURCE_KEYS[at.key] } : null;
        case 'status': return STATUS[at.value] ? { ...range, title: `status: ${at.value}`, body: STATUS[at.value] } : null;
        case 'level': return LEVEL[at.value] ? { ...range, title: `level: ${at.value}`, body: LEVEL[at.value] } : null;
        case 'field': {
            const mods = at.item.modifiers.map(m => m.name);
            const how = mods.includes('contains') ? 'contains' : mods.includes('startswith') ? 'starts with' : mods.includes('endswith') ? 'ends with' : mods.includes('re') ? 'matches the regular expression' : 'equals';
            const n = at.item.values.length;
            return { ...range, title: `field ${at.name}`, body: `${at.name} ${how} ${n > 1 ? (mods.includes('all') ? `all of these ${n} values` : `one of these ${n} values`) : 'the value'} (case-insensitive${mods.includes('cased') ? ' — except: |cased' : ''}).` };
        }
        case 'corrtype': return CORRELATION_TYPES[at.value] ? { ...range, title: `correlation: ${at.value}`, body: CORRELATION_TYPES[at.value] } : null;
        case 'related': {
            const what = at.type === 'combined' ? 'combined by this correlation rule' : RELATED_TYPES[at.type] ? `${at.type}: ${RELATED_TYPES[at.type]}` : 'related rule';
            if (at.target) return { ...range, title: `related rule: ${at.target.name}`, body: `${what}\n\nIn this document (F12 to go to it).` };
            return null;                     // not here: the core looks it up on the host (external-rule)
        }
        case 'tag': {
            const [ns, ...rest] = at.value.split('.');
            const name = rest.join('.');
            if (ns === 'attack' && /^t\d{4}/.test(name)) return { ...range, title: `ATT&CK ${name.toUpperCase()}`, body: `MITRE ATT&CK technique ${name.toUpperCase()}: https://attack.mitre.org/techniques/${name.toUpperCase().replace('.', '/')}/`, code: name.toUpperCase() };
            if (ns === 'attack' && TACTICS[name]) return { ...range, title: `ATT&CK tactic ${name}`, body: `${TACTICS[name]}: https://attack.mitre.org/tactics/${TACTICS[name]}/` };
            if (ns === 'cve') return { ...range, title: name.toUpperCase().replace(/^/, 'CVE-'), body: `Vulnerability CVE-${name}.` };
            return TAG_NAMESPACES[ns] ? { ...range, title: at.value, body: TAG_NAMESPACES[ns] } : null;
        }
        default: return null;
    }
}

/** F12 on an identifier of the condition: its definition. */
export function definition(ctx) {
    const at = locate(ctx.parsed, ctx.pos);
    if (at && at.kind === 'related' && at.target) return { from: at.target.id.from, to: at.target.id.to };
    if (!at || at.kind !== 'ref') return null;
    const hit = matchSearches(at.rule, at.token)[0];
    return hit ? { from: hit.from, to: hit.to } : null;
}

/** Every use of a search identifier: its definition first, then the condition tokens. */
export function references(ctx) {
    const at = locate(ctx.parsed, ctx.pos);
    if (!at) return null;
    let search = null;
    if (at.kind === 'search') search = at.search;
    else if (at.kind === 'ref' && at.token.type === 'ident') search = matchSearches(at.rule, at.token)[0] || null;
    if (!search) return null;
    const ranges = [{ from: search.from, to: search.to }];
    for (const c of at.rule.detection.condition) {
        for (const t of c.tokens) if (t.type === 'ident' && t.value === search.name) ranges.push({ from: t.from, to: t.to });
    }
    return { kind: 'search identifier', name: search.name, ranges };
}

/** F2: renames a search identifier (definition + condition). */
export function rename(ctx, newName) {
    const refs = references(ctx);
    if (!refs) return { error: 'Put the cursor on a search identifier (under detection: or in the condition)' };
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(newName)) return { error: 'Use letters, digits and _ (not starting with a digit)' };
    const rule = ruleAt(ctx.parsed, ctx.pos);
    if (newName !== refs.name && rule.detection.searches.some(s => s.name === newName)) return { error: `${newName} already exists in this rule` };
    return { changes: refs.ranges.map(r => ({ from: r.from, to: r.to, insert: newName })) };
}

export { RELATED_TYPES };
