/**
 * The Sigma rule as a form (Fields panel, "Log source & detection"): the log source, each search
 * identifier as field / modifiers / values rows, and the condition as clauses. Every change is
 * written back into the YAML with the rule's own indentation. Pure functions: the core's
 * selections UI (src/ui/selections.js) calls them through pack.selections.
 *
 *   read(model, rule) -> { logsource: { category, product, service }, searches: [search], condition }
 *   search: { index, name, kind: 'fields' | 'keywords' | 'complex', items: [{ field, modifiers: [names], values: [strings] }],
 *             keywords: [strings], text }       complex = a list of mappings (edited in the editor)
 */
import { CATEGORIES, PRODUCTS, SERVICES, FIELDS, SERVICE_FIELDS, MODIFIERS, LOGSOURCE_KEYS } from './data.js';
import { entry, yamlValue } from './yaml.js';
import { indentUnit, setTop } from './actions.js';
import { rename } from './navigation.js';

const findRule = (model, name) => model.rules.find(r => r.name === name && r.root) || null;
const lineStart = (text, pos) => text.lastIndexOf('\n', pos - 1) + 1;
function lineEnd(text, pos) { const i = text.indexOf('\n', pos); return i === -1 ? text.length : i; }

/** The block of an entry: from its line start to the end of its value's last line (newline included). */
function blockRange(text, e) {
    const from = lineStart(text, e.keyFrom);
    let to = lineEnd(text, e.value ? e.value.to : e.to);
    if (to < text.length) to += 1;
    return { from, to };
}

function readSearch(s, index, text) {
    const node = s.node;
    const out = { index, name: s.name, kind: 'fields', items: [], keywords: [], text: text.slice(s.entry.keyFrom, s.entry.value ? s.entry.value.to : s.entry.to) };
    if (!node || node.type === 'scalar') { out.kind = node && node.value ? 'complex' : 'fields'; return out; }
    if (node.type === 'seq') {
        if (node.items.every(i => i.type === 'scalar')) {
            out.kind = 'keywords';
            out.keywords = node.items.map(i => String(i.value ?? ''));
        } else out.kind = 'complex';
        return out;
    }
    for (const it of s.items) {
        if (it.node && it.node.type === 'map') { out.kind = 'complex'; return out; }
        out.items.push({ field: it.field || '', modifiers: it.modifiers.map(m => m.name), values: it.values.map(v => String(v.value ?? '')) });
    }
    return out;
}

/** "Image|endswith: '\\x.exe'" or a list, as YAML lines under `ind`. */
function itemLines(item, ind, unit) {
    const key = `${item.field || ''}${(item.modifiers || []).map(m => '|' + m).join('')}`;
    const k = /^[A-Za-z0-9_.\-]+(\|[A-Za-z0-9_]+)*$/.test(key) ? key : `'${key.replace(/'/g, "''")}'`;
    const values = (item.values || []).map(v => String(v)).filter(v => v !== '');
    const quote = (v) => (/^-?\d+$/.test(v) && /^(EventID|.*Port|.*Id)$/.test(item.field) ? v : /^(true|false)$/.test(v) && (item.modifiers || []).includes('exists') ? v : `'${v.replace(/'/g, "''")}'`);
    if (values.length === 1) return `${ind}${k}: ${quote(values[0])}`;
    if (!values.length) return `${ind}${k}: ''`;
    return `${ind}${k}:\n${values.map(v => `${ind}${unit}- ${quote(v)}`).join('\n')}`;
}

function searchBlock(search, ind, unit) {
    const head = `${ind}${search.name}:`;
    if (search.kind === 'keywords') {
        const kws = (search.keywords || []).filter(Boolean);
        return `${head}\n${(kws.length ? kws : ['change me']).map(v => `${ind}${unit}- '${String(v).replace(/'/g, "''")}'`).join('\n')}\n`;
    }
    const items = (search.items || []).filter(i => i.field || (i.values || []).length);
    const body = (items.length ? items : [{ field: 'Image', modifiers: ['endswith'], values: ['\\change_me.exe'] }]).map(i => itemLines(i, ind + unit, unit)).join('\n');
    return `${head}\n${body}\n`;
}

/** Top-level and / or of a condition (parentheses kept whole). */
export function splitCondition(text) {
    const parts = [];
    let depth = 0, start = 0, op = null, i = 0;
    const s = String(text || '');
    const push = (end, next) => { const piece = s.slice(start, end).trim(); if (piece) parts.push({ op, text: piece }); op = next; };
    while (i < s.length) {
        const c = s[i];
        if (c === '(') depth++;
        else if (c === ')') depth = Math.max(0, depth - 1);
        else if (depth === 0) {
            const m = /^(and|or)\b/i.exec(s.slice(i));
            if (m && (i === 0 || /[\s)]/.test(s[i - 1]))) { push(i, m[1].toLowerCase()); i += m[1].length; start = i; continue; }
        }
        i++;
    }
    push(s.length, null);
    return parts;
}

export function joinCondition(parts) {
    return parts.filter(p => String(p.text || '').trim())
        .map((p, i) => (i === 0 ? '' : ` ${p.op === 'or' ? 'or' : 'and'} `) + p.text.trim()).join('');
}

export const selections = {
    labels: { logsource: 'Log source', searches: 'Detection', condition: 'Condition', hint: 'written into the rule as you edit' },
    logsourceKeys: Object.entries(LOGSOURCE_KEYS).filter(([k]) => k !== 'definition').map(([key, help]) => ({ key, help })),
    logsourceValues: { category: CATEGORIES, product: PRODUCTS, service: SERVICES },
    modifiers: ['contains', 'startswith', 'endswith', 'all', 're', 'cased', 'windash', 'base64offset', 'cidr', 'exists', 'gt', 'lt'],
    allModifiers: Object.keys(MODIFIERS),
    modifierHelp: MODIFIERS,

    read(model, ruleName) {
        const rule = findRule(model, ruleName);
        if (!rule) return null;
        const ls = rule.logsource;
        const det = rule.detection;
        return {
            logsource: { category: ls && ls.category ? ls.category.value : '', product: ls && ls.product ? ls.product.value : '', service: ls && ls.service ? ls.service.value : '' },
            searches: det ? det.searches.map((s, i) => readSearch(s, i, model.text)) : [],
            condition: det && det.condition.length === 1 ? det.condition[0].text : (det ? det.condition.map(c => c.text).join(' or ') : ''),
        };
    },

    /** Field names to offer for the rule's log source. */
    fields(logsource) {
        const out = [...(FIELDS[logsource.category] || []), ...(SERVICE_FIELDS[logsource.service] || [])];
        return [...new Set(out.length ? out : [...FIELDS.process_creation, 'EventID'])];
    },

    setLogsource(model, ruleName, key, value) {
        const rule = findRule(model, ruleName);
        if (!rule || !['category', 'product', 'service'].includes(key)) return null;
        const text = model.text;
        const unit = indentUnit(text, rule);
        const v = String(value || '').trim();
        const ls = rule.logsource;
        if (!ls || !ls.node || ls.node.type !== 'map') {
            if (!v) return [];
            const block = `logsource:\n${unit}${key}: ${yamlValue(v)}`;
            if (ls) return [{ from: ls.entry.keyFrom, to: ls.entry.value ? ls.entry.value.to : ls.entry.to, insert: block }];
            return setTop(text, rule, 'logsource', '').map(c => ({ ...c, insert: c.insert.replace(/logsource: $/m, block) }));
        }
        const e = entry(ls.node, key);
        if (e && !v) return [{ ...blockRange(text, e), insert: '' }];
        if (e) return [{ from: e.value ? e.value.from : e.to, to: e.value ? e.value.to : e.to, insert: e.value ? yamlValue(v) : ` ${yamlValue(v)}` }];
        if (!v) return [];
        const first = ls.node.entries[0];
        const ind = first ? text.slice(lineStart(text, first.keyFrom), first.keyFrom) : unit;
        const at = lineEnd(text, ls.node.to);
        return [{ from: at, to: at, insert: `\n${ind}${key}: ${yamlValue(v)}` }];
    },

    /** Replaces search `index` (or adds one when index is null, before the condition). */
    setSearch(model, ruleName, index, search) {
        const rule = findRule(model, ruleName);
        if (!rule || !/^[A-Za-z_][\w.\-]*$/.test(search.name || '')) return null;
        const text = model.text;
        const unit = indentUnit(text, rule);
        const det = rule.detection;
        if (!det || !det.node || det.node.type !== 'map') {
            const block = `detection:\n${searchBlock(search, unit, unit)}${unit}condition: ${search.name}`;
            if (det) return [{ from: det.entry.keyFrom, to: det.entry.value ? det.entry.value.to : det.entry.to, insert: block }];
            return setTop(text, rule, 'detection', '').map(c => ({ ...c, insert: c.insert.replace(/detection: $/m, block) }));
        }
        const first = det.node.entries[0];
        const ind = first ? text.slice(lineStart(text, first.keyFrom), first.keyFrom) : unit;
        const old = index !== null ? det.searches[index] : null;
        if (old) {
            if (search.name !== old.name && det.searches.some((s, i) => i !== index && s.name === search.name)) return null;
            const changes = [{ ...blockRange(text, old.entry), insert: searchBlock(search, ind, unit) }];
            // a renamed search identifier is renamed in the condition too
            if (search.name !== old.name) {
                for (const c of det.condition) for (const t of c.tokens) if (t.type === 'ident' && t.value === old.name) changes.push({ from: t.from, to: t.to, insert: search.name });
            }
            return changes;
        }
        if (det.searches.some(s => s.name === search.name)) return null;
        const before = det.conditionEntry || null;
        const at = before ? lineStart(text, before.keyFrom) : lineEnd(text, det.node.to) + 1;
        const block = searchBlock(search, ind, unit);
        const changes = [{ from: Math.min(at, text.length), to: Math.min(at, text.length), insert: at > text.length ? `\n${block}` : block }];
        // a new search identifier joins the condition (a filter as "and not"), so the rule stays valid
        const c = det.condition.length === 1 ? det.condition[0] : null;
        if (c) {
            const quoted = c.node.quoted === '"' || c.node.quoted === "'";
            const end = quoted ? c.to - 1 : c.to;
            const isFilter = /^filter/i.test(search.name);
            const hasOr = c.tokens.some(t => t.type === 'or');
            const covered = c.tokens.some(t => (t.type === 'pattern' && new RegExp('^' + t.value.replace(/[.+?^${}()|[\]\\-]/g, '\\$&').replace(/\*/g, '.*') + '$').test(search.name)) || t.type === 'them');
            if (!covered) {
                if (isFilter && hasOr) changes.push({ from: quoted ? c.from + 1 : c.from, to: quoted ? c.from + 1 : c.from, insert: '(' }, { from: end, to: end, insert: `) and not ${search.name}` });
                else changes.push({ from: end, to: end, insert: isFilter ? ` and not ${search.name}` : ` or ${search.name}` });
            }
        } else if (!det.conditionEntry) {
            changes[0].insert += `${ind}condition: ${search.name}\n`;
        }
        return changes;
    },

    /** Removes search `index` and its uses in the condition (a lone "and not x" / "or x" goes with it). */
    removeSearch(model, ruleName, index) {
        const rule = findRule(model, ruleName);
        const s = rule && rule.detection && rule.detection.searches[index];
        if (!s) return null;
        const text = model.text;
        const changes = [{ ...blockRange(text, s.entry), insert: '' }];
        for (const c of rule.detection.condition) {
            const parts = splitCondition(c.text);
            const kept = parts.filter(p => !new RegExp(`^(not\\s+)?${s.name.replace(/[.\-]/g, '\\$&')}$`).test(p.text.trim()));
            if (kept.length !== parts.length && kept.length) {
                if (kept[0]) kept[0] = { ...kept[0], op: null };
                const quoted = c.node.quoted === '"' || c.node.quoted === "'";
                changes.push({ from: quoted ? c.from + 1 : c.from, to: quoted ? c.to - 1 : c.to, insert: joinCondition(kept) });
            }
        }
        return changes;
    },

    splitCondition,
    joinCondition,

    setCondition(model, ruleName, condition) {
        const rule = findRule(model, ruleName);
        const det = rule && rule.detection;
        if (!det || !det.node || det.node.type !== 'map') return null;
        const value = String(condition || '').trim();
        if (!value) return null;
        const ce = det.conditionEntry;
        const text = model.text;
        if (ce && ce.value && ce.value.type === 'scalar') {
            const quoted = ce.value.quoted === '"' || ce.value.quoted === "'";
            return [{ from: quoted ? ce.value.from + 1 : ce.value.from, to: quoted ? ce.value.to - 1 : ce.value.to, insert: value }];
        }
        if (ce) return [{ from: ce.keyFrom, to: ce.value ? ce.value.to : ce.to, insert: `condition: ${value}` }];
        const first = det.node.entries[0];
        const ind = first ? text.slice(lineStart(text, first.keyFrom), first.keyFrom) : indentUnit(text, rule);
        const at = lineEnd(text, det.node.to);
        return [{ from: at, to: at, insert: `\n${ind}condition: ${value}` }];
    },

    /** Ready-made clauses offered by the condition form. */
    clauses(searches) {
        const names = searches.map(s => s.name);
        const sel = names.filter(n => !/^filter/i.test(n));
        const fil = names.filter(n => /^filter/i.test(n));
        const prefixes = [...new Set(names.map(n => n.match(/^(.*?_)[^_]*$/)).filter(Boolean).map(m => m[1]))];
        return [
            ...sel.map(n => ({ label: n, text: n })),
            ...fil.map(n => ({ label: `not ${n}`, text: `not ${n}` })),
            ...prefixes.filter(p => !/^filter/i.test(p)).flatMap(p => [{ label: `1 of ${p}*`, text: `1 of ${p}*` }, { label: `all of ${p}*`, text: `all of ${p}*` }]),
            ...prefixes.filter(p => /^filter/i.test(p)).map(p => ({ label: `not 1 of ${p}*`, text: `not 1 of ${p}*` })),
            ...(names.length > 1 ? [{ label: '1 of them', text: '1 of them' }] : []),
        ];
    },

    /** A name for a new search identifier: selection, selection_2… or filter_main_1… */
    newName(searches, filter = false) {
        const names = new Set(searches.map(s => s.name));
        const base = filter ? 'filter_main_' : (names.has('selection') ? 'selection_' : 'selection');
        if (!filter && base === 'selection') return 'selection';
        let n = 1;
        while (names.has(`${base}${n}`)) n++;
        return `${base}${n}`;
    },

    rename,
};
