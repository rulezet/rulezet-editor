/**
 * Writing into a Sigma rule (rule tools, Fields panel) and the rule tools themselves. Changes
 * keep the rule's own indentation and put a new key where the specification orders it.
 *
 *   { id, label, input?: { label, placeholder, value? }, run(ctx, value) -> changes[] | { error } }
 */
import { TOP_KEYS, STATUS, LEVEL } from './data.js';
import { ruleAt } from './parser.js';
import { entry, yamlValue } from './yaml.js';

const ORDER = TOP_KEYS.map(k => k.key);

/** The rule's own indentation step (the first nested line), 4 spaces by default. */
export function indentUnit(text, rule) {
    if (rule && rule.root) {
        for (const e of rule.root.entries) {
            const v = e.value;
            if (v && (v.type === 'map' || v.type === 'seq') && !v.flow) {
                const s = text.lastIndexOf('\n', v.from - 1) + 1;
                const n = v.from - s;
                if (n > 0 && n <= 8) return ' '.repeat(n);
            }
        }
    }
    return '    ';
}

function lineEnd(text, pos) { const i = text.indexOf('\n', pos); return i === -1 ? text.length : i; }
function lineStart(text, pos) { return text.lastIndexOf('\n', pos - 1) + 1; }

/** Where a new top-level key goes: after the last present key that comes before it in the spec order. */
function insertPoint(text, rule, key) {
    const want = ORDER.indexOf(key);
    let after = null;
    for (const e of rule.root.entries) {
        const i = ORDER.indexOf(e.key);
        if (i !== -1 && i < want) after = e;
    }
    if (after) return { at: lineEnd(text, after.to), before: '\n', after: '' };
    const first = rule.root.entries[0];
    return first ? { at: lineStart(text, first.keyFrom), before: '', after: '\n' } : { at: rule.to, before: '\n', after: '' };
}

/** Sets a top-level scalar key (replaced, or added at its place). rawValue is written as is. */
export function setTop(text, rule, key, rawValue) {
    const e = entry(rule.root, key);
    if (e) {
        if (e.value && e.value.type === 'scalar') return [{ from: e.value.from, to: e.value.to, insert: rawValue }];
        return [{ from: e.keyFrom, to: e.value ? e.value.to : e.to, insert: `${key}: ${rawValue}` }];
    }
    const p = insertPoint(text, rule, key);
    return [{ from: p.at, to: p.at, insert: `${p.before}${key}: ${rawValue}${p.after}` }];
}

/** Replaces a top-level list with `values` (or adds it). */
export function setList(text, rule, key, values) {
    const ind = indentUnit(text, rule);
    const body = values.map(v => `${ind}- ${yamlValue(v)}`).join('\n');
    const e = entry(rule.root, key);
    if (e) return [{ from: e.keyFrom, to: e.value ? e.value.to : e.to, insert: `${key}:\n${body}` }];
    const p = insertPoint(text, rule, key);
    return [{ from: p.at, to: p.at, insert: `${p.before}${key}:\n${body}${p.after}` }];
}

/** Adds one item to a top-level list (created when missing). */
export function addListItem(text, rule, key, value) {
    const e = entry(rule.root, key);
    const ind = indentUnit(text, rule);
    if (e && e.value && e.value.type === 'seq' && !e.value.flow && e.value.items.length) {
        const last = e.value.items[e.value.items.length - 1];
        const prefix = text.slice(lineStart(text, last.from), last.from);       // "    - ": the list's own layout
        const at = lineEnd(text, last.to);
        if (/^ *- +$/.test(prefix)) return [{ from: at, to: at, insert: `\n${prefix}${yamlValue(value)}` }];
    }
    if (e) return [{ from: e.keyFrom, to: e.value ? e.value.to : e.to, insert: `${key}:\n${ind}- ${yamlValue(value)}` }];
    return setList(text, rule, key, [value]);
}

/** Removes a top-level key and its block. */
export function removeTop(text, rule, key) {
    const e = entry(rule.root, key);
    if (!e) return [];
    const s = lineStart(text, e.keyFrom);
    let end = lineEnd(text, e.value ? e.value.to : e.to);
    end = end < text.length ? end + 1 : end;
    return [{ from: s === 0 ? 0 : s, to: end, insert: '' }];
}

const noRule = { error: 'Put the cursor inside a rule' };

function target(ctx) {
    const rules = ctx.parsed.rules.filter(r => r.root);
    return ruleAt(ctx.parsed, ctx.pos) || (rules.length === 1 ? rules[0] : null);
}

export const ACTIONS = [
    {
        id: 'sigma.date', label: 'Add date (or update "modified")',
        run(ctx) {
            const r = target(ctx);
            if (!r) return noRule;
            return r.date ? setTop(ctx.text, r, 'modified', '{{date}}') : setTop(ctx.text, r, 'date', '{{date}}');
        },
    },
    {
        id: 'sigma.id', label: 'Add an id (UUID)',
        run(ctx) {
            const r = target(ctx);
            if (!r) return noRule;
            if (r.id) return { error: 'This rule already has an id' };
            return setTop(ctx.text, r, 'id', '{{uuid}}');
        },
    },
    {
        id: 'sigma.newId', label: 'Replace the id with a new UUID (and link the old one as derived)',
        run(ctx) {
            const r = target(ctx);
            if (!r) return noRule;
            const changes = setTop(ctx.text, r, 'id', '{{uuid}}');
            if (r.id && /^[0-9a-f-]{36}$/i.test(r.id.value) && !entry(r.root, 'related')) {
                const ind = indentUnit(ctx.text, r);
                changes.push(...setRelated(ctx.text, r, `related:\n${ind}- id: ${r.id.value}\n${ind}  type: derived`));
            }
            return changes;
        },
    },
    {
        id: 'sigma.author', label: 'Set author',
        input: { label: 'Author', placeholder: 'Name or handle', value: (ctx) => ctx.author || '' },
        run(ctx, value) {
            const r = target(ctx);
            if (!r) return noRule;
            if (!String(value || '').trim()) return { error: 'Type a name' };
            return setTop(ctx.text, r, 'author', yamlValue(String(value).trim()));
        },
    },
    {
        id: 'sigma.reference', label: 'Add a reference',
        input: { label: 'URL', placeholder: 'https://…' },
        run(ctx, value) {
            const r = target(ctx);
            if (!r) return noRule;
            const v = String(value || '').trim();
            if (!/^https?:\/\/\S+$/.test(v)) return { error: 'A reference is a web address (https://…)' };
            if (r.references.some(x => x.value === v)) return { error: 'Already listed' };
            return addListItem(ctx.text, r, 'references', v);
        },
    },
    {
        id: 'sigma.attack', label: 'Add an ATT&CK technique tag',
        input: { label: 'Technique', placeholder: 'T1059.001' },
        run(ctx, value) {
            const r = target(ctx);
            if (!r) return noRule;
            const v = String(value || '').trim().toLowerCase();
            if (!/^t\d{4}(\.\d{3})?$/.test(v)) return { error: 'A technique id: T1059 or T1059.001' };
            if (r.tags.some(x => x.value === `attack.${v}`)) return { error: 'Already tagged' };
            return addListItem(ctx.text, r, 'tags', `attack.${v}`);
        },
    },
    {
        id: 'sigma.falsepositive', label: 'Add a false positive',
        input: { label: 'False positive', placeholder: 'Legitimate admin scripts' },
        run(ctx, value) {
            const r = target(ctx);
            if (!r) return noRule;
            const v = String(value || '').trim();
            if (v.length < 2) return { error: 'Describe it in a few words' };
            return addListItem(ctx.text, r, 'falsepositives', v);
        },
    },
    {
        id: 'sigma.level', label: 'Set level',
        input: { label: `Level (${Object.keys(LEVEL).join(', ')})`, placeholder: 'medium', value: (ctx) => { const r = target(ctx); return r && r.level ? r.level.value : 'medium'; } },
        run(ctx, value) {
            const r = target(ctx);
            if (!r) return noRule;
            const v = String(value || '').trim().toLowerCase();
            if (!LEVEL[v]) return { error: `One of ${Object.keys(LEVEL).join(', ')}` };
            return setTop(ctx.text, r, 'level', v);
        },
    },
    {
        id: 'sigma.status', label: 'Set status',
        input: { label: `Status (${Object.keys(STATUS).join(', ')})`, placeholder: 'experimental', value: (ctx) => { const r = target(ctx); return r && r.status ? r.status.value : 'experimental'; } },
        run(ctx, value) {
            const r = target(ctx);
            if (!r) return noRule;
            const v = String(value || '').trim().toLowerCase();
            if (!STATUS[v]) return { error: `One of ${Object.keys(STATUS).join(', ')}` };
            return setTop(ctx.text, r, 'status', v);
        },
    },
    {
        id: 'sigma.filter', label: 'Add a filter (exclude benign activity)',
        input: { label: 'Filter name', placeholder: 'filter_main_legit', value: 'filter_main_' },
        run(ctx, value) {
            const r = target(ctx);
            if (!r || !r.detection || !r.detection.conditionEntry || r.detection.condition.length !== 1) return { error: 'The rule needs a detection with one condition' };
            const name = String(value || '').trim();
            if (!/^[A-Za-z_]\w*$/.test(name)) return { error: 'Letters, digits and _' };
            if (r.detection.searches.some(s => s.name === name)) return { error: `${name} already exists` };
            const ce = r.detection.conditionEntry;
            const s = lineStart(ctx.text, ce.keyFrom);
            const ind = ctx.text.slice(s, ce.keyFrom);
            const unit = indentUnit(ctx.text, r);
            const c = r.detection.condition[0];
            const quoted = c.node.quoted === '"' || c.node.quoted === "'";
            const end = quoted ? c.to - 1 : c.to;
            const cond = c.tokens.some(t => t.type === 'or') ? [{ from: quoted ? c.from + 1 : c.from, to: quoted ? c.from + 1 : c.from, insert: '(' }, { from: end, to: end, insert: `) and not ${name}` }]
                : [{ from: end, to: end, insert: ` and not ${name}` }];
            return [{ from: s, to: s, insert: `${ind}${name}:\n${ind}${unit}ParentImage|endswith: '\\legit.exe'\n` }, ...cond];
        },
    },
    {
        id: 'sigma.lowercaseTags', label: 'Fix the tags (lower case, dashes for tactics)',
        run(ctx) {
            const r = target(ctx);
            if (!r) return noRule;
            const changes = [];
            for (const t of r.tags) {
                let v = t.value.toLowerCase().replace(/\s+/g, '-');
                if (v.startsWith('attack.') && !/^attack\.t\d/.test(v)) v = v.replace(/_/g, '-');
                if (v !== t.value) changes.push({ from: t.from, to: t.to, insert: v });
            }
            return changes.length ? changes : { error: 'The tags are fine' };
        },
    },
];

function setRelated(text, rule, block) {
    const p = (() => {
        const want = ORDER.indexOf('related');
        let after = null;
        for (const e of rule.root.entries) { const i = ORDER.indexOf(e.key); if (i !== -1 && i < want) after = e; }
        return after ? lineEnd(text, after.to) : rule.from;
    })();
    return [{ from: p, to: p, insert: p === rule.from ? `${block}\n` : `\n${block}` }];
}

/** Actions offered at this position (all of them need a rule). */
export function actions(ctx) {
    return target(ctx) ? ACTIONS : [];
}
