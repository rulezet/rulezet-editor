/**
 * Sigma documents -> rule models. One YAML document (between --- lines) is one rule.
 *
 * model: { text, rules: [rule], errors }
 * rule:  { index, from, to, root (YAML map), kind: 'detection' | 'correlation' | 'filter' | 'unknown',
 *          title, id, status, level, date, modified, description, author, license: { value, from, to } | null,
 *          name: what the editor calls the rule (its title, made unique in the document),
 *          tags: [{ value, from, to }], references, falsepositives,
 *          logsource: { node, category, product, service } | null,
 *          detection: { node, searches: [search], condition: [condition] , timeframe } | null,
 *          yamlErrors: [{ from, to, message }] }
 * search:    { name, from, to, node, items: [{ field, fieldFrom, fieldTo, modifiers: [{ name, from, to }], values: [scalar], node }] }
 * condition: { from, to, text, tokens: [{ type, value, from, to }] }   one per condition line / list item
 */
import { parseYaml, entry, str, scalars } from './yaml.js';

function scalarInfo(node) {
    return node && node.type === 'scalar' ? { value: str(node), from: node.from, to: node.to, node } : null;
}

function listInfo(node) {
    return scalars(node).filter(s => s.value != null).map(s => ({ value: String(s.value), from: s.from, to: s.to }));
}

/** "Image|endswith|all" at `from` -> { field, fieldFrom, fieldTo, modifiers }. */
export function splitField(key, from) {
    const parts = key.split('|');
    const field = parts[0];
    const modifiers = [];
    let pos = from + field.length;
    for (const name of parts.slice(1)) {
        pos += 1;
        modifiers.push({ name, from: pos, to: pos + name.length });
        pos += name.length;
    }
    return { field, fieldFrom: from, fieldTo: from + field.length, modifiers };
}

/** The field / value items of one search identifier (map, list of maps, list of keywords). */
function searchItems(node) {
    const items = [];
    const fromMap = (map) => {
        for (const e of map.entries) {
            const f = splitField(e.key, e.keyFrom);
            items.push({ ...f, values: scalars(e.value), node: e.value, entry: e, keyed: true });
        }
    };
    if (!node) return items;
    if (node.type === 'map') fromMap(node);
    else if (node.type === 'seq') {
        for (const it of node.items) {
            if (it.type === 'map') fromMap(it);
            else items.push({ field: null, modifiers: [], values: scalars(it), node: it, keyed: false });   // keywords
        }
    } else items.push({ field: null, modifiers: [], values: [node], node, keyed: false });
    return items;
}

/** Condition text -> tokens: ( ) and or not of them, numbers, identifiers and patterns (with *), | */
export function conditionTokens(text, base) {
    const tokens = [];
    const re = /\s+|(\()|(\))|(\|)|([A-Za-z0-9_*.\-]+)|(\S)/g;
    let m;
    while ((m = re.exec(text))) {
        if (/^\s+$/.test(m[0])) continue;
        const from = base + m.index;
        const to = from + m[0].length;
        if (m[1]) tokens.push({ type: 'lparen', value: '(', from, to });
        else if (m[2]) tokens.push({ type: 'rparen', value: ')', from, to });
        else if (m[3]) tokens.push({ type: 'pipe', value: '|', from, to });
        else if (m[4]) {
            const w = m[4];
            const low = w.toLowerCase();
            if (['and', 'or', 'not', 'of', 'them'].includes(low)) tokens.push({ type: low, value: w, from, to });
            else if (/^\d+$/.test(w)) tokens.push({ type: 'number', value: w, from, to });
            else if (low === 'all' || low === 'any') tokens.push({ type: 'quantifier', value: w, from, to });
            else tokens.push({ type: w.includes('*') ? 'pattern' : 'ident', value: w, from, to });
        } else tokens.push({ type: 'unknown', value: m[0], from, to });
    }
    return tokens;
}

function conditionText(node) {
    // the raw text between the offsets: a quoted condition keeps its quotes out
    if (node.quoted === '"' || node.quoted === "'") return { text: node.value, base: node.from + 1 };
    return { text: String(node.value ?? ''), base: node.from };
}

function ruleKind(root) {
    if (!root || root.type !== 'map') return 'unknown';
    if (entry(root, 'correlation')) return 'correlation';
    if (entry(root, 'filter') && !entry(root, 'detection')) return 'filter';
    return 'detection';
}

export function parse(text) {
    const docs = parseYaml(String(text ?? ''));
    const rules = [];
    const errors = [];
    const seen = new Map();
    docs.forEach((doc, index) => {
        if (doc.empty) return;
        const root = doc.root;
        const map = root && root.type === 'map' ? root : null;
        const get = (k) => (map ? entry(map, k) : null);
        const val = (k) => { const e = get(k); return e ? scalarInfo(e.value) : null; };
        const rule = {
            index, from: doc.from, to: doc.to, root: map, rootNode: root, kind: ruleKind(map),
            title: val('title'), id: val('id'), status: val('status'), level: val('level'), date: val('date'),
            modified: val('modified'), description: val('description'), author: val('author'), license: val('license'),
            tags: get('tags') ? listInfo(get('tags').value) : [],
            references: get('references') ? listInfo(get('references').value) : [],
            falsepositives: get('falsepositives') ? listInfo(get('falsepositives').value) : [],
            logsource: null, detection: null, correlation: null, yamlErrors: doc.errors,
            yamlName: val('name'),           // the name a correlation rule refers to this rule by
        };
        const corr = get('correlation');
        if (corr) {
            const node = corr.value;
            const cv = (k) => (node && node.type === 'map' && entry(node, k) ? entry(node, k) : null);
            const rulesEntry = cv('rules');
            rule.correlation = {
                entry: corr, node, type: cv('type') ? scalarInfo(cv('type').value) : null,
                rulesEntry, rules: rulesEntry ? listInfo(rulesEntry.value) : [],
                timespan: cv('timespan') ? scalarInfo(cv('timespan').value) : null,
                groupBy: cv('group-by'), condition: cv('condition'),
            };
        }
        const ls = get('logsource');
        if (ls) {
            const node = ls.value;
            const lv = (k) => (node && node.type === 'map' && entry(node, k) ? scalarInfo(entry(node, k).value) : null);
            rule.logsource = { entry: ls, node, category: lv('category'), product: lv('product'), service: lv('service') };
        }
        const det = get('detection');
        if (det) {
            const node = det.value;
            const searches = [];
            const condition = [];
            let timeframe = null;
            let conditionEntry = null;
            if (node && node.type === 'map') {
                for (const e of node.entries) {
                    if (e.key === 'condition') {
                        conditionEntry = e;
                        for (const s of scalars(e.value)) {
                            const { text: t, base } = conditionText(s);
                            condition.push({ from: s.from, to: s.to, text: t, tokens: conditionTokens(t, base), node: s });
                        }
                    } else if (e.key === 'timeframe') {
                        timeframe = scalarInfo(e.value);
                    } else {
                        searches.push({ name: e.key, from: e.keyFrom, to: e.keyTo, entry: e, node: e.value, items: searchItems(e.value) });
                    }
                }
            }
            rule.detection = { entry: det, node, searches, condition, conditionEntry, timeframe };
        }
        // the editor's name for the rule: its title, unique in the document
        const base = (rule.title && rule.title.value.trim()) || `(untitled rule ${rules.length + 1})`;
        const n = (seen.get(base) || 0) + 1;
        seen.set(base, n);
        rule.name = n > 1 ? `${base} (${n})` : base;
        rules.push(rule);
    });
    return { text: String(text ?? ''), rules, errors };
}

/** The rule whose document contains pos (or the only rule). */
export function ruleAt(model, pos) {
    return model.rules.find(r => pos >= r.from && pos <= r.to + 1) || null;
}

/** Search identifiers a condition token stands for (exact name, a * pattern, or "them"). */
export function matchSearches(rule, token) {
    const searches = (rule.detection && rule.detection.searches) || [];
    if (token.type === 'them') return searches;               // pySigma: every search identifier (pattern .*)
    if (token.type === 'pattern') {
        const re = new RegExp('^' + token.value.split('*').map(x => x.replace(/[.+?^${}()|[\]\\-]/g, '\\$&')).join('.*') + '$');
        return searches.filter(s => re.test(s.name));
    }
    if (token.type === 'ident') return searches.filter(s => s.name === token.value);
    return [];
}
