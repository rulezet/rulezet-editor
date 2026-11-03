/**
 * Sigma lint, aligned on what Rulezet refuses: its JSON schema (title, logsource, detection +
 * condition, date format, list keys), pySigma's parsing (modifiers, status, level, id, condition)
 * and pySigma's HIGH-severity checks (unused search identifier, unknown identifier in the
 * condition, `all` without `contains`, `base64offset` without `contains`, `windash` with `all`,
 * control characters, same id / title twice). Those are errors; pySigma's MEDIUM checks are
 * warnings, its LOW ones infos. Each diagnostic has a stable code and, when it helps, fixes.
 */
import { TOP_KEYS, STATUS, LEVEL, RELATED_TYPES, MODIFIERS, TACTICS, TLP, TAG_NAMESPACES } from './data.js';
import { matchSearches } from './parser.js';
import { entry, yamlValue } from './yaml.js';

export const DEFAULT_LINT_OPTIONS = {
    suggest: true,          // infos: missing id / description / author / level, wildcards instead of modifiers
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DATE = /^\d{4}([-/])(0[1-9]|1[0-2])\1(0[1-9]|[12][0-9]|3[01])$/;
const LIST_KEYS = ['references', 'tags', 'falsepositives', 'fields', 'scope', 'related'];
const KNOWN = new Set(TOP_KEYS.map(k => k.key));
const NUMERIC = ['gt', 'gte', 'lt', 'lte', 'minute', 'hour', 'day', 'week', 'month', 'year'];
const RE_FLAGS = ['i', 'ignorecase', 'm', 'multiline', 's', 'dotall'];

function distance(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        }
    }
    return d[a.length][b.length];
}

/** Up to 3 names of `list` close to `word` (typos). */
export function closest(word, list, max = 2) {
    const w = String(word).toLowerCase();
    return list.map(x => ({ x, d: distance(w, String(x).toLowerCase()) }))
        .filter(o => o.d <= Math.max(1, Math.min(max, Math.floor(w.length / 3))) || String(o.x).toLowerCase().startsWith(w))
        .sort((a, b) => a.d - b.d).slice(0, 3).map(o => o.x);
}

/** The whole line of `pos` (with its newline), to remove it. */
function lineRange(text, from, to = from) {
    const s = text.lastIndexOf('\n', from - 1) + 1;
    let e = text.indexOf('\n', to);
    e = e === -1 ? text.length : e + 1;
    return { from: s, to: e };
}

function lineIndent(text, pos) {
    const s = text.lastIndexOf('\n', pos - 1) + 1;
    return text.slice(s, pos).match(/^[ ]*/)[0];
}

export function lint(model, options = {}) {
    const opts = { ...DEFAULT_LINT_OPTIONS, ...options };
    const text = model.text;
    const out = [];
    const add = (from, to, severity, message, code, fixes) => {
        from = Math.max(0, Math.min(from, text.length));
        to = Math.max(from, Math.min(Math.max(to, from + 1), text.length));
        out.push({ from, to, severity, message, code, ...(fixes && fixes.length ? { fixes } : {}) });
    };

    const ids = new Map();
    const titles = new Map();
    const docIds = new Set(model.rules.map(r => r.id && r.id.value && r.id.value.trim()).filter(Boolean));
    // what a correlation rule may name: the id or the name: of a rule of this document
    const refsHere = new Set([...docIds, ...model.rules.map(r => r.yamlName && r.yamlName.value.trim()).filter(Boolean)]);
    for (const rule of model.rules) {
        for (const e of rule.yamlErrors) add(e.from, e.to, 'error', `YAML: ${e.message}`, 'yaml');
        lintRule(rule, text, add, opts, refsHere);
        // related: a rule of this document, or one to look up on the host (Rulezet)
        const rel = rule.root && entry(rule.root, 'related');
        if (rel && rel.value && rel.value.type === 'seq') {
            for (const it of rel.value.items) {
                const id = it.type === 'map' ? entry(it, 'id') : null;
                const v = id && id.value && id.value.type === 'scalar' ? String(id.value.value || '').trim() : '';
                if (UUID.test(v) && !docIds.has(v)) add(id.value.from, id.value.to, 'info', `Related rule ${v} is not in this document`, 'external-rule');
            }
        }
        if (rule.id && rule.id.value) (ids.get(rule.id.value) || ids.set(rule.id.value, []).get(rule.id.value)).push(rule.id);
        if (rule.title && rule.title.value) (titles.get(rule.title.value) || titles.set(rule.title.value, []).get(rule.title.value)).push(rule.title);
    }
    for (const [id, list] of ids) {
        if (list.length > 1) {
            for (const n of list.slice(1)) {
                add(n.from, n.to, 'error', `The id ${id} is used by another rule of this document: each rule needs its own`, 'duplicate-id',
                    [{ label: 'Use a new UUID', changes: [{ from: n.from, to: n.to, insert: '{{uuid}}' }] }]);
            }
        }
    }
    for (const [title, list] of titles) {
        if (list.length > 1) for (const n of list.slice(1)) add(n.from, n.to, 'error', `Another rule of this document is titled "${title}": titles must be unique`, 'duplicate-title');
    }
    return out;
}

function lintRule(rule, text, add, opts, refsHere = new Set()) {
    const at = rule.from;
    const root = rule.root;
    if (!root) {
        if (rule.rootNode) add(rule.from, rule.to, 'error', 'A Sigma rule is a YAML mapping of "key: value" lines', 'not-a-map');
        return;
    }
    // a correlation rule combines other rules (no logsource / detection of its own)
    if (rule.kind === 'correlation') {
        lintCorrelation(rule, text, add, refsHere);
        return;
    }
    if (rule.kind === 'filter') {
        const e = entry(root, 'filter');
        add(e.keyFrom, e.keyTo, 'error', 'A filter rule (meta filter): Rulezet stores detection and correlation rules only', 'filter-rule');
        return;
    }

    // ── keys ────────────────────────────────────────────────────────────────
    const seen = new Map();
    for (const e of root.entries) {
        if (seen.has(e.key)) add(e.keyFrom, e.keyTo, 'warning', `"${e.key}" is written twice: only the last one counts`, 'duplicate-key');
        seen.set(e.key, e);
        if (!KNOWN.has(e.key)) {
            const near = closest(e.key, [...KNOWN]);
            if (near.length) {
                add(e.keyFrom, e.keyTo, 'warning', `Unknown key "${e.key}": did you mean "${near[0]}"?`, 'unknown-key',
                    near.map(k => ({ label: `Rename to ${k}`, changes: [{ from: e.keyFrom, to: e.keyTo, insert: k }] })));
            } else {
                add(e.keyFrom, e.keyTo, 'info', `"${e.key}" is not a Sigma key: kept as a custom attribute`, 'custom-key');
            }
        }
        if (LIST_KEYS.includes(e.key) && e.value && e.value.type !== 'seq') {
            const fixes = e.value.type === 'scalar' && e.value.value
                ? [{ label: 'Make it a list', changes: [{ from: e.value.from, to: e.value.to, insert: `\n${lineIndent(text, e.keyFrom)}    - ${e.value.raw}` }] }]
                : undefined;
            add(e.keyFrom, e.value.to, 'error', `"${e.key}" must be a list ("- item" lines)`, 'not-a-list', fixes);
        }
    }

    // required: title, logsource, detection
    const top = rule.from;
    if (!rule.title || !rule.title.value.trim()) {
        const e = entry(root, 'title');
        if (e) add(e.keyFrom, e.to, 'error', 'The title is empty', 'title-required');
        else add(top, top, 'error', 'A Sigma rule needs a title', 'title-required', [{ label: 'Add a title', changes: [{ from: top, to: top, insert: 'title: New rule\n' }] }]);
    } else if (rule.title.value.length > 256) {
        add(rule.title.from, rule.title.to, 'error', `The title is too long (${rule.title.value.length} characters, 256 at most)`, 'title-length');
    }
    if (!rule.logsource) {
        add(at, at, 'error', 'A Sigma rule needs a logsource (category / product / service)', 'logsource-required',
            [{ label: 'Add a logsource', changes: [{ from: rule.to, to: rule.to, insert: '\nlogsource:\n    category: process_creation\n    product: windows' }] }]);
    } else if (!rule.logsource.node || rule.logsource.node.type !== 'map') {
        add(rule.logsource.entry.keyFrom, rule.logsource.entry.to, 'error', 'logsource must hold category / product / service keys', 'logsource-map');
    } else {
        const ls = rule.logsource;
        if (!ls.category && !ls.product && !ls.service) {
            add(ls.entry.keyFrom, ls.entry.keyTo, 'warning', 'The logsource names no category, product nor service: the rule cannot be matched to any log', 'logsource-empty');
        }
        for (const e of ls.node.entries) {
            if (!['category', 'product', 'service', 'definition'].includes(e.key)) {
                // pySigma: a custom logsource attribute is refused (FieldnameLogsource, HIGH)
                const near = closest(e.key, ['category', 'product', 'service', 'definition']);
                add(e.keyFrom, e.keyTo, 'error', `"${e.key}" is not a logsource key: category, product, service or definition`, 'logsource-key',
                    near.map(k => ({ label: `Rename to ${k}`, changes: [{ from: e.keyFrom, to: e.keyTo, insert: k }] })));
            }
        }
    }
    if (!rule.detection) {
        add(at, at, 'error', 'A Sigma rule needs a detection section (search identifiers + condition)', 'detection-required',
            [{ label: 'Add a detection', changes: [{ from: rule.to, to: rule.to, insert: '\ndetection:\n    selection:\n        Image|endswith: \'\\example.exe\'\n    condition: selection' }] }]);
    } else {
        lintDetection(rule, text, add, opts);
    }

    // ── metadata values ─────────────────────────────────────────────────────
    if (rule.id) {
        if (!UUID.test(rule.id.value.trim())) {
            add(rule.id.from, rule.id.to, 'error', 'The id must be a UUID (e.g. 929a690e-bef0-4204-a928-ef5e620d6fcc)', 'id-uuid',
                [{ label: 'Replace with a new UUID', changes: [{ from: rule.id.from, to: rule.id.to, insert: '{{uuid}}' }] }]);
        }
    } else if (opts.suggest) {
        const t = entry(root, 'title');
        const pos = t ? Math.min(text.length, (text.indexOf('\n', t.to) + 1) || text.length) : top;
        add(t ? t.keyFrom : top, t ? t.keyTo : top, 'info', 'No id: add a UUID so the rule can be recognised when it is updated', 'id-missing',
            [{ label: 'Add an id', changes: [{ from: pos, to: pos, insert: 'id: {{uuid}}\n' }] }]);
    }
    enumValue(rule.status, STATUS, 'status', add);
    enumValue(rule.level, LEVEL, 'level', add);
    for (const k of ['date', 'modified']) {
        const v = rule[k];
        if (v && !DATE.test(v.value.trim())) {
            add(v.from, v.to, 'error', `${k} must be a date written YYYY-MM-DD`, 'date-format',
                [{ label: 'Use today\'s date', changes: [{ from: v.from, to: v.to, insert: '{{date}}' }] }]);
        }
    }
    if (rule.date && rule.modified && DATE.test(rule.date.value) && DATE.test(rule.modified.value)
        && rule.modified.value.replace(/\//g, '-') < rule.date.value.replace(/\//g, '-')) {
        add(rule.modified.from, rule.modified.to, 'warning', 'modified is before date', 'date-order');
    }
    if (rule.description && rule.description.value.length > 65535) {
        add(rule.description.from, rule.description.to, 'error', 'The description is too long (65535 characters at most)', 'description-length');
    }
    if (opts.suggest) {
        if (!rule.description) {
            const t = entry(root, 'title');
            if (t) add(t.keyFrom, t.keyTo, 'info', 'No description: say what the rule detects and why', 'description-missing');
        }
        if (!rule.level && rule.detection) {
            add(rule.detection.entry.keyFrom, rule.detection.entry.keyTo, 'info', 'No level: low, medium, high or critical tells analysts how urgent a hit is', 'level-missing',
                [{ label: 'Add level: medium', changes: [{ from: rule.to, to: rule.to, insert: '\nlevel: medium' }] }]);
        }
    }

    // related: [{ id, type }]
    const rel = entry(root, 'related');
    if (rel && rel.value && rel.value.type === 'seq') {
        for (const it of rel.value.items) {
            if (it.type !== 'map') { add(it.from, it.to, 'error', 'Each related item needs an id and a type', 'related-item'); continue; }
            const id = entry(it, 'id');
            const type = entry(it, 'type');
            if (!id || !UUID.test(String(id.value && id.value.value || ''))) add(it.from, it.from + 1, 'error', 'related: the id must be the UUID of the related rule', 'related-id');
            const tv = type && type.value && type.value.value;
            if (!type || !RELATED_TYPES[tv]) {
                add(type ? type.value.from : it.from, type ? type.value.to : it.from + 1, 'error', `related: type must be one of ${Object.keys(RELATED_TYPES).join(', ')}`, 'related-type',
                    type && tv ? closest(tv, Object.keys(RELATED_TYPES)).map(k => ({ label: `Use ${k}`, changes: [{ from: type.value.from, to: type.value.to, insert: k }] })) : undefined);
            }
        }
    }

    lintTags(rule, text, add);
    // the schema refuses the same item twice in these lists (uniqueItems)
    const fieldsEntry = entry(root, 'fields');
    const lists = { references: rule.references, falsepositives: rule.falsepositives, fields: fieldsEntry && fieldsEntry.value && fieldsEntry.value.type === 'seq' ? fieldsEntry.value.items.filter(x => x.type === 'scalar').map(x => ({ value: String(x.value), from: x.from, to: x.to })) : [] };
    for (const [key, items] of Object.entries(lists)) {
        const seenItems = new Set();
        for (const r of items) {
            if (seenItems.has(r.value)) add(r.from, r.to, 'error', `Listed twice in ${key} (Rulezet refuses duplicates)`, `duplicate-${key}`, [{ label: 'Remove it', changes: [{ ...lineRange(text, r.from, r.to), insert: '' }] }]);
            seenItems.add(r.value);
        }
    }
    for (const key of ['falsepositives', 'scope']) {
        const e = entry(root, key);
        if (!e || !e.value || e.value.type !== 'seq') continue;
        for (const it of e.value.items) {
            if (it.type === 'scalar' && String(it.value ?? '').trim().length < 2) add(it.from, Math.max(it.to, it.from + 1), 'error', `A ${key} item needs at least 2 characters`, `${key}-item`);
        }
    }
}

export const CORRELATION_TYPES = {
    event_count: 'Counts the events the rules match (condition on the count): "more than 10 failed logons by user in 5 minutes".',
    value_count: 'Counts distinct values of a field (condition.field): "one source logs on to more than 20 hosts".',
    temporal: 'All the rules match within the timespan, in any order.',
    temporal_ordered: 'All the rules match within the timespan, in the order listed.',
    value_sum: 'Sum of a field (condition.field) over the timespan.',
    value_avg: 'Average of a field (condition.field) over the timespan.',
    value_percentile: 'Percentile of a field (condition.field, condition.percentile).',
    value_median: 'Median of a field (condition.field).',
};
const CORR_OPS = ['gt', 'gte', 'lt', 'lte', 'eq', 'neq'];

function lintCorrelation(rule, text, add, refsHere) {
    const root = rule.root;
    const c = rule.correlation;
    if (!rule.title || !rule.title.value.trim()) add(rule.from, rule.from, 'error', 'A correlation rule needs a title', 'title-required');
    if (!c.node || c.node.type !== 'map') {
        add(c.entry.keyFrom, c.entry.to, 'error', 'correlation must hold type, rules, timespan (and group-by, condition)', 'correlation-map');
        return;
    }
    const type = c.type ? c.type.value.trim() : '';
    if (!c.type) add(c.entry.keyFrom, c.entry.keyTo, 'error', `correlation.type is missing: ${Object.keys(CORRELATION_TYPES).join(', ')}`, 'correlation-type');
    else if (!CORRELATION_TYPES[type]) {
        add(c.type.from, c.type.to, 'error', `Unknown correlation type: ${Object.keys(CORRELATION_TYPES).join(', ')}`, 'correlation-type',
            closest(type, Object.keys(CORRELATION_TYPES), 3).map(k => ({ label: `Use ${k}`, changes: [{ from: c.type.from, to: c.type.to, insert: k }] })));
    }
    if (!c.rulesEntry || !c.rules.length) add(c.entry.keyFrom, c.entry.keyTo, 'error', 'correlation.rules must list the rules it combines (their name: or id)', 'correlation-rules');
    for (const r of c.rules) {
        if (!refsHere.has(r.value.trim())) add(r.from, r.to, 'info', `Rule ${r.value} is not in this document`, 'external-rule');
    }
    if (!c.timespan) add(c.entry.keyFrom, c.entry.keyTo, 'error', 'correlation.timespan is missing (e.g. 5m, 1h, 1d)', 'correlation-timespan');
    else if (!/^\d+[smhdwMy]$/.test(c.timespan.value.trim())) add(c.timespan.from, c.timespan.to, 'error', 'timespan is a number and a unit: 30s, 5m, 1h, 1d, 1w, 1M, 1y', 'correlation-timespan');
    if (c.groupBy && c.groupBy.value && c.groupBy.value.type !== 'seq') add(c.groupBy.keyFrom, c.groupBy.to, 'error', 'group-by must be a list of fields', 'correlation-groupby');
    const counting = type && !type.startsWith('temporal');
    if (counting && CORRELATION_TYPES[type]) {
        const cond = c.condition && c.condition.value;
        if (!c.condition || !cond || cond.type !== 'map') {
            add((c.condition || c.entry).keyFrom, (c.condition || c.entry).keyTo, 'error', `${type} needs a condition: e.g. "gte: 10"`, 'correlation-condition');
        } else {
            const ops = cond.entries.filter(e => CORR_OPS.includes(e.key));
            if (!ops.length) add(c.condition.keyFrom, c.condition.keyTo, 'error', `The condition needs an operator: ${CORR_OPS.join(', ')}`, 'correlation-condition');
            for (const e of cond.entries) {
                if (!CORR_OPS.includes(e.key) && !['field', 'percentile'].includes(e.key)) {
                    add(e.keyFrom, e.keyTo, 'error', `Unknown condition key: ${CORR_OPS.join(', ')}, field`, 'correlation-condition',
                        closest(e.key, CORR_OPS).map(k => ({ label: `Use ${k}`, changes: [{ from: e.keyFrom, to: e.keyTo, insert: k }] })));
                } else if (CORR_OPS.includes(e.key) && !/^-?\d+(\.\d+)?$/.test(String(e.value && e.value.value))) {
                    add(e.value ? e.value.from : e.keyFrom, e.value ? e.value.to : e.keyTo, 'error', `${e.key} takes a number`, 'correlation-condition');
                }
            }
            if (type.startsWith('value_') && !cond.entries.some(e => e.key === 'field')) {
                add(c.condition.keyFrom, c.condition.keyTo, 'error', `${type} needs condition.field: the field whose values are counted / summed`, 'correlation-condition');
            }
        }
    }
    for (const k of ['date', 'modified']) {
        const v = rule[k];
        if (v && !DATE.test(v.value.trim())) add(v.from, v.to, 'error', `${k} must be a date written YYYY-MM-DD`, 'date-format');
    }
    enumValue(rule.status, STATUS, 'status', add);
    enumValue(rule.level, LEVEL, 'level', add);
    if (rule.id && !UUID.test(rule.id.value.trim())) add(rule.id.from, rule.id.to, 'error', 'The id must be a UUID', 'id-uuid');
    void root; void text;
}

function enumValue(v, values, key, add) {
    if (!v) return;
    const value = v.value.trim();
    if (values[value]) return;
    const near = closest(value, Object.keys(values), 3);
    add(v.from, v.to, 'error', `${key} must be one of ${Object.keys(values).join(', ')}`, `${key}-value`,
        (near.length ? near : Object.keys(values)).map(k => ({ label: `Use ${k}`, changes: [{ from: v.from, to: v.to, insert: k }] })));
}

function lintTags(rule, text, add) {
    const seen = new Set();
    for (const t of rule.tags) {
        const tag = t.value;
        if (seen.has(tag)) {
            add(t.from, t.to, 'error', `The tag ${tag} is listed twice (Rulezet refuses duplicates)`, 'duplicate-tag', [{ label: 'Remove it', changes: [{ ...lineRange(text, t.from, t.to), insert: '' }] }]);
            continue;
        }
        seen.add(tag);
        if (!/^[a-z0-9_-]+\.[a-z0-9._-]+$/.test(tag)) {
            const lower = tag.toLowerCase().replace(/\s+/g, '-');
            add(t.from, t.to, 'error', 'A tag is namespace.name: lower case letters, digits, _ - . only (e.g. attack.t1059.001)', 'tag-format',
                lower !== tag && /^[a-z0-9_-]+\.[a-z0-9._-]+$/.test(lower) ? [{ label: `Use ${lower}`, changes: [{ from: t.from, to: t.to, insert: lower }] }] : undefined);
            continue;
        }
        const [ns, ...restParts] = tag.split('.');
        const name = restParts.join('.');
        if (ns === 'attack') {
            if (/^t\d{4}(\.\d{3})?$/.test(name) || /^[gsm]\d{4}$/.test(name) || /^ds\d{4}$/.test(name) || TACTICS[name]) continue;
            const dashed = name.replace(/_/g, '-');
            if (TACTICS[dashed]) {
                add(t.from, t.to, 'warning', `ATT&CK tactics are written with dashes: attack.${dashed}`, 'attack-tag',
                    [{ label: `Use attack.${dashed}`, changes: [{ from: t.from, to: t.to, insert: `attack.${dashed}` }] }]);
            } else {
                const near = closest(name, Object.keys(TACTICS), 3);
                add(t.from, t.to, 'warning', 'Not an ATT&CK tag: a technique (attack.t1059.001), a tactic (attack.execution), a group (attack.g0016) or software (attack.s0002)', 'attack-tag',
                    near.map(k => ({ label: `Use attack.${k}`, changes: [{ from: t.from, to: t.to, insert: `attack.${k}` }] })));
            }
        } else if (ns === 'tlp' && !TLP.includes(name) && name !== 'white') {
            add(t.from, t.to, 'warning', `TLP tags: ${TLP.map(x => 'tlp.' + x).join(', ')}`, 'tlp-tag');
        } else if (ns === 'cve' && !/^\d{4}-\d{4,}$/.test(name)) {
            add(t.from, t.to, 'warning', 'A CVE tag is cve.YYYY-NNNN (e.g. cve.2024-3094)', 'cve-tag');
        } else if (!TAG_NAMESPACES[ns]) {
            add(t.from, t.to, 'info', `"${ns}" is not a usual Sigma tag namespace (attack, cve, tlp, detection, car, stp, d3fend)`, 'tag-namespace');
        }
    }
}

function lintDetection(rule, text, add, opts) {
    const det = rule.detection;
    if (!det.node || det.node.type !== 'map') {
        add(det.entry.keyFrom, det.entry.to, 'error', 'detection must hold search identifiers and a condition', 'detection-map');
        return;
    }
    const searches = det.searches;
    if (!searches.length) add(det.entry.keyFrom, det.entry.keyTo, 'error', 'The detection has no search identifier (e.g. selection:)', 'no-search');

    for (const s of searches) {
        if (!/^[A-Za-z0-9_][A-Za-z0-9_.\-]*$/.test(s.name)) add(s.from, s.to, 'warning', 'Use letters, digits and _ in search identifier names (the condition refers to them)', 'search-name');
        if (!s.node || (s.node.type === 'scalar' && (s.node.value === null || s.node.value === ''))) {
            add(s.from, s.to, 'error', `The search identifier "${s.name}" is empty`, 'empty-search');
            continue;
        }
        if (s.node.type === 'scalar') {
            // Rulezet's schema: a search is a list (keywords) or "field: value" lines
            add(s.from, s.node.to, 'error', `"${s.name}" must be a list of keywords ("- value") or "field: value" lines`, 'search-scalar',
                [{ label: 'Make it a keyword list', changes: [{ from: s.node.from, to: s.node.to, insert: `\n${lineIndent(text, s.from)}    - ${s.node.raw}` }] }]);
            continue;
        }
        for (const it of s.items) lintItem(it, text, add, opts);
    }

    // condition
    if (!det.conditionEntry) {
        const names = searches.map(s => s.name);
        const at = det.node.to;
        const ind = searches[0] ? lineIndent(text, searches[0].from) : '    ';
        add(det.entry.keyFrom, det.entry.keyTo, 'error', 'The detection has no condition', 'condition-required',
            names.length ? [{ label: `Add condition: ${names.length > 1 ? '1 of them' : names[0]}`, changes: [{ from: at, to: at, insert: `\n${ind}condition: ${names.length > 1 ? '1 of them' : names[0]}` }] }] : undefined);
        return;
    }
    if (det.conditionEntry.value && det.conditionEntry.value.type === 'seq') {
        add(det.conditionEntry.keyFrom, det.conditionEntry.keyTo, 'error', 'Rulezet needs one condition expression, not a list: join them with "or"', 'condition-list',
            det.condition.length > 1 ? [{ label: 'Join with or', changes: [{ from: det.conditionEntry.value.from, to: det.conditionEntry.value.to,
                insert: det.condition.map(c => (c.tokens.some(t => t.type === 'or') ? `(${c.text})` : c.text)).join(' or ') }] }] : undefined);
    }
    if (!det.condition.length || det.condition.every(c => !c.text.trim())) {
        add(det.conditionEntry.keyFrom, det.conditionEntry.to, 'error', 'The condition is empty', 'condition-empty');
        return;
    }
    if (det.timeframe) {
        const e = det.node.entries.find(x => x.key === 'timeframe');
        add(e.keyFrom, e.to, 'error', 'timeframe (Sigma v1 aggregations) is not accepted: use a correlation rule', 'timeframe',
            [{ label: 'Remove timeframe', changes: [{ ...lineRange(text, e.keyFrom, e.to), insert: '' }] }]);
    }
    const used = new Set();
    for (const c of det.condition) checkCondition(c, rule, add, used);
    specificLogsource(rule, add);

    // pySigma: a search identifier never used by the condition is an error (DanglingDetection, HIGH)
    for (const s of searches) {
        if (used.has(s.name)) continue;
        const c = det.condition[det.condition.length - 1];
        const isFilter = /^(filter|fp|exclude|not_)/i.test(s.name);
        const clause = isFilter ? ` and not ${s.name}` : ` or ${s.name}`;
        const fixes = [{ label: `Add "${clause.trim()}" to the condition`, changes: [{ from: c.to - (c.node.quoted === '"' || c.node.quoted === "'" ? 1 : 0), to: c.to - (c.node.quoted === '"' || c.node.quoted === "'" ? 1 : 0), insert: clause }] }];
        if (s.entry) fixes.push({ label: `Remove ${s.name}`, changes: [{ ...lineRange(text, s.entry.keyFrom, s.entry.to), insert: '' }] });
        add(s.from, s.to, 'error', `"${s.name}" is not used in the condition`, 'unused-search', fixes);
    }
}

// pySigma (SpecificInsteadOfGenericLogsource, HIGH): Sysmon / Security event ids that have a
// generic category of their own must use it
const SPECIFIC = {
    sysmon: { 1: 'process_creation', 2: 'file_change', 3: 'network_connection', 4: 'sysmon_status', 5: 'process_termination', 6: 'driver_load',
        7: 'image_load', 8: 'create_remote_thread', 9: 'raw_access_thread', 10: 'process_access', 11: 'file_event', 12: 'registry_event',
        13: 'registry_event', 14: 'registry_event', 15: 'create_stream_hash', 16: 'sysmon_status', 17: 'pipe_created', 18: 'pipe_created',
        19: 'wmi_event', 20: 'wmi_event', 21: 'wmi_event', 22: 'dns_query', 23: 'file_delete', 24: 'clipboard_change', 25: 'process_tampering',
        26: 'file_delete_detected', 27: 'file_block_executable', 28: 'file_block_shredding', 29: 'file_executable_detected', 255: 'sysmon_error' },
    security: { 4688: 'process_creation' },
};

function specificLogsource(rule, add) {
    const ls = rule.logsource;
    if (!ls || !ls.product || ls.product.value !== 'windows' || !ls.service || !SPECIFIC[ls.service.value]) return;
    const map = SPECIFIC[ls.service.value];
    for (const s of rule.detection.searches) {
        for (const it of s.items) {
            if (it.field !== 'EventID' || it.modifiers.length) continue;
            for (const v of it.values) {
                // only numbers count (EventID: 1), as in pySigma; a quoted '1' is a string
                if (v.quoted || !/^\d+$/.test(String(v.value)) || !map[+v.value]) continue;
                add(v.from, v.to, 'error', `EventID ${v.value} of ${ls.service.value} has its own log source: use "category: ${map[+v.value]}" (product windows) instead of service ${ls.service.value}`, 'specific-logsource');
            }
        }
    }
}

/** Recursive descent over the condition tokens: syntax errors, unknown identifiers. */
function checkCondition(c, rule, add, used) {
    const toks = c.tokens;
    let i = 0;
    const err = (t, message, code = 'condition-syntax', fixes) => { add(t ? t.from : c.to, t ? t.to : c.to, 'error', message, code, fixes); throw new Error('stop'); };
    const names = rule.detection.searches.map(s => s.name);
    const use = (t) => {
        const hits = matchSearches(rule, t);
        if (!hits.length) {
            if (t.type === 'ident') {
                const near = closest(t.value, names);
                add(t.from, t.to, 'error', `"${t.value}" is not a search identifier of this rule`, 'unknown-search',
                    near.map(n => ({ label: `Use ${n}`, changes: [{ from: t.from, to: t.to, insert: n }] })));
            } else if (t.type === 'pattern') {
                add(t.from, t.to, 'error', `No search identifier matches ${t.value}`, 'pattern-nothing');
            } else {
                add(t.from, t.to, 'error', 'The rule has no search identifier for "them"', 'them-nothing');
            }
        }
        for (const s of hits) used.add(s.name);
        return hits;
    };
    const primary = () => {
        const t = toks[i];
        if (!t) err(null, 'The condition ends too early');
        if (t.type === 'lparen') {
            i++;
            or();
            if (!toks[i] || toks[i].type !== 'rparen') err(toks[i] || null, 'Missing )');
            i++;
            return;
        }
        if (t.type === 'number' || t.type === 'quantifier') {
            if (!(t.value === '1' || /^(all|any)$/i.test(t.value))) err(t, 'Only "1 of" and "all of" are allowed (pySigma)', 'condition-quantifier',
                [{ label: 'Use 1 of', changes: [{ from: t.from, to: t.to, insert: '1' }] }]);
            const of = toks[i + 1];
            if (!of || of.type !== 'of') err(of || null, `"${t.value}" must be followed by "of"`);
            const target = toks[i + 2];
            if (!target || !['ident', 'pattern', 'them'].includes(target.type)) err(target || null, `"${t.value} of" needs an identifier pattern (selection_*) or "them"`);
            const hits = use(target);
            if (target.type === 'them' && /^all$/i.test(t.value) && rule.detection.searches.length > 1) {
                add(t.from, target.to, 'warning', '"all of them" also requires the filters to match: name each part instead', 'all-of-them');
            } else if (target.type === 'them' && hits.length === 1) {
                add(target.from, target.to, 'info', `Only one search identifier: write "${hits[0].name}" instead of "${t.value} of them"`, 'them-single',
                    [{ label: `Use ${hits[0].name}`, changes: [{ from: t.from, to: target.to, insert: hits[0].name }] }]);
            }
            i += 3;
            return;
        }
        if (t.type === 'ident' || t.type === 'pattern') {
            if (t.type === 'pattern') err(t, `A pattern needs a quantifier: "1 of ${t.value}" or "all of ${t.value}"`, 'condition-syntax',
                [{ label: `Use 1 of ${t.value}`, changes: [{ from: t.from, to: t.from, insert: '1 of ' }] }]);
            use(t);
            i++;
            return;
        }
        if (t.type === 'them') err(t, '"them" needs a quantifier: "1 of them" or "all of them"');
        if (t.type === 'pipe') err(t, 'Aggregations after | are not supported by pySigma: use a correlation rule', 'condition-aggregation');
        err(t, `Unexpected "${t.value}"`);
    };
    const not = () => {
        if (toks[i] && toks[i].type === 'not') { i++; not(); return; }
        primary();
    };
    const and = () => { not(); while (toks[i] && toks[i].type === 'and') { i++; not(); } };
    const or = () => { and(); while (toks[i] && toks[i].type === 'or') { i++; and(); } };
    try {
        or();
        if (i < toks.length) {
            const t = toks[i];
            if (t.type === 'pipe') err(t, 'Aggregations after | are not supported by pySigma: use a correlation rule', 'condition-aggregation');
            err(t, t.type === 'rparen' ? 'Unexpected )' : `Expected "and" or "or" before "${t.value}"`);
        }
    } catch (e) {
        if (e.message !== 'stop') throw e;
        // keep marking the identifiers as used so an unused-search error does not pile up
        for (const t of toks) if (t.type === 'ident' || t.type === 'pattern' || t.type === 'them') for (const s of matchSearches(rule, t)) used.add(s.name);
    }
}

function lintItem(it, text, add, opts) {
    const mods = it.modifiers.map(m => m.name);
    const has = (n) => mods.includes(n);
    for (const m of it.modifiers) {
        if (!MODIFIERS[m.name]) {
            const near = closest(m.name, Object.keys(MODIFIERS));
            add(m.from, m.to, 'error', `Unknown modifier "${m.name}"`, 'unknown-modifier',
                near.map(n => ({ label: `Use ${n}`, changes: [{ from: m.from, to: m.to, insert: n }] })));
        }
    }
    const counts = {};
    for (const m of it.modifiers) {
        counts[m.name] = (counts[m.name] || 0) + 1;
        if (counts[m.name] === 2 && m.name !== 'base64') {
            add(m.from - 1, m.to, 'warning', `The modifier ${m.name} is applied twice`, 'modifier-twice', [{ label: 'Remove it', changes: [{ from: m.from - 1, to: m.to, insert: '' }] }]);
        }
    }
    if (it.field) {                  // '|all': a keyword list (no field) is fine
        const last = it.modifiers[it.modifiers.length - 1];
        const at = last ? last.to : it.fieldTo;
        if (has('all') && !has('contains')) {
            const a = it.modifiers.find(m => m.name === 'all');
            add(a.from, a.to, 'error', '"all" needs "contains" (pySigma refuses all without contains)', 'all-without-contains',
                [{ label: 'Add |contains before all', changes: [{ from: a.from - 1, to: a.from - 1, insert: '|contains' }] }]);
        }
        if (has('base64offset') && !has('contains')) {
            add(it.fieldFrom, at, 'error', '"base64offset" needs "contains"', 'base64offset-without-contains',
                [{ label: 'Add |contains', changes: [{ from: at, to: at, insert: '|contains' }] }]);
        }
        if (has('windash') && has('all')) add(it.fieldFrom, at, 'error', '"windash" cannot be combined with "all"', 'windash-all');
        const reAt = mods.indexOf('re');
        for (const m of it.modifiers) {
            if (RE_FLAGS.includes(m.name) && (reAt === -1 || mods.indexOf(m.name) < reAt)) {
                add(m.from, m.to, 'error', `"${m.name}" is a regular expression flag: it goes after |re`, 're-flag');
            }
        }
    }

    const vals = it.values;
    if (it.node && it.node.type === 'map') add(it.entry ? it.entry.keyFrom : it.node.from, it.node.from, 'error', 'A field value cannot be a mapping', 'value-map');
    for (const v of vals) {
        const value = v.value == null ? null : String(v.value);
        if (value !== null && /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) add(v.from, v.to, 'error', 'The value contains a control character', 'control-character');
        if (has('exists') && !/^(true|false|yes|no)$/i.test(value || '')) add(v.from, v.to, 'error', 'exists takes true or false', 'exists-value');
        if (NUMERIC.some(n => has(n)) && !/^-?\d+(\.\d+)?$/.test(value || '')) add(v.from, v.to, 'error', `${mods.find(n => NUMERIC.includes(n))} compares numbers: the value must be a number`, 'numeric-value');
        if (has('cidr') && value !== null && !/^[0-9a-f.:]+\/\d{1,3}$/i.test(value)) add(v.from, v.to, 'error', 'cidr takes a network such as 10.0.0.0/8', 'cidr-value');
        if (has('re') && value !== null) {
            try { new RegExp(value.replace(/\(\?[imsx]+\)/g, '').replace(/\(\?<(?![=!])/g, '(?<'), 'u'); } catch (e) {
                try { new RegExp(value.replace(/\(\?[imsx]+\)/g, '')); } catch (e2) { add(v.from, v.to, 'warning', `This regular expression may be invalid: ${e2.message}`, 'regex'); }
            }
        }
        if (value && value.includes('**')) add(v.from, v.to, 'info', 'Double wildcard ** : one * is enough', 'double-wildcard');
        // wildcards where a modifier says it better (pySigma LOW)
        if (opts.suggest && it.field && !mods.length && value && v.quoted !== '|' && !/\\\*/.test(value)) {
            const inner = value.slice(1, -1);
            const open = (q) => (v.quoted === '"' || v.quoted === "'" ? 1 : 0);
            if (value.length > 2 && value.startsWith('*') && value.endsWith('*') && !inner.includes('*')) {
                add(v.from, v.to, 'info', 'Use |contains instead of *…*', 'wildcard-contains', [{ label: 'Use |contains', changes: [
                    { from: it.fieldTo, to: it.fieldTo, insert: '|contains' },
                    { from: v.from + open(), to: v.from + open() + 1, insert: '' },
                    { from: v.to - open() - 1, to: v.to - open(), insert: '' }] }]);
            } else if (value.length > 1 && value.endsWith('*') && !value.slice(0, -1).includes('*') && !value.slice(0, -1).includes('?')) {
                add(v.from, v.to, 'info', 'Use |startswith instead of a trailing *', 'wildcard-startswith', [{ label: 'Use |startswith', changes: [
                    { from: it.fieldTo, to: it.fieldTo, insert: '|startswith' }, { from: v.to - open() - 1, to: v.to - open(), insert: '' }] }]);
            } else if (value.length > 1 && value.startsWith('*') && !value.slice(1).includes('*') && !value.slice(1).includes('?')) {
                add(v.from, v.to, 'info', 'Use |endswith instead of a leading *', 'wildcard-endswith', [{ label: 'Use |endswith', changes: [
                    { from: it.fieldTo, to: it.fieldTo, insert: '|endswith' }, { from: v.from + open(), to: v.from + open() + 1, insert: '' }] }]);
            }
        }
    }
    if (it.field && it.node && it.node.type === 'seq' && !it.node.items.length) add(it.entry.keyFrom, it.entry.to, 'warning', 'Empty list of values: this field matches nothing', 'empty-values');
}

/** For other modules: a YAML-safe value. */
export { yamlValue };
