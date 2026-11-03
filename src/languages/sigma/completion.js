/**
 * Context-aware completion of the Sigma pack. The context is read from the text around the
 * cursor (the line, its indentation and the keys above it), so it works while the rule is
 * still incomplete.
 *
 *   top-level key               title, logsource (with its block), detection…
 *   logsource key / value       category, product, service + known values
 *   status, level, related type their values
 *   a field in a search         field names of the rule's category / service
 *   after Field|                value modifiers
 *   in the condition            search identifiers, patterns (selection_*), and / or / not / 1 of / all of / them
 *   tags                        attack.<tactic>, attack.t…, tlp.*, cve., detection.*
 */
import { TOP_KEYS, STATUS, LEVEL, RELATED_TYPES, LOGSOURCE_KEYS, PRODUCTS, CATEGORIES, SERVICES, FIELDS, SERVICE_FIELDS,
    MODIFIERS, CONDITION_KEYWORDS, TACTICS, TAG_NAMESPACES, TLP, DETECTION_TAGS } from './data.js';
import { ruleAt } from './parser.js';

const IND = '    ';

/** Top-level snippets: a whole rule, and the blocks that need several lines. */
export const TOP_SNIPPETS = [
    {
        label: 'sigma rule', type: 'snippet', detail: 'a complete detection rule',
        snippet: 'title: ${Title of what is detected}\nid: {{uuid}}\nstatus: experimental\ndescription: ${What the rule detects and why}\nreferences:\n    - ${https://example.org/report}\nauthor: ${author}\ndate: {{date}}\ntags:\n    - attack.${execution}\nlogsource:\n    category: ${process_creation}\n    product: ${windows}\ndetection:\n    selection:\n        ${Image}|endswith: \'${\\evil.exe}\'\n    condition: selection\nfalsepositives:\n    - ${Unknown}\nlevel: ${medium}\n',
    },
];

const BLOCKS = {
    logsource: `logsource:\n${IND}category: \${process_creation}\n${IND}product: \${windows}`,
    detection: `detection:\n${IND}selection:\n${IND}${IND}\${Image}|endswith: '\${\\example.exe}'\n${IND}condition: selection`,
    tags: `tags:\n${IND}- attack.\${execution}`,
    references: `references:\n${IND}- \${https://}`,
    falsepositives: `falsepositives:\n${IND}- \${Unknown}`,
    related: `related:\n${IND}- id: \${uuid of the related rule}\n${IND}  type: \${derived}`,
    fields: `fields:\n${IND}- \${CommandLine}`,
    id: 'id: {{uuid}}',
    date: 'date: {{date}}',
    modified: 'modified: {{date}}',
};

function lineOf(text, pos) {
    const start = text.lastIndexOf('\n', pos - 1) + 1;
    let end = text.indexOf('\n', pos);
    if (end === -1) end = text.length;
    return { start, end, before: text.slice(start, pos), line: text.slice(start, end) };
}

/** The keys enclosing the line at `start` (walking up by indentation): ['detection', 'selection']. */
function path(text, start, indent) {
    const keys = [];
    let want = indent;
    let pos = start;
    while (pos > 0 && want > 0) {
        const end = pos - 1;
        const s = text.lastIndexOf('\n', end - 1) + 1;
        const l = text.slice(s, end);
        pos = s;
        if (!l.trim() || /^\s*#/.test(l)) continue;
        if (/^(---|\.\.\.)\s*$/.test(l)) break;
        const ind = l.match(/^ */)[0].length;
        const dash = /^-\s+/.exec(l.slice(ind));
        const col = dash ? ind + dash[0].length : ind;
        if (col >= want) continue;
        const m = /^([^\s:#][^:#]*?)\s*:(\s|$)/.exec(l.slice(col));
        if (m) keys.unshift(m[1]);
        want = ind;
    }
    return keys;
}

const opt = (label, type, detail, info, extra = {}) => ({ label, type, detail, info, ...extra });

export function complete(ctx) {
    const { text, pos, explicit } = ctx;
    const model = ctx.parsed;
    const L = lineOf(text, pos);
    const before = L.before;
    const indent = before.match(/^ */)[0].length;
    const rule = model && model.rules ? ruleAt(model, pos) : null;
    const word = before.match(/[\w.*\-]*$/)[0];
    const from = pos - word.length;

    // ── after "key: " ───────────────────────────────────────────────────────
    const kv = /^(\s*(?:-\s+)?)([^\s:#][^:#]*?)\s*:\s+(.*)$/.exec(before);
    const keys = path(text, L.start, indent);
    if (kv) {
        const key = kv[2].split('|')[0];
        const parent = keys[keys.length - 1];
        const valueWord = kv[3].match(/[\w.*\-]*$/)[0];
        const vFrom = pos - valueWord.length;
        if (key === 'condition' || (parent === 'condition')) return conditionCompletion(rule, kv[3], pos, explicit);
        if (indent === 0 && key === 'status') return { from: vFrom, options: Object.entries(STATUS).map(([k, d]) => opt(k, 'constant', 'status', d)) };
        if (indent === 0 && key === 'level') return { from: vFrom, options: Object.entries(LEVEL).map(([k, d]) => opt(k, 'constant', 'level', d)) };
        if (key === 'type' && keys.includes('related')) return { from: vFrom, options: Object.entries(RELATED_TYPES).map(([k, d]) => opt(k, 'constant', 'related', d)) };
        if (parent === 'logsource' || keys[0] === 'logsource') {
            const list = key === 'product' ? PRODUCTS : key === 'category' ? CATEGORIES : key === 'service' ? SERVICES : null;
            if (list) return { from: vFrom, options: list.map(v => opt(v, 'constant', key)) };
        }
        if (indent === 0 && (key === 'date' || key === 'modified') && !kv[3].trim()) {
            return { from: vFrom, options: [opt(new Date().toISOString().slice(0, 10), 'constant', 'today')] };
        }
        if (indent === 0 && key === 'id' && !kv[3].trim()) return { from: vFrom, options: [opt('new UUID', 'snippet', '', 'A random UUID v4', { apply: '{{uuid}}' })] };
        return null;
    }
    // a condition continued on the next lines
    if (keys[keys.length - 1] === 'condition') return conditionCompletion(rule, before, pos, explicit);

    // ── Field|modifier ──────────────────────────────────────────────────────
    const mod = /([^\s:|#-][^\s:#]*)\|([\w|]*)$/.exec(before);
    if (mod && keys[0] === 'detection') {
        const typed = mod[2].split('|');
        const partial = typed[typed.length - 1];
        const used = new Set(typed.slice(0, -1));
        const options = Object.entries(MODIFIERS).filter(([k]) => !used.has(k)).map(([k, d]) => opt(k, 'modifier', 'modifier', d, { boost: ['contains', 'endswith', 'startswith', 'all', 're'].includes(k) ? 2 : 0 }));
        return { from: pos - partial.length, options };
    }

    // ── list items: tags, references… ─────────────────────────────────────
    const item = /^(\s*)-\s+([\w.*\-]*)$/.exec(before);
    const listKey = keys[keys.length - 1];
    if (item && listKey === 'tags') return tagCompletion(item[2], pos);

    // ── a key at the start of the line ────────────────────────────────────
    if (!/^\s*(-\s+)?[\w.*\-|]*$/.test(before)) return null;
    if (!word && !explicit) return null;
    if (indent === 0) {
        const present = new Set(rule && rule.root ? rule.root.entries.map(e => e.key) : []);
        const options = TOP_KEYS.filter(k => !present.has(k.key)).map(k => (BLOCKS[k.key]
            ? opt(k.key, 'keyword', k.required ? 'required' : 'key', k.doc, { snippet: BLOCKS[k.key] })
            : opt(k.key, 'keyword', k.required ? 'required' : 'key', k.doc, { apply: `${k.key}: ` })));
        if (!rule || !rule.root) options.push(...TOP_SNIPPETS);
        return { from, options };
    }
    if (keys[0] === 'logsource' && keys.length === 1) {
        return { from, options: Object.entries(LOGSOURCE_KEYS).map(([k, d]) => opt(k, 'property', 'logsource', d, { apply: `${k}: ` })) };
    }
    if (keys[0] === 'detection') {
        if (keys.length === 1) {
            const names = rule && rule.detection ? rule.detection.searches.map(s => s.name) : [];
            const has = (n) => names.includes(n);
            return {
                from,
                options: [
                    ...(!has('selection') ? [opt('selection', 'property', 'search identifier', 'What to look for: field / value pairs (all must match).', { snippet: 'selection:\n' + ' '.repeat(indent + 4) + '${Image}|endswith: \'${\\example.exe}\'' })] : []),
                    opt('filter_main_', 'property', 'search identifier', 'Benign activity to exclude: "selection and not 1 of filter_main_*".', { snippet: 'filter_main_${name}:\n' + ' '.repeat(indent + 4) + '${ParentImage}|endswith: \'${\\legit.exe}\'' }),
                    opt('keywords', 'property', 'search identifier', 'Free-text keywords searched in the whole event (a list).', { snippet: 'keywords:\n' + ' '.repeat(indent + 4) + '- \'${keyword}\'' }),
                    ...(!has('condition') ? [opt('condition', 'keyword', 'required', 'How the search identifiers combine: selection and not filter, 1 of selection_*…', { apply: 'condition: ' })] : []),
                ],
            };
        }
        // a field of a search identifier
        const fields = fieldNames(rule);
        return { from, options: fields.map(f => opt(f, 'property', 'field', null, { apply: f })) };
    }
    return null;
}

/** Field names for the rule's logsource (category first, then service). */
function fieldNames(rule) {
    const ls = rule && rule.logsource;
    const cat = ls && ls.category && ls.category.value;
    const svc = ls && ls.service && ls.service.value;
    const out = [...(FIELDS[cat] || []), ...(SERVICE_FIELDS[svc] || [])];
    if (!out.length) out.push(...FIELDS.process_creation, 'EventID');
    // fields already used in this rule come first
    const used = rule && rule.detection ? rule.detection.searches.flatMap(s => s.items.map(i => i.field).filter(Boolean)) : [];
    return [...new Set([...used, ...out])];
}

function conditionCompletion(rule, typed, pos, explicit) {
    const word = typed.match(/[\w.*\-]*$/)[0];
    const searches = rule && rule.detection ? rule.detection.searches.map(s => s.name) : [];
    const prefixes = [...new Set(searches.map(n => n.match(/^(.*?_)[^_]*$/)).filter(Boolean).map(m => m[1] + '*'))];
    const prev = typed.slice(0, typed.length - word.length).trim().split(/\s+/).pop() || '';
    const options = [];
    if (/^of$/i.test(prev)) {
        options.push(...prefixes.map(p => opt(p, 'variable', 'pattern', 'Every search identifier starting with ' + p.slice(0, -1))));
        options.push(opt('them', 'keyword', '', CONDITION_KEYWORDS.them));
        options.push(...searches.map(n => opt(n, 'variable', 'search identifier')));
        return { from: pos - word.length, options };
    }
    if (!word && !explicit && !/\s$/.test(typed)) return null;
    options.push(...searches.map(n => opt(n, 'variable', 'search identifier', null, { boost: 3 })));
    options.push(opt('and', 'keyword', '', CONDITION_KEYWORDS.and), opt('or', 'keyword', '', CONDITION_KEYWORDS.or), opt('not', 'keyword', '', CONDITION_KEYWORDS.not));
    options.push(opt('1 of', 'keyword', '', CONDITION_KEYWORDS.of, { apply: '1 of ' }), opt('all of', 'keyword', '', CONDITION_KEYWORDS.of, { apply: 'all of ' }));
    if (prefixes.length) options.push(...prefixes.map(p => opt(`1 of ${p}`, 'variable', 'any of them', null, { apply: `1 of ${p}` })));
    if (searches.some(n => /^filter/.test(n))) {
        const f = searches.filter(n => /^filter/.test(n));
        options.push(opt(f.length > 1 ? `not 1 of filter_*` : `not ${f[0]}`, 'snippet', 'exclude the filters', null, { apply: f.length > 1 ? 'not 1 of filter_*' : `not ${f[0]}` }));
    }
    return { from: pos - word.length, options };
}

function tagCompletion(typed, pos) {
    const options = [];
    const ns = typed.includes('.') ? typed.split('.')[0] : null;
    if (!ns) {
        for (const [k, d] of Object.entries(TAG_NAMESPACES)) options.push(opt(`${k}.`, 'module', 'namespace', d, { apply: `${k}.` }));
        for (const t of Object.keys(TACTICS)) options.push(opt(`attack.${t}`, 'constant', TACTICS[t]));
    } else if (ns === 'attack') {
        for (const t of Object.keys(TACTICS)) options.push(opt(`attack.${t}`, 'constant', `tactic ${TACTICS[t]}`));
        options.push(opt('attack.t', 'snippet', 'technique', 'A technique: attack.t1059 or a sub-technique attack.t1059.001', { apply: 'attack.t' }));
    } else if (ns === 'tlp') {
        for (const t of TLP) options.push(opt(`tlp.${t}`, 'constant', 'TLP'));
    } else if (ns === 'detection') {
        for (const t of DETECTION_TAGS) options.push(opt(`detection.${t}`, 'constant', 'kind of rule'));
    } else if (ns === 'cve') {
        options.push(opt('cve.', 'snippet', 'vulnerability', 'cve.YYYY-NNNN', { apply: 'cve.' }));
    }
    return { from: pos - typed.length, options };
}
