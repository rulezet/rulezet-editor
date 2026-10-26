/**
 * Fields panel logic (pure functions, no DOM): the host's fields for a rule (title, CVE, tags...)
 * against the rule's own key / value metadata (YARA `meta:`), read through the pack's `meta`.
 *
 * A field definition (from the host, see docs/fields.md):
 *   { id, label, type: 'text' | 'textarea' | 'select' | 'list', help?, required?, options?,
 *     suggest?: bool, free?: bool (list: accept typed values), pattern?: 'regex',
 *     report?: bool (written into the rule by default),
 *     meta?: { key, aliases?: [], extract?: 'cve' | 'url', extractFrom?: [], join?: ', ' } }
 *
 * More kinds (all optional, all from the host's definition):
 *   type 'version'            a major.minor stepper: { version: { min: '1.0', minorMax: 9 } }
 *   select + searchable       type to filter the options
 *   list + formats            a format menu that prefills a prefix: [{ label, prefix }]
 *   list + pattern            live "valid / invalid" feedback before adding
 *   list + browse             browse the host's folders (tag namespaces, ATT&CK tactics)
 *   list + chipColors         chip colour by prefix: [{ prefix, color }]; or item.color
 *   list + max                at most N items
 *
 * Values: text / textarea / select / version -> string; list -> [{ value, label, detail?, color? }].
 */
const EXTRACT = {
    cve: /\bCVE-\d{4}-\d{4,}\b/gi,
    url: /\bhttps?:\/\/[^\s"'<>]+/gi,
    attack: /\bT\d{4}(?:\.\d{3})?\b/g,
    // every vulnerability id format of Rulezet's manual form
    vuln: /\b(?:CVE-\d{4}-\d{4,7}|GCVE-\d+-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d{2,5}|GSD-\d{4}-\d{4,5}|wid-sec-w-\d{4}-\d{4}|cisco-sa-\d{8}-[a-z0-9]+|RHSA-\d{4}:\d{4}|msrc_CVE-\d{4}-\d{4,}|CERTFR-\d{4}-[A-Z]{3}-\d{3})\b/gi,
};

export function emptyValue(def) {
    return def.type === 'list' ? [] : '';
}

export function isEmpty(def, value) {
    return def.type === 'list' ? !value || !value.length : !String(value ?? '').trim();
}

const itemKey = (item) => String(item.label ?? item.value ?? '').trim().toLowerCase();

/** Same content, ignoring order (lists), case of list items and surrounding spaces. */
export function sameValue(def, a, b) {
    if (def.type === 'list') {
        const x = new Set((a || []).map(itemKey));
        const y = new Set((b || []).map(itemKey));
        return x.size === y.size && [...x].every(k => y.has(k));
    }
    return String(a ?? '').trim() === String(b ?? '').trim();
}

/** The field's value as the rule holds it, or null when the rule says nothing about it. */
export function readField(def, entries) {
    if (!def.meta || !entries) return null;
    const keys = [def.meta.key, ...(def.meta.aliases || [])].map(k => k.toLowerCase());
    const own = entries.filter(e => keys.includes(e.key.toLowerCase())).map(e => e.value);
    const extra = def.meta.extract
        ? entries.filter(e => (def.meta.extractFrom || []).map(k => k.toLowerCase()).includes(e.key.toLowerCase())).map(e => e.value)
        : [];
    if (!own.length && !extra.length) return null;
    if (def.type !== 'list') return own.length ? own[0] : null;
    let items;
    if (def.meta.extract && EXTRACT[def.meta.extract]) {
        const re = EXTRACT[def.meta.extract];
        items = [...own, ...extra].flatMap(v => String(v).match(re) || []);
        if (def.meta.extract === 'cve' || def.meta.extract === 'vuln' || def.upper) items = items.map(s => s.toUpperCase());
    } else {
        items = own.flatMap(v => String(v).split(def.meta.split ? new RegExp(def.meta.split) : /\s*[,;]\s*/));
    }
    items = [...new Set(items.map(s => s.trim()).filter(Boolean))];
    return items.length ? items.map(s => ({ value: s, label: s })) : null;
}

/** What goes after `key =` in the rule. */
export function toMetaValue(def, value) {
    if (def.type === 'list') return (value || []).map(i => i.label ?? i.value).join(def.meta && def.meta.join ? def.meta.join : ', ');
    return String(value ?? '').trim();
}

/** The status of one field of one rule, for the panel.
 *  synced     written in the rule, same value
 *  kept       differs from the rule on purpose (the rule is left untouched)
 *  conflict   the rule says something else and the user has not decided
 *  host       only in the host (not written in the rule, the rule says nothing)
 *  rule       the rule has a value the field does not (empty field)
 *  empty      nothing anywhere */
export function fieldStatus(def, state, ruleValue) {
    const value = state.values[def.id];
    const has = !isEmpty(def, value);
    if (ruleValue === null || ruleValue === undefined) return has ? 'host' : 'empty';
    if (!has) return 'rule';
    if (sameValue(def, value, ruleValue)) return state.report[def.id] ? 'synced' : 'same';
    return state.keep[def.id] ? 'kept' : 'conflict';
}

/** A fresh state for a rule: every field filled from the rule when it has the value. */
export function initialState(defs, entries, reportDefault, ruleName = null) {
    const state = { values: {}, report: {}, keep: {} };
    for (const def of defs) {
        // a title-like field starts as the rule's own name (what the host uses when it is empty)
        const fromRule = readField(def, entries) ?? (def.fromRuleName && ruleName ? ruleName : null);
        state.values[def.id] = fromRule ?? emptyValue(def);
        state.report[def.id] = !!def.meta && (def.report ?? reportDefault);
        state.keep[def.id] = false;
    }
    return state;
}

/** Checks a typed list item against the field's pattern (e.g. CVE ids). */
export function validItem(def, text) {
    if (!String(text).trim()) return false;
    if (!def.pattern) return true;
    try { return new RegExp(def.pattern, 'i').test(String(text).trim()); } catch { return true; }
}

/** major.minor stepper, as Rulezet's version picker: minor 0..minorMax with carry, never below min. */
export function stepVersion(value, step, { min = '1.0', minorMax = 9 } = {}) {
    const parse = (v) => {
        const m = String(v || '').match(/^(\d+)(?:\.(\d+))?/);
        return m ? [parseInt(m[1], 10) || 0, parseInt(m[2] || '0', 10) || 0] : null;
    };
    const [minMajor, minMinor] = parse(min) || [1, 0];
    let [major, minor] = parse(value) || [minMajor, minMinor];
    minor += step;
    if (minor > minorMax) { minor = 0; major += 1; }
    if (minor < 0) { minor = minorMax; major -= 1; }
    if (major < minMajor || (major === minMajor && minor < minMinor)) { major = minMajor; minor = minMinor; }
    return `${major}.${minor}`;
}

/** Is this version the smallest one allowed (the minus button is then disabled)? */
export function isMinVersion(value, { min = '1.0' } = {}) {
    return stepVersion(value, -1, { min }) === stepVersion(value, 0, { min }) && stepVersion(value, 0, { min }) === String(min);
}

/** Colour of a chip: the item's own colour, else the first chipColors prefix that matches. */
export function chipColor(def, item) {
    if (item && item.color) return item.color;
    const label = String((item && (item.label ?? item.value)) || '').toLowerCase();
    const hit = (def.chipColors || []).find(c => label.startsWith(String(c.prefix).toLowerCase()));
    return hit ? hit.color : null;
}

/** Readable text colour on a background (black or white). */
export function textOn(hex) {
    const m = String(hex || '').replace('#', '').match(/^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i);
    if (!m) return null;
    const [r, g, b] = m.slice(1).map(x => parseInt(x, 16));
    return (r * 299 + g * 587 + b * 114) / 1000 > 150 ? '#1f2328' : '#ffffff';
}
