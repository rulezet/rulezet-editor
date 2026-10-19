/**
 * Authoring actions on the rule under the cursor (or the only rule): add a date, an id, a tag,
 * a string, a file type check... Engine-neutral: each action returns changes, the core applies
 * them and fills {{uuid}} / {{date}}.
 *
 *   { id, label, input?: { label, placeholder, value? }, run(ctx, value) -> changes[] | { error } }
 */
import { ruleAt } from './analysis.js';

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const quote = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function targetRule(ctx) {
    const rules = ctx.parsed.rules.filter(r => r.openBrace != null);
    return ruleAt(ctx.parsed, ctx.pos) || (rules.length === 1 ? rules[0] : null);
}

function lineEnd(text, pos) { const i = text.indexOf('\n', pos); return i === -1 ? text.length : i; }
function indentOf(text, pos) { const s = text.lastIndexOf('\n', pos - 1) + 1; return text.slice(s, pos).match(/^[ \t]*/)[0]; }

/** Indentation used for section headers and their entries in this rule. */
function indents(text, rule) {
    const sec = Object.values(rule.sections)[0];
    const section = sec ? indentOf(text, sec.from) : '    ';
    const entry = rule.meta[0] ? indentOf(text, rule.meta[0].from) : rule.strings[0] ? indentOf(text, rule.strings[0].from) : section + '    ';
    return { section, entry };
}

/** Sets a meta key: replaces its value, or adds the line (and the meta: section if needed). */
export function setMeta(text, rule, key, rawValue, { replace = true } = {}) {
    const existing = rule.meta.find(m => m.key === key);
    if (existing) return replace ? [{ from: existing.valueFrom, to: existing.valueTo, insert: rawValue }] : [];
    const { section, entry } = indents(text, rule);
    if (rule.meta.length) {
        const at = lineEnd(text, rule.meta[rule.meta.length - 1].to);
        return [{ from: at, to: at, insert: `\n${entry}${key} = ${rawValue}` }];
    }
    if (rule.sections.meta) {
        const at = rule.sections.meta.to;
        return [{ from: at, to: at, insert: `\n${entry}${key} = ${rawValue}` }];
    }
    const at = rule.openBrace + 1;
    return [{ from: at, to: at, insert: `\n${section}meta:\n${entry}${key} = ${rawValue}` }];
}

/** "cond" -> "cond and extra" (or "extra and cond"), with parentheses when "or" is involved. */
function andCondition(rule, extra, { prefix = false } = {}) {
    const c = rule.condition;
    if (!c || !c.tokens.length) return null;
    const needsParens = c.tokens.some(t => t.value === 'or');
    const body = needsParens ? `(${c.text})` : c.text;
    return [{ from: c.from, to: c.to, insert: prefix ? `${extra} and ${body}` : `${body} and ${extra}` }];
}

const noRule = { error: 'Put the cursor inside a rule' };

export const ACTIONS = [
    {
        id: 'yara.date', label: 'Add date (or update "modified")',
        run(ctx) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            return rule.meta.some(m => m.key === 'date')
                ? setMeta(ctx.text, rule, 'modified', '"{{date}}"')
                : setMeta(ctx.text, rule, 'date', '"{{date}}"');
        },
    },
    {
        id: 'yara.id', label: 'Add an id (UUID)',
        run(ctx) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            if (rule.meta.some(m => m.key === 'id' || m.key === 'uuid')) return { error: 'This rule already has an id' };
            return setMeta(ctx.text, rule, 'id', '"{{uuid}}"');
        },
    },
    {
        id: 'yara.newId', label: 'Replace the id with a new UUID',
        run(ctx) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            const key = rule.meta.some(m => m.key === 'uuid') && !rule.meta.some(m => m.key === 'id') ? 'uuid' : 'id';
            return setMeta(ctx.text, rule, key, '"{{uuid}}"');
        },
    },
    {
        id: 'yara.author', label: 'Set author',
        input: { label: 'Author', placeholder: 'Name or handle', value: (ctx) => ctx.author || '' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            if (!value || !value.trim()) return { error: 'Empty author' };
            return setMeta(ctx.text, rule, 'author', quote(value.trim()));
        },
    },
    {
        id: 'yara.description', label: 'Set description',
        input: { label: 'Description', placeholder: 'What the rule detects' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            if (!value || !value.trim()) return { error: 'Empty description' };
            return setMeta(ctx.text, rule, 'description', quote(value.trim()));
        },
    },
    {
        id: 'yara.reference', label: 'Add a reference (URL)',
        input: { label: 'Reference', placeholder: 'https://...' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            if (!value || !value.trim()) return { error: 'Empty reference' };
            // several references: reference, reference2, ...
            let key = 'reference';
            for (let n = 2; rule.meta.some(m => m.key === key); n++) key = `reference${n}`;
            return setMeta(ctx.text, rule, key, quote(value.trim()));
        },
    },
    {
        id: 'yara.mitre', label: 'Add a MITRE ATT&CK technique',
        input: { label: 'Technique', placeholder: 'T1059.001' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            const v = (value || '').trim().toUpperCase();
            if (!/^T\d{4}(\.\d{3})?$/.test(v)) return { error: 'Expected a technique id like T1059 or T1059.001' };
            const existing = rule.meta.find(m => m.key === 'mitre_attack');
            if (existing && existing.valueType === 'string') {
                const list = existing.value.split(/[,\s]+/).filter(Boolean);
                if (list.includes(v)) return { error: `${v} is already there` };
                return [{ from: existing.valueFrom, to: existing.valueTo, insert: quote([...list, v].join(', ')) }];
            }
            return setMeta(ctx.text, rule, 'mitre_attack', quote(v));
        },
    },
    {
        id: 'yara.meta', label: 'Add a meta key',
        input: { label: 'key = value', placeholder: 'tlp = "clear"' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            const m = (value || '').match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*(.*?))?\s*$/);
            if (!m) return { error: 'Expected key = value' };
            let raw = m[2] == null || m[2] === '' ? '""' : m[2];
            if (!/^(".*"|-?\d+|true|false)$/.test(raw)) raw = quote(raw);
            return setMeta(ctx.text, rule, m[1], raw);
        },
    },
    {
        id: 'yara.tag', label: 'Add a tag',
        input: { label: 'Tag', placeholder: 'APT, ransomware, ...' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            const tags = (value || '').split(/[\s,]+/).filter(Boolean);
            if (!tags.length) return { error: 'Empty tag' };
            const bad = tags.find(t => !IDENT.test(t));
            if (bad) return { error: `"${bad}" is not a valid tag: letters, digits and _ only, not starting with a digit` };
            const fresh = tags.filter(t => !rule.tags.some(x => x.name === t));
            if (!fresh.length) return { error: 'Tag already there' };
            if (rule.tags.length) {
                const at = rule.tags[rule.tags.length - 1].to;
                return [{ from: at, to: at, insert: ' ' + fresh.join(' ') }];
            }
            return [{ from: rule.nameTo, to: rule.nameTo, insert: ' : ' + fresh.join(' ') }];
        },
    },
    {
        id: 'yara.string', label: 'Add a text string',
        input: { label: 'Text to find', placeholder: 'malicious.example' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            if (!value) return { error: 'Empty string' };
            let n = 1;
            while (rule.strings.some(s => s.name === `s${n}`)) n++;
            const id = `$s${n}`;
            const { section, entry } = indents(ctx.text, rule);
            const line = `${id} = ${quote(value)}`;
            const changes = [];
            if (rule.strings.length) {
                const at = lineEnd(ctx.text, rule.strings[rule.strings.length - 1].to);
                changes.push({ from: at, to: at, insert: `\n${entry}${line}` });
            } else if (rule.sections.strings) {
                const at = rule.sections.strings.to;
                changes.push({ from: at, to: at, insert: `\n${entry}${line}` });
            } else if (rule.sections.condition) {
                const at = rule.sections.condition.from;
                changes.push({ from: at, to: at, insert: `strings:\n${entry}${line}\n${section}` });
            } else {
                return { error: 'The rule has no condition: section' };
            }
            // use it, so the rule stays valid ("or": lowest precedence, no parentheses needed)
            const c = rule.condition;
            if (c && c.tokens.length && !/\bof them\b/.test(c.text)) changes.push({ from: c.to, to: c.to, insert: ` or ${id}` });
            return changes;
        },
    },
    {
        id: 'yara.pe', label: 'Only match PE files (MZ header)',
        run(ctx) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            if (/uint16\(0\)\s*==\s*0x5a4d/i.test(rule.condition ? rule.condition.text : '')) return { error: 'The condition already checks the MZ header' };
            return andCondition(rule, 'uint16(0) == 0x5A4D', { prefix: true }) || { error: 'The rule has no condition' };
        },
    },
    {
        id: 'yara.elf', label: 'Only match ELF files',
        run(ctx) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            return andCondition(rule, 'uint32(0) == 0x464C457F', { prefix: true }) || { error: 'The rule has no condition' };
        },
    },
    {
        id: 'yara.filesize', label: 'Limit the file size',
        input: { label: 'Maximum size', placeholder: '5MB', value: () => '5MB' },
        run(ctx, value) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            const v = (value || '').trim().toUpperCase().replace(/\s+/g, '');
            if (!/^\d+(KB|MB)?$/.test(v)) return { error: 'Expected a size like 500KB or 5MB' };
            return andCondition(rule, `filesize < ${v}`) || { error: 'The rule has no condition' };
        },
    },
    {
        id: 'yara.private', label: 'Toggle private',
        run(ctx) {
            const rule = targetRule(ctx);
            if (!rule) return noRule;
            const text = ctx.text;
            const m = /\bprivate\s+/.exec(text.slice(rule.from, rule.nameFrom));
            if (m) return [{ from: rule.from + m.index, to: rule.from + m.index + m[0].length, insert: '' }];
            return [{ from: rule.from, to: rule.from, insert: 'private ' }];
        },
    },
];

/** Actions offered at this position (all of them need a rule). */
export function actions(ctx) {
    return targetRule(ctx) ? ACTIONS : [];
}
