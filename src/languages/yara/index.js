/**
 * YARA language pack for rulezet-editor.
 * Pure data and functions: no network, no DOM, no editor engine import.
 */
import { parse } from './parser.js';
import { lint, DEFAULT_LINT_OPTIONS } from './lint.js';
import { complete, TOP_SNIPPETS } from './completion.js';
import { hover, definition, references, rename } from './navigation.js';
import { format, DEFAULT_FORMAT_OPTIONS } from './format.js';
import { actions, setMeta } from './actions.js';
import { stream } from './highlight.js';
import { conditionRefs } from './analysis.js';
import { MODULES } from './modules.js';
import { TUTORIAL } from './tutorial.js';

const SAMPLE = `import "pe"

rule Example_Downloader : downloader
{
    meta:
        author = "you"
        description = "Small PE that downloads a second stage"
        date = "${new Date().toISOString().slice(0, 10)}"
    strings:
        $url = "http://" ascii wide
        $api = "URLDownloadToFileA" ascii
        $mz  = { 4D 5A 90 00 }
    condition:
        $mz at 0 and pe.imports("urlmon.dll") and all of ($url, $api)
}
`;

export default {
    id: 'yara',
    name: 'YARA',
    version: '0.1.0',
    maturity: 'full',
    extensions: ['.yar', '.yara', '.rule'],
    validateAs: 'yara',
    testInput: 'binary',
    sample: SAMPLE,

    detect(text) {
        if (/^\s*(private\s+|global\s+)*rule\s+[A-Za-z_]\w*[^{]*\{/m.test(text) && /\bcondition\s*:/.test(text)) return 0.95;
        if (/^\s*import\s+"(pe|elf|math|hash|dotnet)"/m.test(text)) return 0.8;
        return 0;
    },

    stream,
    comments: { line: '//', block: ['/*', '*/'] },
    indentUnit: '    ',
    snippets: TOP_SNIPPETS,
    tutorial: TUTORIAL,            // "A complete example" chapter of the editor's tutorial
    actions,
    modules: MODULES,

    parse,
    lint(model, options) { return lint(model, { ...DEFAULT_LINT_OPTIONS, ...options }); },
    complete,
    hover,
    definition,
    references,
    rename,
    format(model, options) { return format(model, { ...DEFAULT_FORMAT_OPTIONS, ...options }); },

    /** One entry per rule, with its sections and strings (outline + multi-rule view). */
    splitRules(model) {
        return model.rules.map(r => ({
            name: r.name || '(unnamed)',
            from: r.from,
            to: r.to,
            kind: r.modifiers.includes('private') ? 'private rule' : r.modifiers.includes('global') ? 'global rule' : 'rule',
            tags: r.tags.map(t => t.name),
            detail: (r.meta.find(m => m.key === 'description') || {}).value || '',
            text: model.text.slice(r.from, r.to),
            children: [
                ...r.strings.map(s => ({ name: s.id, from: s.idFrom, to: s.to, kind: `${s.kind} string` })),
                ...(r.condition ? [{ name: 'condition', from: r.sections.condition.from, to: r.condition.to, kind: 'condition' }] : []),
            ],
        }));
    },

    /** Key / value metadata of a rule (Fields panel): YARA `meta:` entries. */
    meta: {
        /** meta: entries, plus the rule's header tags (rule X : a b) as the pseudo key "@tags". */
        entries(model, ruleName) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule) return null;
            const out = rule.meta.map(m => ({ key: m.key, value: String(m.value) }));
            if (rule.tags.length) out.push({ key: '@tags', value: rule.tags.map(t => t.name).join(' ') });
            return out;
        },
        /** Sets `key` (string value), replacing its first occurrence or adding it. */
        set(model, ruleName, key, value) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule || rule.openBrace == null || !/^[A-Za-z_]\w*$/.test(key)) return null;
            const quoted = `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, ' ')}"`;
            return setMeta(model.text, rule, key, quoted);
        },
        /** A new rule to fill from the Fields panel (no placeholders: it compiles once $s1 is set). */
        skeleton(name, { strings = true } = {}) {
            const body = strings ? '    strings:\n        $s1 = "change me"\n    condition:\n        $s1\n' : '    condition:\n        true\n';
            return `rule ${name}\n{\n    meta:\n        id = "{{uuid}}"\n        date = "{{date}}"\n${body}}\n`;
        },
        /** A rule identifier made from a title: "My rule (v2)" -> My_rule_v2. */
        ruleName(title) {
            let n = String(title || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
            if (!n) return null;
            if (/^\d/.test(n)) n = `rule_${n}`;
            return n.slice(0, 128);
        },
        /** Renames a rule everywhere in the document (its declaration and every use). */
        renameRule(model, ruleName, newName) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule || rule.nameFrom == null) return null;
            if (model.rules.some(r => r.name === newName)) return { error: `A rule named ${newName} already exists` };
            const res = rename({ text: model.text, pos: rule.nameFrom, parsed: model }, newName);
            return res.error ? res : res.changes;
        },
        /** Removes every `key = ...` line of the rule (and an emptied meta: section). */
        remove(model, ruleName, key) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule) return null;
            const text = model.text;
            const hits = rule.meta.filter(m => m.key === key);
            if (!hits.length) return [];
            const lineOf = (pos) => {
                const s = text.lastIndexOf('\n', pos - 1);
                const e = text.indexOf('\n', pos);
                return { from: s, to: e === -1 ? text.length : e };    // removes the newline before the line
            };
            if (hits.length === rule.meta.length && rule.sections.meta) {
                const sec = lineOf(rule.sections.meta.from);
                const last = lineOf(hits[hits.length - 1].to);
                return [{ from: sec.from, to: last.to, insert: '' }];
            }
            return hits.map(m => ({ ...lineOf(m.from), insert: '' }));
        },
    },

    /** Strings and condition as form fields (Fields panel, "Strings & condition"). */
    body: {
        modifiers: {
            text: ['ascii', 'wide', 'nocase', 'fullword', 'private', 'xor', 'base64', 'base64wide'],
            hex: ['private'],
            regex: ['ascii', 'wide', 'nocase', 'fullword', 'private'],
        },
        /** { strings: [{ index, id, kind, value, modifiers: [{ name, args }] }], condition } or null. */
        read(model, ruleName) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule) return null;
            return {
                strings: rule.strings.map((s, index) => ({ index, id: s.id, kind: s.kind, value: bodyValue(s), modifiers: s.modifiers.map(m => ({ name: m.name, args: m.args })) })),
                condition: rule.condition ? rule.condition.text : '',
            };
        },
        /** Replaces string `index` (or adds one when index is null). s: { id, kind, value, modifiers } */
        setString(model, ruleName, index, s) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule || rule.openBrace == null) return null;
            const line = stringLine(s);
            if (!line) return null;
            const text = model.text;
            if (index !== null && rule.strings[index]) {
                const old = rule.strings[index];
                return [{ from: old.from, to: old.to, insert: line }];
            }
            const ind = bodyIndents(text, rule);
            if (rule.strings.length) {
                const last = rule.strings[rule.strings.length - 1];
                return [{ from: last.to, to: last.to, insert: `\n${ind.entry}${line}` }];
            }
            if (rule.sections.strings) return [{ from: rule.sections.strings.to, to: rule.sections.strings.to, insert: `\n${ind.entry}${line}` }];
            const cond = rule.sections.condition;
            if (cond) {
                const at = text.lastIndexOf('\n', cond.from - 1) + 1;
                return [{ from: at, to: at, insert: `${ind.section}strings:\n${ind.entry}${line}\n` }];
            }
            return [{ from: rule.closeBrace, to: rule.closeBrace, insert: `${ind.section}strings:\n${ind.entry}${line}\n` }];
        },
        removeString(model, ruleName, index) {
            const rule = model.rules.find(r => r.name === ruleName);
            const s = rule && rule.strings[index];
            if (!s) return null;
            const text = model.text;
            const from = text.lastIndexOf('\n', s.from - 1);
            return [{ from: from < 0 ? s.from : from, to: s.to, insert: '' }];
        },
        /** "a and (b or c) or d" -> [{ op: null, text: 'a' }, { op: 'and', text: '(b or c)' }, { op: 'or', text: 'd' }]
         *  (top level only: parentheses, strings and regexes are kept whole). */
        splitCondition(text) {
            return splitTopLevel(String(text || ''));
        },
        joinCondition(parts) {
            return parts.filter(p => String(p.text || '').trim())
                .map((p, i) => (i === 0 ? '' : ` ${p.op === 'or' ? 'or' : 'and'} `) + p.text.trim()).join('');
        },
        /** Ready-made clauses offered by the condition form. */
        clauses(strings) {
            const ids = strings.map(s => s.id).filter(id => id && id !== '$');
            return [
                ...(ids.length ? [{ label: 'any of them', text: 'any of them' }, { label: 'all of them', text: 'all of them' }] : []),
                ...ids.map(id => ({ label: id, text: id })),
                { label: 'PE file', text: 'uint16(0) == 0x5A4D' },
                { label: 'ELF file', text: 'uint32(0) == 0x464C457F' },
                { label: 'filesize <', text: 'filesize < 2MB' },
                ...(ids[0] ? [{ label: `${ids[0]} at 0`, text: `${ids[0]} at 0` }, { label: `#${ids[0].slice(1)} > 2`, text: `#${ids[0].slice(1)} > 2` }] : []),
                { label: 'not …', text: 'not ' + (ids[0] || 'true') },
            ];
        },
        setCondition(model, ruleName, condition) {
            const rule = model.rules.find(r => r.name === ruleName);
            if (!rule || rule.openBrace == null) return null;
            const value = String(condition || '').trim() || 'true';
            if (rule.condition && rule.condition.text) return [{ from: rule.condition.from, to: rule.condition.to, insert: value }];
            const ind = bodyIndents(model.text, rule);
            if (rule.sections.condition) return [{ from: rule.sections.condition.to, to: rule.sections.condition.to, insert: `\n${ind.entry}${value}` }];
            return [{ from: rule.closeBrace, to: rule.closeBrace, insert: `${ind.section}condition:\n${ind.entry}${value}\n` }];
        },
    },

    /** Tests on samples (rulezet-tester): how a hit reads and where it points in the rule. */
    test: {
        sampleKind: 'file',
        hitLabel(hit) {
            const w = hit.where || {};
            if (w.kind === 'offset') return `${hit.item} at 0x${w.offset.toString(16)}${w.length ? ` (${w.length} B)` : ''}`;
            return hit.item || 'condition';
        },
        /** Range of the matched string (or of the rule) in the document. */
        locate(model, hit) {
            const rule = model.rules.find(r => r.name === hit.rule);
            if (!rule) return null;
            const s = hit.item && rule.strings.find(x => x.id === hit.item);
            return s ? { from: s.idFrom, to: s.idTo } : { from: rule.from, to: rule.from };
        },
    },

    /** Rules a rule needs that are not in the document (for host lookup). */
    dependencies(model) {
        const local = new Set(model.rules.map(r => r.name));
        const out = [];
        for (const r of model.rules) {
            for (const t of conditionRefs(r).idents) {
                if (!local.has(t.value) && !MODULES[t.value]) out.push({ rule: r.name, name: t.value, from: t.from, to: t.to });
            }
        }
        return out;
    },

    /** Foldable ranges: rule bodies and sections. */
    folding(model) {
        const ranges = [];
        for (const r of model.rules) {
            if (r.openBrace != null && r.closeBrace != null) ranges.push({ from: r.openBrace + 1, to: r.closeBrace, line: 'open' });
            const secs = Object.values(r.sections).sort((a, b) => a.from - b.from);
            for (const s of secs) if (s.bodyTo > s.to) ranges.push({ from: s.to, to: trimEnd(model.text, s.bodyTo) });
        }
        return ranges;
    },
};

/** Splits a condition on its top-level and / or (outside parentheses, brackets, strings, regexes). */
function splitTopLevel(text) {
    const parts = [];
    let depth = 0, start = 0, op = null, i = 0;
    const push = (end, nextOp) => {
        const piece = text.slice(start, end).trim();
        if (piece) parts.push({ op, text: piece });
        op = nextOp;
    };
    while (i < text.length) {
        const c = text[i];
        if (c === '"') { i++; while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; } i++; continue; }
        if (c === '/' && /matches\s*$/.test(text.slice(0, i))) { i++; while (i < text.length && text[i] !== '/') { if (text[i] === '\\') i++; i++; } i++; continue; }
        if (c === '(' || c === '[') depth++;
        else if (c === ')' || c === ']') depth = Math.max(0, depth - 1);
        else if (depth === 0) {
            const m = /^(and|or)\b/.exec(text.slice(i));
            if (m && (i === 0 || /\s|\)/.test(text[i - 1]))) {
                push(i, m[1]);
                i += m[1].length;
                start = i;
                continue;
            }
        }
        i++;
    }
    push(text.length, null);
    return parts;
}

/** What the form shows for a string: the text inside the quotes / braces, a regex as written. */
function bodyValue(s) {
    if (s.kind === 'text') return s.raw.slice(1, s.raw.endsWith('"') && s.raw.length > 1 ? -1 : undefined);
    if (s.kind === 'hex') return s.raw.replace(/^\{\s*|\s*\}$/g, '');
    return s.raw;
}

function stringLine(s) {
    const id = String(s.id || '').trim().replace(/^\$?/, '$');
    if (!/^\$[A-Za-z0-9_]*$/.test(id)) return null;
    let value = String(s.value ?? '');
    if (s.kind === 'text') value = `"${value.replace(/(^|[^\\])"/g, '$1\\"')}"`;
    else if (s.kind === 'hex') value = `{ ${value.trim()} }`;
    else if (!/^\/.*\/[is]*$/s.test(value.trim())) value = `/${value.trim()}/`;
    const mods = (s.modifiers || []).map(m => (m.args ? `${m.name}(${m.args})` : m.name)).join(' ');
    return `${id} = ${value.trim ? value.trim() : value}${mods ? ' ' + mods : ''}`;
}

function bodyIndents(text, rule) {
    const lineIndent = (pos) => { const s = text.lastIndexOf('\n', pos - 1) + 1; return text.slice(s, pos).match(/^[ \t]*/)[0]; };
    const sec = Object.values(rule.sections)[0];
    const section = sec ? lineIndent(sec.from) : '    ';
    const first = rule.strings[0] || rule.meta[0];
    return { section, entry: first ? lineIndent(first.from) : section + '    ' };
}

function trimEnd(text, pos) {
    while (pos > 0 && /\s/.test(text[pos - 1])) pos--;
    return pos;
}
