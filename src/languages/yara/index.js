/**
 * YARA language pack for rulezet-editor.
 * Pure data and functions: no network, no DOM, no editor engine import.
 */
import { parse } from './parser.js';
import { lint, DEFAULT_LINT_OPTIONS } from './lint.js';
import { complete, TOP_SNIPPETS } from './completion.js';
import { hover, definition, references, rename } from './navigation.js';
import { format, DEFAULT_FORMAT_OPTIONS } from './format.js';
import { actions } from './actions.js';
import { stream } from './highlight.js';
import { conditionRefs } from './analysis.js';
import { MODULES } from './modules.js';

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

function trimEnd(text, pos) {
    while (pos > 0 && /\s/.test(text[pos - 1])) pos--;
    return pos;
}
