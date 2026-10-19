/**
 * Context-aware YARA completion (engine-neutral).
 *
 * complete(ctx) -> { from, options, remoteRules? } | null
 * option: { label, type, detail, info, apply?, snippet?, boost?, extraChanges? }
 *   snippet uses ${name} / ${} placeholders.
 *   extraChanges: [{from, to, insert}] applied together (e.g. add an import).
 */
import { T } from './lexer.js';
import { CONDITION_KEYWORDS, META_KEYS, MODIFIERS, SECTIONS } from './keywords.js';
import { MODULES, resolvePath, childrenOf } from './modules.js';
import { sectionAt } from './analysis.js';

const BUILTIN_FUNCS = Object.keys(CONDITION_KEYWORDS).filter(k => /int\d/.test(k));

export const TOP_SNIPPETS = [
    { label: 'rule', detail: 'new rule', type: 'snippet', boost: 10, snippet: 'rule ${name}\n{\n    meta:\n        id = "{{uuid}}"\n        author = "${author}"\n        description = "${description}"\n        date = "{{date}}"\n    strings:\n        $s1 = "${text}"\n    condition:\n        ${condition}\n}' },
    { label: 'rule (minimal)', detail: 'rule without meta', type: 'snippet', snippet: 'rule ${name}\n{\n    strings:\n        $s1 = "${text}"\n    condition:\n        $s1\n}' },
    { label: 'rule (PE file)', detail: 'Windows executable', type: 'snippet', snippet: 'rule ${name}\n{\n    meta:\n        id = "{{uuid}}"\n        author = "${author}"\n        description = "${description}"\n        date = "{{date}}"\n    strings:\n        $s1 = "${text}" ascii wide\n    condition:\n        uint16(0) == 0x5A4D and filesize < ${size}MB and $s1\n}' },
    { label: 'rule (ELF file)', detail: 'Linux executable', type: 'snippet', snippet: 'rule ${name}\n{\n    meta:\n        id = "{{uuid}}"\n        author = "${author}"\n        description = "${description}"\n        date = "{{date}}"\n    strings:\n        $s1 = "${text}"\n    condition:\n        uint32(0) == 0x464C457F and $s1\n}' },
    { label: 'private rule', type: 'snippet', snippet: 'private rule ${name}\n{\n    meta:\n        id = "{{uuid}}"\n        author = "${author}"\n        description = "${description}"\n        date = "{{date}}"\n    condition:\n        ${condition}\n}' },
    { label: 'global rule', type: 'snippet', snippet: 'global rule ${name}\n{\n    meta:\n        id = "{{uuid}}"\n        author = "${author}"\n        description = "${description}"\n        date = "{{date}}"\n    condition:\n        ${filesize < 10MB}\n}' },
    { label: 'import', type: 'keyword', snippet: 'import "${module}"' },
    { label: 'include', type: 'keyword', snippet: 'include "${file.yar}"' },
];

const CONDITION_SNIPPETS = [
    { label: 'any of them', type: 'snippet', apply: 'any of them' },
    { label: 'all of them', type: 'snippet', apply: 'all of them' },
    { label: 'N of ($s*)', type: 'snippet', snippet: '${2} of ($${s}*)' },
    { label: 'for any i in', type: 'snippet', detail: 'loop over occurrences', snippet: 'for any i in (1..#${a}) : ( @${a}[i] < ${100} )' },
    { label: 'for all of them', type: 'snippet', snippet: 'for all of them : ( # > ${1} )' },
    { label: 'MZ header', type: 'snippet', detail: 'uint16(0) == 0x5A4D', apply: 'uint16(0) == 0x5A4D' },
    { label: 'PE header', type: 'snippet', detail: 'MZ + PE signature', apply: 'uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550' },
    { label: 'ELF header', type: 'snippet', detail: 'uint32(0) == 0x464C457F', apply: 'uint32(0) == 0x464C457F' },
    { label: 'filesize <', type: 'snippet', snippet: 'filesize < ${1}MB' },
];

/** The rule an offset belongs to, unclosed rules included (the user is typing in it). */
export function ruleForPos(parsed, pos) {
    let found = null;
    for (const r of parsed.rules) {
        if (r.from > pos) break;
        const end = r.closeBrace != null ? r.to : Infinity;
        if (pos <= end) found = r;
    }
    return found;
}

function tokenAt(parsed, pos) {
    for (const c of parsed.comments) if (pos > c.from && pos <= c.to && (c.block ? pos < c.to || !c.value.endsWith('*/') : true)) return c;
    return parsed.tokens.find(t => pos > t.from && pos < t.to) || null;
}

export function complete(ctx) {
    const { text, pos, parsed } = ctx;
    const before = text.slice(0, pos);
    const lineBefore = before.slice(before.lastIndexOf('\n') + 1);

    // inside import "..."
    const imp = lineBefore.match(/^\s*import\s+"([A-Za-z0-9_]*)$/);
    if (imp) {
        const used = new Set(parsed.imports.map(i => i.name));
        return {
            from: pos - imp[1].length,
            options: Object.entries(MODULES).filter(([n]) => !used.has(n)).map(([name, m]) => ({ label: name, type: 'module', info: m.doc })),
        };
    }

    const inside = tokenAt(parsed, pos);
    if (inside && (inside.type === T.COMMENT || inside.type === T.TEXT || inside.type === T.REGEX || inside.type === T.HEX)) return null;

    const word = lineBefore.match(/[$#@!]?[A-Za-z0-9_]*\*?$/)[0];
    const from = pos - word.length;
    const rule = ruleForPos(parsed, pos);

    if (!rule || (rule.openBrace == null && !/^\s*(private\s+|global\s+)*rule\b/.test(lineBefore))) {
        if (!ctx.explicit && !word) return null;
        return { from, options: TOP_SNIPPETS };
    }
    const section = sectionAt(rule, pos);
    if (section === 'header') return null;

    const atLineStart = lineBefore.slice(0, lineBefore.length - word.length).trim() === '';
    const options = [];

    // section headers, at line start
    if (atLineStart && !word.startsWith('$')) {
        for (const [name, doc] of Object.entries(SECTIONS)) {
            if (!rule.sections[name]) options.push({ label: `${name}:`, type: 'section', info: doc, apply: `${name}:\n        `, boost: 5 });
        }
    }

    if (section === 'meta') {
        if (atLineStart) {
            const used = new Set(rule.meta.map(m => m.key));
            for (const [key, doc] of Object.entries(META_KEYS)) {
                if (used.has(key)) continue;
                const value = key === 'date' || key === 'modified' ? new Date().toISOString().slice(0, 10) : '';
                options.push({ label: key, type: 'property', info: doc, snippet: `${key} = "\${${value}}"` });
            }
        }
        return options.length ? { from, options } : null;
    }

    if (section === 'strings') {
        const s = rule.strings.find(x => x.from < pos && lineIndexOf(text, x.from) === lineIndexOf(text, pos));
        if (s && pos >= s.valueTo) {
            const used = new Set(s.modifiers.map(m => m.name));
            for (const [name, def] of Object.entries(MODIFIERS)) {
                if (used.has(name) || !def.kinds.includes(s.kind)) continue;
                options.push({ label: name, type: 'modifier', info: def.doc });
            }
            return { from, options };
        }
        if (atLineStart) {
            const n = nextStringName(rule);
            options.push(
                { label: `$${n} = "..."`, type: 'snippet', detail: 'text string', snippet: `$\${${n}} = "\${text}"`, boost: 3 },
                { label: `$${n} = { ... }`, type: 'snippet', detail: 'hex string', snippet: `$\${${n}} = { \${4D 5A} }` },
                { label: `$${n} = /.../`, type: 'snippet', detail: 'regular expression', snippet: `$\${${n}} = /\${regex}/` },
            );
        }
        return options.length ? { from, options } : null;
    }

    if (section !== 'condition') return options.length ? { from, options } : null;

    // condition: $a #a @a !a
    if (/^[$#@!]/.test(word)) {
        const sigil = word[0];
        const names = rule.strings.map(x => x.name).filter(Boolean);
        for (const n of names) {
            const def = rule.strings.find(x => x.name === n);
            options.push({ label: `${sigil}${n}`, type: 'variable', detail: def.kind, info: text.slice(def.from, def.to) });
        }
        if (sigil === '$') {
            const prefixes = new Set(names.map(n => n.replace(/\d+$/, '')).filter(p => p && names.filter(n => n.startsWith(p)).length > 1));
            for (const p of prefixes) options.push({ label: `$${p}*`, type: 'variable', detail: 'every string starting with ' + p });
        }
        return { from, options };
    }

    // module.path.
    const dotted = lineBefore.slice(0, lineBefore.length - word.length).match(/([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)*)\.$/);
    if (dotted) {
        const parts = dotted[1].replace(/\[[^\]]*\]/g, '').split('.');
        const node = resolvePath(parts);
        const children = childrenOf(node);
        for (const [name, child] of Object.entries(children)) {
            const isFunc = child.kind === 'function';
            const isArray = child.kind === 'array';
            const isDict = child.kind === 'dict';
            options.push({
                label: name,
                type: isFunc ? 'function' : child.kind === 'constant' ? 'constant' : isArray || child.kind === 'struct' ? 'namespace' : 'property',
                detail: isFunc ? child.sig : child.type || (isArray ? 'array' : child.kind),
                info: child.doc || undefined,
                snippet: isFunc ? `${name}(\${})` : isArray ? `${name}[\${0}]` : isDict ? `${name}["\${key}"]` : undefined,
            });
        }
        return options.length ? { from, options } : null;
    }

    // keywords, builtins, modules, rule names, snippets
    for (const [kw, doc] of Object.entries(CONDITION_KEYWORDS)) {
        if (BUILTIN_FUNCS.includes(kw)) options.push({ label: kw, type: 'function', info: doc, snippet: `${kw}(\${0})` });
        else options.push({ label: kw, type: 'keyword', info: doc });
    }
    const imported = new Set(parsed.imports.map(i => i.name));
    const importAt = parsed.imports.length ? lineEndOf(text, parsed.imports[parsed.imports.length - 1].to) : 0;
    for (const [name, m] of Object.entries(MODULES)) {
        const opt = { label: name, type: 'module', info: m.doc, detail: imported.has(name) ? 'module' : 'module (adds import)' };
        if (!imported.has(name)) opt.extraChanges = [{ from: importAt, to: importAt, insert: parsed.imports.length ? `\nimport "${name}"` : `import "${name}"\n\n` }];
        options.push(opt);
    }
    for (const r of parsed.rules) {
        if (r === rule || !r.name || r.from > rule.from) continue;     // only rules above can be used
        const desc = r.meta.find(m => m.key === 'description');
        options.push({ label: r.name, type: 'rule', detail: 'rule in this document', info: desc ? desc.value : undefined, boost: 2 });
    }
    if (rule.strings.length) options.push({ label: 'them', type: 'keyword', info: CONDITION_KEYWORDS.them });
    options.push(...CONDITION_SNIPPETS);
    return { from, options, remoteRules: word.length >= 3 ? word : null };
}

function nextStringName(rule) {
    const used = new Set(rule.strings.map(s => s.name));
    let i = rule.strings.length + 1;
    while (used.has(`s${i}`)) i++;
    return `s${i}`;
}

function lineIndexOf(text, pos) {
    let n = 0;
    for (let i = 0; i < pos; i++) if (text.charCodeAt(i) === 10) n++;
    return n;
}

function lineEndOf(text, pos) {
    const i = text.indexOf('\n', pos);
    return i === -1 ? text.length : i;
}
