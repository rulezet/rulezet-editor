/**
 * YARA lint: everything that can be checked without compiling.
 * Diagnostic: {from, to, severity: error|warning|info, message, code, fixes?: [{label, changes:[{from,to,insert}]}]}
 */
import { MODULES, resolvePath } from './modules.js';
import { MODIFIERS, MODIFIER_CONFLICTS } from './keywords.js';
import { conditionRefs, refMatches, checkHex, checkTextEscapes, checkRegex } from './analysis.js';
import { T } from './lexer.js';
import { textByteLength } from './parser.js';

export const DEFAULT_LINT_OPTIONS = {
    requireMeta: ['author', 'description'],   // info when missing; [] to disable
    performance: true,
};

export function lint(parsed, options = {}) {
    const opts = { ...DEFAULT_LINT_OPTIONS, ...options };
    const text = parsed.text;
    const out = [];
    const add = (from, to, severity, message, code, fixes) => out.push({ from, to: Math.max(to, from + 1), severity, message, code, fixes });

    for (const e of parsed.errors) {
        const fixes = e.fix ? [{ label: 'Add the missing "}"', changes: [{ from: e.fix.insertAt, to: e.fix.insertAt, insert: e.fix.text }] }] : undefined;
        add(e.from, e.to, 'error', e.message, e.code || 'syntax', fixes);
    }

    // escapes: every text string (meta, strings, condition) and every regex outside strings:
    const stringValues = new Set(parsed.rules.flatMap(r => r.strings.map(x => x.valueFrom)));
    for (const t of parsed.tokens) {
        if (t.type === T.TEXT && t.closed) {
            checkTextEscapes(t.value).forEach(e => add(t.from + e.offset, t.from + e.offset + e.length, 'error', e.message, 'escape'));
        } else if (t.type === T.REGEX && t.closed && !stringValues.has(t.from)) {
            checkRegex(t.value.slice(1, t.value.lastIndexOf('/'))).forEach(e => add(t.from + 1 + e.offset, t.from + 1 + e.offset + e.length, 'error', e.message, 'regex'));
        }
    }

    for (const inc of parsed.includes) {
        add(inc.from, inc.to, 'info', `include "${inc.name}" is not resolved by the editor: rules from that file are not checked`, 'include');
    }

    // ── imports ──
    const imported = new Set();
    for (const imp of parsed.imports) {
        if (imported.has(imp.name)) {
            add(imp.from, imp.to, 'warning', `Module "${imp.name}" is imported twice`, 'duplicate-import',
                [{ label: 'Remove this import', changes: [removeLine(text, imp.from, imp.to)] }]);
        }
        imported.add(imp.name);
        if (!MODULES[imp.name]) add(imp.nameFrom, imp.nameTo, 'error', `Unknown module "${imp.name}"`, 'unknown-module');
        else if (MODULES[imp.name].optional) add(imp.nameFrom, imp.nameTo, 'warning', `Module "${imp.name}" is not built into every YARA (missing from yara-python, used by Rulezet)`, 'optional-module');
    }
    const usedModules = new Set();
    const importInsertAt = parsed.imports.length ? lineEnd(text, parsed.imports[parsed.imports.length - 1].to) : 0;
    const importChange = (mod) => ({
        from: importInsertAt, to: importInsertAt,
        insert: parsed.imports.length ? `\nimport "${mod}"` : `import "${mod}"\n\n`,
    });

    // ── rules ──
    const seen = new Map();
    const metaIds = new Map();
    const defined = new Set();
    const allNames = new Set(parsed.rules.map(r => r.name).filter(Boolean));

    for (const rule of parsed.rules) {
        if (rule.name) {
            if (seen.has(rule.name)) add(rule.nameFrom, rule.nameTo, 'error', `Duplicate rule name "${rule.name}"`, 'duplicate-rule');
            seen.set(rule.name, rule);
        }

        // tags
        const tagSeen = new Set();
        for (const tag of rule.tags) {
            if (tagSeen.has(tag.name)) add(tag.from, tag.to, 'error', `Duplicate tag "${tag.name}"`, 'duplicate-tag');
            tagSeen.add(tag.name);
        }

        // meta
        if (opts.requireMeta.length && rule.openBrace != null) {
            const keys = new Set(rule.meta.map(m => m.key));
            const missing = opts.requireMeta.filter(k => !keys.has(k));
            if (missing.length) {
                const fixes = [];
                if (rule.sections.meta) {
                    const at = lineEnd(text, rule.meta.length ? rule.meta[rule.meta.length - 1].to : rule.sections.meta.to);
                    const indent = rule.meta.length ? indentOf(text, rule.meta[0].from) : '        ';
                    fixes.push({ label: `Add ${missing.join(', ')}`, changes: [{ from: at, to: at, insert: missing.map(k => `\n${indent}${k} = "${metaDefault(k)}"`).join('') }] });
                } else {
                    const at = rule.openBrace + 1;
                    fixes.push({ label: 'Add a meta section', changes: [{ from: at, to: at, insert: `\n    meta:${missing.map(k => `\n        ${k} = "${metaDefault(k)}"`).join('')}` }] });
                }
                add(rule.nameFrom, rule.nameTo, 'info', `Missing meta: ${missing.join(', ')}`, 'missing-meta', fixes);
            }
        }

        // meta id: Rulezet keeps it as the rule's original uuid, so it must be one and be unique
        for (const m of rule.meta) {
            if (m.key !== 'id' && m.key !== 'uuid') continue;
            if (m.valueType === 'string' && !UUID.test(m.value)) {
                add(m.valueFrom, m.valueTo, 'warning', `"${m.key}" is not a UUID: Rulezet uses it as the rule's identifier`, 'meta-id-format',
                    [{ label: 'Replace with a new UUID', changes: [{ from: m.valueFrom, to: m.valueTo, insert: '"{{uuid}}"' }] }]);
            } else if (m.valueType === 'string') {
                const other = metaIds.get(m.value.toLowerCase());
                if (other) add(m.valueFrom, m.valueTo, 'warning', `Same ${m.key} as rule "${other}": every rule needs its own UUID`, 'meta-id-duplicate',
                    [{ label: 'Replace with a new UUID', changes: [{ from: m.valueFrom, to: m.valueTo, insert: '"{{uuid}}"' }] }]);
                else metaIds.set(m.value.toLowerCase(), rule.name);
            }
        }

        // strings
        const ids = new Map();
        for (const s of rule.strings) {
            if (s.name !== '' && ids.has(s.id)) add(s.idFrom, s.idTo, 'error', `Duplicate string identifier ${s.id}`, 'duplicate-string');
            if (s.name !== '') ids.set(s.id, s);
            checkString(s, add, opts);
        }

        // condition
        if (rule.condition) {
            const refs = conditionRefs(rule);
            const used = new Set();
            for (const ref of refs.strings) {
                if (ref.name === '' && !ref.wildcard) continue;          // anonymous "$" inside a for..of loop
                const hits = rule.strings.filter(s => refMatches(ref, s.name));
                if (!hits.length) {
                    const fixes = [];
                    const close = closest(ref.name, rule.strings.map(s => s.name));
                    if (close) fixes.push({ label: `Change to ${ref.sigil}${close}`, changes: [{ from: ref.tok.from + 1, to: ref.tok.to, insert: close }] });
                    add(ref.tok.from, ref.tok.to, 'error', ref.wildcard ? `No string matches ${ref.tok.value}` : `Undefined string ${ref.tok.value}`, 'undefined-string', fixes);
                }
                hits.forEach(s => used.add(s));
            }
            if (refs.them.length) {
                rule.strings.forEach(s => used.add(s));
                if (!rule.strings.length) refs.them.forEach(t => add(t.from, t.to, 'error', '"them" used but the rule has no strings', 'them-without-strings'));
            }
            for (const s of rule.strings) {
                if (!used.has(s)) {
                    add(s.idFrom, s.idTo, 'error', `String ${s.id} is never used in the condition (YARA refuses unreferenced strings)`, 'unused-string', [
                        { label: `Use ${s.id} in the condition`, changes: [{ from: rule.condition.to, to: rule.condition.to, insert: ` and ${s.id}` }] },
                        { label: `Remove ${s.id}`, changes: [removeLine(text, s.from, s.to)] },
                    ]);
                }
            }
            for (const p of refs.paths) {
                const root = p.parts[0];
                if (MODULES[root]) {
                    usedModules.add(root);
                    if (!imported.has(root)) {
                        add(p.tok.from, p.tok.to, 'error', `Module "${root}" is used but not imported`, 'module-not-imported',
                            [{ label: `Add import "${root}"`, changes: [importChange(root)] }]);
                    } else if (p.parts.length > 1 && !resolvePath(p.parts) && Object.keys(MODULES[root].fields).length) {
                        add(p.from, p.to, 'warning', `Unknown field "${p.parts.join('.')}" in module ${root}`, 'unknown-member');
                    }
                } else if (!refs.loopVars.has(root)) {
                    add(p.tok.from, p.tok.to, 'error', `Unknown module or variable "${root}"`, 'unknown-identifier');
                }
            }
            for (const t of refs.idents) {
                if (text[t.to] === '*') {
                    // rule set "any of (name*)"
                    if (![...defined].some(n => n.startsWith(t.value))) {
                        add(t.from, t.to + 1, 'warning', `No rule before this one starts with "${t.value}" in this document (rules from another file?)`, 'external-rule');
                    }
                    continue;
                }
                if (defined.has(t.value)) continue;
                if (t.value === rule.name) {
                    add(t.from, t.to, 'warning', `Rule "${t.value}" refers to itself`, 'self-reference');
                } else if (allNames.has(t.value)) {
                    add(t.from, t.to, 'error', `Rule "${t.value}" is used before it is defined (move it above)`, 'rule-order');
                } else if (MODULES[t.value]) {
                    // bare module name, already reported as a path
                } else {
                    add(t.from, t.to, 'warning', `"${t.value}" is not defined in this document (rule from another file?)`, 'external-rule');
                }
            }
            for (const t of refs.deprecated) {
                const fixes = [{ label: 'Replace with pe.entry_point', changes: [{ from: t.from, to: t.to, insert: 'pe.entry_point' }, ...(imported.has('pe') ? [] : [importChange('pe')])] }];
                add(t.from, t.to, 'warning', '"entrypoint" is deprecated: use pe.entry_point or elf.entry_point', 'deprecated', fixes);
                usedModules.add('pe');
            }
        }
        if (rule.name) defined.add(rule.name);
    }

    for (const imp of parsed.imports) {
        if (MODULES[imp.name] && !usedModules.has(imp.name) && imp.name !== 'console') {
            add(imp.from, imp.to, 'warning', `Module "${imp.name}" is imported but never used`, 'unused-import',
                [{ label: 'Remove this import', changes: [removeLine(text, imp.from, imp.to)] }]);
        }
    }
    return out;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Value put by the "add missing meta" fix; {{uuid}} and {{date}} are filled in by the core. */
function metaDefault(key) {
    return key === 'id' || key === 'uuid' ? '{{uuid}}' : key === 'date' ? '{{date}}' : '';
}

function checkString(s, add, opts) {
    // modifiers
    const names = new Set();
    for (const m of s.modifiers) {
        const def = MODIFIERS[m.name];
        if (names.has(m.name)) add(m.from, m.to, 'error', `Duplicate modifier "${m.name}"`, 'duplicate-modifier');
        names.add(m.name);
        if (def && !def.kinds.includes(s.kind)) {
            add(m.from, m.to, 'error', `"${m.name}" cannot be used on a ${s.kind === 'hex' ? 'hex string' : s.kind === 'regex' ? 'regular expression' : 'text string'}`, 'modifier-kind');
        }
        if (m.args != null && !['xor', 'base64', 'base64wide'].includes(m.name)) {
            add(m.from, m.to, 'error', `"${m.name}" takes no argument`, 'modifier-args');
        }
        if (m.name === 'xor' && m.args != null) {
            const r = m.args.trim().match(/^(0x[0-9a-fA-F]+|\d+)(\s*-\s*(0x[0-9a-fA-F]+|\d+))?$/);
            const lo = r && Number(r[1]);
            const hi = r && r[3] !== undefined ? Number(r[3]) : lo;
            if (!r || lo > 255 || hi > 255 || lo > hi) add(m.from, m.to, 'error', 'xor range must be xor(n) or xor(lo-hi) with 0 <= lo <= hi <= 255', 'xor-range');
        }
        if ((m.name === 'base64' || m.name === 'base64wide') && m.args != null) {
            const alpha = m.args.trim().replace(/^"|"$/g, '');
            if (alpha.length !== 64) add(m.from, m.to, 'error', `Custom base64 alphabet must be 64 characters (got ${alpha.length})`, 'base64-alphabet');
        }
    }
    for (const [a, b] of MODIFIER_CONFLICTS) {
        if (names.has(a) && names.has(b)) {
            const m = s.modifiers.find(x => x.name === b);
            add(m.from, m.to, 'error', `"${a}" and "${b}" cannot be used together`, 'modifier-conflict');
        }
    }

    if (s.kind === 'text' && s.closed) {
        const len = textByteLength(s.raw);
        if (len === 0) add(s.valueFrom, s.valueTo, 'error', 'Empty string', 'empty-string');
        else if (opts.performance && len < 4 && !names.has('base64') && !names.has('xor'))
            add(s.valueFrom, s.valueTo, 'info', `Short string (${len} byte${len > 1 ? 's' : ''}): may slow down scanning`, 'perf-short-string');
    }
    if (s.kind === 'hex' && s.closed) {
        const h = checkHex(s.raw);
        h.errors.forEach(e => add(s.valueFrom + e.offset, s.valueFrom + e.offset + e.length, 'error', e.message, 'hex'));
        if (!h.errors.length && opts.performance) {
            if (h.fixedBytes < 3) add(s.valueFrom, s.valueTo, 'info', `Only ${h.fixedBytes} fixed byte${h.fixedBytes === 1 ? '' : 's'}: may slow down scanning`, 'perf-short-hex');
            else if (h.leadingWildcard) add(s.valueFrom, s.valueTo, 'info', 'Hex string starts with a wildcard: start with fixed bytes for faster scanning', 'perf-hex-wildcard');
        }
    }
    if (s.kind === 'regex' && s.closed) {
        const body = s.raw.slice(1, s.raw.lastIndexOf('/'));
        checkRegex(body).forEach(e => add(s.valueFrom + 1 + e.offset, s.valueFrom + 1 + e.offset + e.length, 'error', e.message, 'regex'));
    }
    if (s.kind === 'regex' && s.closed && opts.performance) {
        const body = s.raw.slice(1, s.raw.lastIndexOf('/'));
        if (/^(\.\*|\.\+)/.test(body) || /(\.\*|\.\+)$/.test(body))
            add(s.valueFrom, s.valueTo, 'info', 'Leading / trailing ".*" adds nothing and slows scanning: remove it', 'perf-regex-dotstar');
        else if (/\.\*|\.\+/.test(body) && !/\.\*\?|\.\+\?|\.\{/.test(body))
            add(s.valueFrom, s.valueTo, 'info', 'Unbounded ".*" in a regex: prefer a bounded repeat like .{0,64}', 'perf-regex-unbounded');
        if (body.length === 0) add(s.valueFrom, s.valueTo, 'error', 'Empty regular expression', 'empty-regex');
    }
}

// ── small text helpers ──
function lineStart(text, pos) { const i = text.lastIndexOf('\n', pos - 1); return i + 1; }
function lineEnd(text, pos) { const i = text.indexOf('\n', pos); return i === -1 ? text.length : i; }
function indentOf(text, pos) { const s = lineStart(text, pos); return text.slice(s, pos).match(/^\s*/)[0]; }

/** Removes the whole line(s) when the range is alone on them, else just the range. */
function removeLine(text, from, to) {
    const s = lineStart(text, from);
    const e = lineEnd(text, to);
    if (text.slice(s, from).trim() === '' && text.slice(to, e).trim() === '') return { from: s, to: Math.min(text.length, e + 1), insert: '' };
    return { from, to, insert: '' };
}

/** Closest name by edit distance (for "did you mean"). */
export function closest(word, candidates) {
    let best = null;
    let bestD = Infinity;
    for (const c of candidates) {
        if (!c) continue;
        const d = distance(word, c);
        if (d < bestD) { bestD = d; best = c; }
    }
    return bestD <= Math.max(1, Math.floor(word.length / 3)) ? best : null;
}

function distance(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
    for (let j = 1; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++)
        for (let j = 1; j <= n; j++)
            dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return dp[m][n];
}
