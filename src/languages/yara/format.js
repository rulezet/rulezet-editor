/**
 * YARA formatter. Rewrites every rule that parses cleanly into one layout,
 * keeps comments, leaves rules with syntax errors untouched.
 *
 * format(parsed, options) -> { text, formatted, skipped: [ruleName] }
 */

export const DEFAULT_FORMAT_OPTIONS = {
    indent: 4,                 // spaces per level
    braceOnNewLine: true,      // "rule x\n{" (YARA style) or "rule x {"
    alignEquals: true,         // align "=" in meta and strings
    normalizeHex: true,        // single-line hex: { 4D 5A ?? 00 }
};

export function format(parsed, options = {}) {
    const opts = { ...DEFAULT_FORMAT_OPTIONS, ...options };
    const text = parsed.text;
    let out = '';
    let last = 0;
    const skipped = [];
    let formatted = 0;

    for (const rule of parsed.rules) {
        if (rule.errors.length || rule.closeBrace == null || !rule.condition) {
            skipped.push(rule.name || '(unnamed)');
            continue;
        }
        const comments = parsed.comments.filter(c => c.from > rule.from && c.to < rule.to);
        const res = formatRule(text, rule, comments, opts);
        if (res == null) { skipped.push(rule.name); continue; }
        out += text.slice(last, rule.from) + res;
        last = rule.to;
        formatted++;
    }
    out += text.slice(last);

    out = out
        .split('\n').map(l => l.replace(/[ \t]+$/, '')).join('\n')
        .replace(/\}\n(?=[ \t]*(private\s+|global\s+)*rule\b)/g, '}\n\n')
        .replace(/(^import "[^"\n]*"\n)(?=[ \t]*(private\s+|global\s+)*rule\b)/gm, '$1\n')
        .replace(/\n{3,}/g, '\n\n')
        .replace(/^\n+/, '')
        .replace(/\n*$/, '\n');
    return { text: out, formatted, skipped };
}

function formatRule(text, rule, comments, opts) {
    const ind = (n) => ' '.repeat(opts.indent * n);
    const condFrom = rule.condition.from;      // comments from here on stay inside the condition text

    // comments outside the condition are attached to the entry they precede (or follow on the same line)
    const items = [];
    for (const name of ['meta', 'strings', 'condition']) {
        const sec = rule.sections[name];
        if (!sec) continue;
        items.push({ type: 'section', name, from: sec.from, to: sec.to, lead: [], trail: null });
        const entries = name === 'meta' ? rule.meta : name === 'strings' ? rule.strings : [];
        for (const e of entries) items.push({ type: name, entry: e, from: e.from, to: e.to, lead: [], trail: null });
    }
    items.sort((a, b) => a.from - b.from);

    for (const c of comments) {
        if (c.from >= condFrom) continue;
        if (c.from < rule.openBrace) return null;            // comment in the header: leave the rule alone
        const prev = [...items].reverse().find(it => it.to <= c.from);
        if (prev && !text.slice(prev.to, c.from).includes('\n') && !c.block) { prev.trail = c.value; continue; }
        const next = items.find(it => it.from >= c.to);
        if (next) { next.lead.push(c.value); continue; }
        const cond = items.find(it => it.name === 'condition');
        (cond.condLead = cond.condLead || []).push(c.value);    // between "condition:" and the expression
    }

    const head = [...rule.modifiers, 'rule', rule.name].join(' ') + (rule.tags.length ? ' : ' + rule.tags.map(t => t.name).join(' ') : '');
    const lines = [head + (opts.braceOnNewLine ? '' : ' {')];
    if (opts.braceOnNewLine) lines.push('{');

    const metaWidth = opts.alignEquals ? Math.max(0, ...rule.meta.map(m => m.key.length)) : 0;
    const strWidth = opts.alignEquals ? Math.max(0, ...rule.strings.map(s => s.id.length)) : 0;

    for (const it of items) {
        const level = it.type === 'section' ? 1 : 2;
        for (const c of it.lead) pushComment(lines, c, ind(level));
        let line;
        if (it.type === 'section') {
            if (it.name === 'condition') {
                lines.push(ind(1) + 'condition:' + (it.trail ? ' ' + it.trail : ''));
                for (const c of it.condLead || []) pushComment(lines, c, ind(2));
                lines.push(...formatCondition(text, rule, ind(2)));
                continue;
            }
            line = ind(1) + it.name + ':';
        } else if (it.type === 'meta') {
            const m = it.entry;
            line = ind(2) + m.key.padEnd(metaWidth) + ' = ' + m.raw;
        } else {
            const s = it.entry;
            let value = text.slice(s.valueFrom, s.valueTo);
            if (s.kind === 'hex' && opts.normalizeHex && !value.includes('\n') && !value.includes('/')) {
                value = '{ ' + value.slice(1, -1).trim().replace(/\s+/g, ' ') + ' }';
            }
            const mods = s.modifiers.map(m => text.slice(m.from, m.to).replace(/\s+/g, ''));
            line = ind(2) + s.id.padEnd(strWidth) + ' = ' + value + (mods.length ? ' ' + mods.join(' ') : '');
        }
        lines.push(line + (it.trail ? ' ' + it.trail : ''));
    }
    lines.push('}');
    return lines.join('\n');
}

function pushComment(lines, value, indent) {
    const parts = value.split('\n');
    lines.push(indent + parts[0].trim());
    for (const p of parts.slice(1)) lines.push(indent + ' ' + p.trim());
}

function formatCondition(text, rule, indent) {
    const from = rule.condition.from;
    const raw = text.slice(from, rule.closeBrace).replace(/\s+$/, '');
    const rawLines = raw.split('\n');
    const lineStart = text.lastIndexOf('\n', from - 1) + 1;
    const ownLine = text.slice(lineStart, from).trim() === '';
    const rest = rawLines.slice(1).filter(l => l.trim());
    const baseCol = ownLine ? from - lineStart : (rest.length ? Math.min(...rest.map(l => l.match(/^\s*/)[0].length)) : 0);
    const out = [indent + rawLines[0].trim()];
    for (const l of rawLines.slice(1)) {
        if (!l.trim()) { out.push(''); continue; }
        const col = l.replace(/\t/g, '    ').match(/^\s*/)[0].length;
        out.push(indent + ' '.repeat(Math.max(0, col - baseCol)) + l.trim());
    }
    return out;
}
