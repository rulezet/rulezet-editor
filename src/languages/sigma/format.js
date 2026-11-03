/**
 * Sigma formatter (Shift+Alt+F), after the SigmaHQ conventions: 4-space indentation (list items
 * indented under their key), top-level keys in the specification's order, no trailing spaces,
 * one blank-free "---" between rules, a final newline. Values, comments and quoting are kept as
 * written: only indentation, line order of top-level blocks and separators change. A rule with a
 * YAML error is left untouched (its name goes to `skipped`). Idempotent.
 */
import { TOP_KEYS } from './data.js';

const ORDER = TOP_KEYS.map(k => k.key);
const UNIT = '    ';

/** Re-indents one document's lines: each indentation level becomes 4 spaces deeper than its parent.
 *  Block scalar contents are put back afterwards (fixBlockScalars). */
function reindent(lines) {
    const out = [];
    const stack = [];            // [{ old, nu }] open indentation levels
    for (const raw of lines) {
        const line = raw.replace(/\s+$/, '');
        if (!line.trim()) { out.push(''); continue; }
        const old = line.match(/^ */)[0].length;
        const body = line.slice(old);
        // a comment line does not open or close a level: it takes the indentation of the next line
        if (body.startsWith('#')) { out.push({ comment: body }); continue; }
        while (stack.length && stack[stack.length - 1].old > old) stack.pop();
        let nu;
        if (!stack.length || old === 0) { stack.length = 0; nu = 0; stack.push({ old: 0, nu: 0 }); }
        else if (stack[stack.length - 1].old === old) nu = stack[stack.length - 1].nu;
        else { nu = stack[stack.length - 1].nu + UNIT.length; stack.push({ old, nu }); }
        // "- key: v": the item's own content column is a level of its own ("- " = 2 columns)
        const dash = /^-(\s+)(?=\S)/.exec(body);
        if (dash) {
            out.push(' '.repeat(nu) + '- ' + body.slice(dash[0].length));
            stack.push({ old: old + dash[0].length, nu: nu + 2 });
        } else out.push(' '.repeat(nu) + body);
    }
    for (let i = out.length - 1, next = ''; i >= 0; i--) {
        if (typeof out[i] === 'object') out[i] = next + out[i].comment;
        else if (out[i].trim()) next = out[i].match(/^ */)[0];
    }
    return out;
}

/** "key:\n- a" (list at the key's indentation) -> "key:\n    - a"; then re-indented as a whole. */
function indentLists(lines) {
    const out = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        out.push(line);
        if (/:\s*[|>][+-]?\d*\s*(#.*)?$/.test(line)) {
            // a block scalar: its text is not YAML structure, copied as is
            const ind = line.match(/^ */)[0].length;
            while (i + 1 < lines.length && (!lines[i + 1].trim() || lines[i + 1].match(/^ */)[0].length > ind)) out.push(lines[++i]);
            continue;
        }
        const m = /^( *)([^\s#-][^#]*?):\s*(#.*)?$/.exec(line);
        if (!m) continue;
        const ind = m[1].length;
        let j = i + 1;
        while (j < lines.length && (!lines[j].trim() || lines[j].match(/^ */)[0].length === ind && /^ *-(\s|$)/.test(lines[j]))) {
            if (!lines[j].trim()) break;
            out.push(UNIT + lines[j]);
            // the continuation lines of that item (deeper than its dash) move with it
            let k = j + 1;
            while (k < lines.length && lines[k].trim() && lines[k].match(/^ */)[0].length > ind) { out.push(UNIT + lines[k]); k++; }
            j = k;
        }
        i = j - 1;
    }
    return out;
}

/** Block scalar contents keep their relative indentation (reindent() moved their first line only). */
function fixBlockScalars(src, dst) {
    const out = dst.slice();
    for (let i = 0; i < src.length; i++) {
        if (!/:\s*[|>][+-]?\d*\s*(#.*)?$/.test(src[i])) continue;
        const keyOld = src[i].match(/^ */)[0].length;
        const keyNew = out[i].match(/^ */)[0].length;
        let inner = null;
        for (let j = i + 1; j < src.length; j++) {
            if (src[j].trim() && src[j].match(/^ */)[0].length <= keyOld) break;
            if (!src[j].trim()) continue;
            const ind = src[j].match(/^ */)[0].length;
            if (inner === null) inner = ind;
            // a block scalar's text is kept exactly, trailing spaces included (they are part of the value)
            out[j] = ' '.repeat(keyNew + UNIT.length + Math.max(0, ind - inner)) + src[j].trimStart();
        }
    }
    return out;
}

/** Top-level blocks (a key line + its deeper / blank lines), with the comments just above each. */
function topBlocks(lines) {
    const blocks = [];
    let pending = [];
    for (const line of lines) {
        if (/^\S/.test(line) && !/^#/.test(line)) {
            const key = (/^([^:#]+?)\s*:/.exec(line) || [])[1] || '';
            blocks.push({ key, lines: [...pending, line] });
            pending = [];
        } else if (/^#/.test(line) || (!line.trim() && !blocks.length)) {
            pending.push(line);
        } else if (blocks.length) {
            blocks[blocks.length - 1].lines.push(line);
        } else pending.push(line);
    }
    return { blocks, tail: pending };
}

function formatDoc(text) {
    let lines = text.replace(/\r\n/g, '\n').split('\n');
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    while (lines.length && !lines[0].trim()) lines.shift();
    const src = indentLists(lines);
    let out = fixBlockScalars(src, reindent(src));
    // top-level keys in the specification's order (unknown keys keep their place after known ones)
    const { blocks, tail } = topBlocks(out);
    const rank = (k) => { const i = ORDER.indexOf(k); return i === -1 ? ORDER.length : i; };
    const sorted = blocks.map((b, i) => ({ ...b, i })).sort((a, b) => rank(a.key) - rank(b.key) || a.i - b.i);
    out = [];
    for (const b of sorted) {
        const ls = b.lines.slice();
        while (ls.length > 1 && !ls[ls.length - 1].trim()) ls.pop();          // blank lines between keys go
        out.push(...ls);
    }
    out.push(...tail.filter(l => l.trim()));
    return out.join('\n');
}

export function format(model) {
    const text = model.text;
    if (!model.rules.length) return { text, formatted: false, skipped: [] };
    const skipped = [];
    const parts = [];
    let pos = 0;
    // keep what comes before the first rule (comments) and split on the rules' own ranges
    const head = text.slice(0, model.rules[0].from).replace(/^(---|\.\.\.)\s*$/gm, '').trim();
    for (const r of model.rules) {
        const piece = text.slice(r.from, r.to);
        if (r.yamlErrors.length || !r.root) { skipped.push(r.name); parts.push(piece.replace(/\s+$/, '')); }
        else parts.push(formatDoc(piece));
        pos = r.to;
    }
    const after = text.slice(pos).replace(/^\s*(---|\.\.\.)?\s*$/gm, '').trim();
    const result = (head ? head + '\n' : '') + parts.join('\n---\n') + (after ? '\n' + after : '') + '\n';
    return { text: result, formatted: result !== text, skipped };
}
