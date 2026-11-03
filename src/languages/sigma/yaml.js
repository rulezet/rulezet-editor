/**
 * A small, error-tolerant YAML reader for Sigma rules: block mappings and sequences, flow
 * sequences ([a, b]), plain / quoted scalars, block scalars (| and >), comments, several
 * documents (---). Every node keeps its offsets, which a general YAML library does not give.
 * It never throws: what it cannot read becomes an entry of `errors`.
 *
 * Nodes:
 *   { type: 'map', entries: [{ key, keyFrom, keyTo, value: node | null, from, to }], from, to }
 *   { type: 'seq', items: [node], from, to, flow?: true }
 *   { type: 'scalar', value, raw, quoted: '' | '"' | "'" | '|' | '>', from, to }
 * A key with nothing after it (`key:` and no block) has value null.
 */

/** Lines of one document: { from, to, indent, text (without the comment), col, blank }. */
function lines(text, from, to) {
    const out = [];
    let pos = from;
    while (pos <= to) {
        let end = text.indexOf('\n', pos);
        if (end === -1 || end > to) end = to;
        const raw = text.slice(pos, end).replace(/\r$/, '');
        const indent = raw.match(/^[ ]*/)[0].length;
        const body = stripComment(raw.slice(indent));
        out.push({ from: pos, to: pos + raw.length, indent, text: body.replace(/\s+$/, ''), col: pos + indent, raw, tab: /^ *\t/.test(raw) });
        if (end >= to) break;
        pos = end + 1;
    }
    return out;
}

/** The text before a comment (# after a space or at the start). A quote opens a string only at
 *  the start of a scalar: "a 'b' # c" is a plain value followed by a comment. */
function stripComment(s) {
    let q = null;
    let start = true;           // at the start of a scalar (line start, after ": ", "- ", "[" or ",")
    let flow = 0;
    for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (q) {
            if (c === q) {
                if (q === "'" && s[i + 1] === "'") { i++; continue; }
                q = null;
            } else if (c === '\\' && q === '"') i++;
            continue;
        }
        if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
        if (c === ' ' || c === '\t') continue;
        if (start) {
            start = false;
            if (c === '"' || c === "'") { q = c; continue; }
            if (c === '-' && /\s|$/.test(s[i + 1] || '')) { start = true; continue; }
            if (c === '[' || c === '{') { flow++; start = true; continue; }
        }
        if (c === ':' && /\s/.test(s[i + 1] || ' ')) { start = true; continue; }
        if (flow && (c === ',' || c === '[' || c === '{')) { if (c !== ',') flow++; start = true; continue; }
        if (flow && (c === ']' || c === '}')) flow--;
    }
    return s;
}

const isBlank = (l) => !l.text;

/** "key: value" at the start of s: { key, keyLen, rest, restOffset } or null. */
function splitKey(s) {
    let i = 0;
    let key;
    if (s[0] === '"' || s[0] === "'") {
        const q = s[0];
        i = 1;
        while (i < s.length && s[i] !== q) { if (q === '"' && s[i] === '\\') i++; i++; }
        if (i >= s.length) return null;
        key = s.slice(1, i);
        i++;
        if (s[i] !== ':') return null;
    } else {
        // a plain key ends at the first ": " or ":" at the end of the line
        const m = /^([^\s#\[\]{},"'][^#]*?)\s*:(?=\s|$)/.exec(s);
        if (!m || m[1].startsWith('- ') || m[1] === '-') return null;
        key = m[1];
        i = m[0].length - 1;
    }
    let j = i + 1;
    while (s[j] === ' ') j++;
    return { key, keyLen: s[0] === '"' || s[0] === "'" ? i : key.length, rest: s.slice(j), restOffset: j };
}

/** A scalar written on one line, starting at `from`. */
function scalar(raw, from) {
    const t = raw;
    if (t[0] === '"') {
        const end = findQuote(t, '"');
        const body = t.slice(1, end === -1 ? undefined : end);
        const value = body.replace(/\\(["\\\/bfnrt]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})/g, (_, e) => {
            const map = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
            if (map[e]) return map[e];
            if (e[0] === 'x' || e[0] === 'u') return String.fromCharCode(parseInt(e.slice(1), 16));
            return e;
        });
        return { type: 'scalar', value, raw: t, quoted: '"', from, to: from + t.length, unterminated: end === -1 };
    }
    if (t[0] === "'") {
        const end = findQuote(t, "'");
        const body = t.slice(1, end === -1 ? undefined : end);
        return { type: 'scalar', value: body.replace(/''/g, "'"), raw: t, quoted: "'", from, to: from + t.length, unterminated: end === -1 };
    }
    return { type: 'scalar', value: t, raw: t, quoted: '', from, to: from + t.length };
}

function findQuote(t, q) {
    for (let i = 1; i < t.length; i++) {
        if (q === '"' && t[i] === '\\') { i++; continue; }
        if (t[i] === q) {
            if (q === "'" && t[i + 1] === "'") { i++; continue; }
            return i;
        }
    }
    return -1;
}

/** [a, 'b', "c"] (one or several lines already joined): a seq node with offsets. */
function flowSeq(text, from, errors) {
    const items = [];
    let i = 1;
    let closed = false;
    while (i < text.length) {
        while (i < text.length && /[\s,]/.test(text[i])) i++;
        if (text[i] === ']') { closed = true; i++; break; }
        if (i >= text.length) break;
        let j = i;
        if (text[i] === '"' || text[i] === "'") {
            const end = findQuote(text.slice(i), text[i]);
            j = end === -1 ? text.length : i + end + 1;
        } else {
            while (j < text.length && text[j] !== ',' && text[j] !== ']') j++;
        }
        const raw = text.slice(i, j).replace(/\s+$/, '');
        if (raw) items.push(scalar(raw, from + i));
        i = j;
    }
    if (!closed) errors.push({ from, to: from + text.length, message: 'Unclosed [ list: add the ]' });
    return { type: 'seq', items, from, to: from + Math.min(i, text.length), flow: true };
}

class Reader {
    constructor(text, ls, errors) {
        this.text = text;
        this.ls = ls;
        this.errors = errors;
        this.i = 0;
    }

    skipBlank() {
        while (this.i < this.ls.length && isBlank(this.ls[this.i])) this.i++;
    }

    /** The block starting at the current line, whose lines are indented `indent`. */
    block(indent) {
        this.skipBlank();
        const l = this.ls[this.i];
        if (!l) return null;
        if (/^-(\s|$)/.test(l.text)) return this.seq(l.indent);
        return this.map(l.indent);
    }

    map(indent) {
        const entries = [];
        const start = this.ls[this.i].col;
        let end = start;
        while (true) {
            this.skipBlank();
            const l = this.ls[this.i];
            if (!l || l.indent < indent) break;
            if (l.tab) this.errors.push({ from: l.from, to: l.col + 1, message: 'Tabs are not allowed for indentation in YAML: use spaces' });
            if (l.indent > indent) {
                this.errors.push({ from: l.col, to: l.to, message: 'Unexpected indentation' });
                this.i++;
                continue;
            }
            if (/^-(\s|$)/.test(l.text)) {
                this.errors.push({ from: l.col, to: l.to, message: 'A list item where a "key: value" was expected' });
                this.i++;
                continue;
            }
            const kv = splitKey(l.text);
            if (!kv) {
                this.errors.push({ from: l.col, to: l.to, message: 'Expected "key: value"' });
                this.i++;
                continue;
            }
            const entry = { key: kv.key, keyFrom: l.col, keyTo: l.col + kv.keyLen, value: null, from: l.col, to: l.col + l.text.length, line: this.i };
            this.i++;
            const rest = kv.rest;
            const restFrom = l.col + kv.restOffset;
            if (!rest) {
                // a nested block (deeper, or a list at the same indentation)
                const save = this.i;
                this.skipBlank();
                const n = this.ls[this.i];
                if (n && n.indent > indent && !splitKey(n.text) && !/^-(\s|$)/.test(n.text) && n.text[0] !== '[') {
                    // the value starts on the next line ("condition:" then the expression below)
                    this.i++;
                    entry.value = this.plainMultiline(n.text, n.col, indent);
                    if (entry.value.unterminated) this.errors.push({ from: n.col, to: entry.value.to, message: 'Unterminated quoted string' });
                    entry.to = entry.value.to;
                } else if (n && (n.indent > indent || (n.indent === indent && /^-(\s|$)/.test(n.text)))) {
                    entry.value = n.indent === indent ? this.seq(indent) : this.block(n.indent);
                    if (entry.value) entry.to = entry.value.to;
                } else this.i = save;
            } else if (/^[|>][+-]?\d*$/.test(rest)) {
                entry.value = this.blockScalar(indent, rest, restFrom);
                entry.to = entry.value.to;
            } else if (rest[0] === '[') {
                entry.value = this.flow(rest, restFrom, indent);
                entry.to = entry.value.to;
            } else if (rest[0] === '{') {
                this.errors.push({ from: restFrom, to: restFrom + rest.length, message: 'Inline { } mappings are not supported here: write one "key: value" per line' });
                entry.value = scalar(rest, restFrom);
            } else {
                entry.value = this.plainMultiline(rest, restFrom, indent);
                if (entry.value.unterminated) this.errors.push({ from: restFrom, to: entry.value.to, message: 'Unterminated quoted string' });
                entry.to = entry.value.to;
            }
            end = entry.to;
            entries.push(entry);
        }
        return { type: 'map', entries, from: start, to: end };
    }

    seq(indent) {
        const items = [];
        const start = this.ls[this.i].col;
        let end = start;
        while (true) {
            this.skipBlank();
            const l = this.ls[this.i];
            if (!l || l.indent !== indent || !/^-(\s|$)/.test(l.text)) {
                if (l && l.indent > indent) {
                    this.errors.push({ from: l.col, to: l.to, message: 'Unexpected indentation' });
                    this.i++;
                    continue;
                }
                break;
            }
            const m = /^-(\s+)/.exec(l.text);
            const offset = m ? 1 + m[1].length : 1;
            const rest = l.text.slice(offset);
            const restFrom = l.col + offset;
            let item;
            if (!rest) {
                this.i++;
                this.skipBlank();
                const n = this.ls[this.i];
                item = n && n.indent > indent ? this.block(n.indent) : { type: 'scalar', value: null, raw: '', quoted: '', from: restFrom, to: restFrom };
            } else if (splitKey(rest)) {
                // "- key: value": a mapping whose first line shares the dash's line
                const virtualIndent = l.indent + offset;
                this.ls[this.i] = { ...l, indent: virtualIndent, text: rest, col: restFrom };
                item = this.map(virtualIndent);
            } else if (rest[0] === '[') {
                this.i++;
                item = this.flow(rest, restFrom, indent);
            } else if (/^[|>][+-]?\d*$/.test(rest)) {
                this.i++;
                item = this.blockScalar(indent, rest, restFrom);
            } else {
                this.i++;
                item = this.plainMultiline(rest, restFrom, indent);
                if (item.unterminated) this.errors.push({ from: restFrom, to: item.to, message: 'Unterminated quoted string' });
            }
            if (item) { items.push(item); end = item.to; }
        }
        return { type: 'seq', items, from: start, to: end };
    }

    /** A plain or quoted value, continued on deeper lines (YAML folds them with spaces). */
    plainMultiline(rest, restFrom, indent) {
        const node = scalar(rest, restFrom);
        if (node.quoted && !node.unterminated) return node;
        // continuation lines: deeper indentation, not a key, not a list item
        const parts = [node.quoted ? node.raw : rest];
        let to = node.to;
        while (this.i < this.ls.length) {
            const n = this.ls[this.i];
            if (isBlank(n) || n.indent <= indent) break;
            if (!node.quoted && splitKey(n.text)) break;      // deeper "- x" lines continue a plain value, as in YAML
            parts.push(n.text);
            to = n.col + n.text.length;
            this.i++;
        }
        if (parts.length === 1) return node;
        const joined = parts.join(' ');
        const full = scalar(joined, restFrom);
        return { ...full, to, multiline: true };
    }

    blockScalar(indent, header, from) {
        const parts = [];
        let to = from + header.length;
        let inner = null;
        while (this.i < this.ls.length) {
            const n = this.ls[this.i];
            if (n.raw.trim() && n.indent <= indent) break;
            if (n.raw.trim()) {
                inner = inner === null ? n.indent : Math.min(inner, n.indent);
                to = n.to;
            }
            parts.push(n.raw);
            this.i++;
        }
        while (parts.length && !parts[parts.length - 1].trim()) parts.pop();
        const body = parts.map(p => p.slice(inner || 0)).join('\n');
        const value = header[0] === '>' ? body.replace(/([^\n])\n(?=[^\n ])/g, '$1 ') : body;
        // chomping, as YAML: clip (default) keeps one final newline, - strips it, + keeps them all
        const chomp = header.includes('-') ? '' : '\n';
        return { type: 'scalar', value: body ? value + chomp : value, raw: header, quoted: header[0], from, to };
    }

    flow(rest, restFrom, indent) {
        // a [ list spread over several lines: joined until the ]
        let text = rest;
        let to = restFrom + rest.length;
        if (!/\]\s*$/.test(rest)) {
            while (this.i < this.ls.length) {
                const n = this.ls[this.i];
                if (n.indent <= indent && n.text) break;
                text += ' '.repeat(Math.max(1, n.col - to)) + n.text;
                to = n.col + n.text.length;
                this.i++;
                if (/\]\s*$/.test(n.text)) break;
            }
        }
        const node = flowSeq(text, restFrom, this.errors);
        // offsets inside a joined multi-line list are approximate: keep them inside the list
        for (const it of node.items) { it.from = Math.min(it.from, to); it.to = Math.min(it.to, to); }
        node.to = to;
        return node;
    }
}

/** The documents of a text: [{ from, to, root, errors, empty }], split on --- lines. */
export function parseYaml(text) {
    const docs = [];
    const sep = /^(---|\.\.\.)[ \t]*(#.*)?$/gm;
    let start = 0;
    const cuts = [];
    let m;
    while ((m = sep.exec(text))) cuts.push({ from: m.index, to: m.index + m[0].length });
    const ranges = [];
    for (const c of cuts) {
        ranges.push({ from: start, to: c.from });
        start = Math.min(text.length, c.to + 1);
    }
    ranges.push({ from: start, to: text.length });
    for (const r of ranges) {
        const errors = [];
        const ls = lines(text, r.from, r.to);
        const reader = new Reader(text, ls, errors);
        reader.skipBlank();
        let root = null;
        if (reader.i < ls.length) {
            const first = ls[reader.i];
            if (first.indent > 0) errors.push({ from: first.col, to: first.to, message: 'The rule must start at the left margin (no indentation)' });
            root = reader.block(first.indent);
            reader.skipBlank();
            while (reader.i < ls.length) {
                const l = ls[reader.i];
                errors.push({ from: l.col, to: l.to, message: 'Unexpected text: wrong indentation?' });
                reader.i++;
                reader.skipBlank();
            }
        }
        // a document ends where its last non-blank line ends
        let to = r.from;
        for (const l of ls) if (l.raw.trim()) to = l.to;
        const firstLine = ls.find(l => l.raw.trim() && !/^\s*#/.test(l.raw));
        docs.push({ from: firstLine ? firstLine.from : r.from, to: Math.max(to, firstLine ? firstLine.from : r.from), root, errors, empty: !root });
    }
    return docs;
}

/** The entry `key` of a map node (exact key), or null. */
export function entry(node, key) {
    if (!node || node.type !== 'map') return null;
    return node.entries.find(e => e.key === key) || null;
}

/** A scalar node's value as a string ('' for anything else). */
export function str(node) {
    return node && node.type === 'scalar' && node.value != null ? String(node.value) : '';
}

/** The scalars of a node: itself, or the items of a list (nested lists flattened). */
export function scalars(node) {
    if (!node) return [];
    if (node.type === 'scalar') return [node];
    if (node.type === 'seq') return node.items.flatMap(scalars);
    return [];
}

/** A value written as YAML: quoted when a plain scalar would read differently. */
export function yamlValue(value) {
    const s = String(value ?? '');
    if (s === '') return "''";
    const plainOk = /^[^\s'"#&*!|>%@`{}\[\],?:-][^#]*$/.test(s) && !/:\s|\s#|\s$/.test(s)
        && !/^(true|false|yes|no|on|off|null|~|[-+]?\d[\d_.eE+-]*)$/i.test(s);
    return plainOk ? s : `'${s.replace(/'/g, "''")}'`;
}
