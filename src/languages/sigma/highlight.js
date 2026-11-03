/**
 * Incremental tokenizer of the Sigma pack (highlighting): one line at a time, with a small state
 * for block scalars (| and >) and conditions written over several lines.
 *
 *   top-level keys      section      title, logsource, detection…
 *   nested keys         property     category, selection, Image
 *   |modifier           modifier     |contains, |all
 *   condition words     keyword      and, or, not, 1 of, all of, them
 *   identifiers         variable     selection, filter_*
 *   status / level      atom
 *   tags                tag          attack.t1059
 */
import { MODIFIERS, STATUS, LEVEL } from './data.js';

const KEYWORDS = new Set(['and', 'or', 'not', 'of', 'them', 'all', 'any']);
const ATOMS = new Set(['true', 'false', 'null', 'yes', 'no', '~']);

export const stream = {
    startState() { return { block: null, cond: null, key: null, keyIndent: 0, afterKey: false, list: null }; },
    copyState(s) { return { ...s }; },

    token(stream, state) {
        if (stream.sol()) {
            const indent = stream.string.match(/^ */)[0].length;
            const blank = !stream.string.trim();
            // a block scalar continues while the lines are deeper than its key
            if (state.block !== null) {
                if (blank || indent > state.block) { stream.skipToEnd(); return blank ? null : 'string'; }
                state.block = null;
            }
            if (state.cond !== null && !blank && (indent <= state.cond || /^\s*[\w.|*-]+\s*:(\s|$)/.test(stream.string))) state.cond = null;
            state.afterKey = false;
            state.lineIndent = indent;
            if (state.list !== null && !blank && indent <= state.listIndent && !/^\s*-\s/.test(stream.string)) state.list = null;
        }
        if (stream.eatSpace()) return null;

        if (stream.sol() || stream.string.slice(0, stream.pos).trim() === '') {
            if (stream.match(/^(---|\.\.\.)\s*$/)) return 'meta';
        }
        if (stream.peek() === '#' && (stream.pos === 0 || /\s/.test(stream.string[stream.pos - 1]))) { stream.skipToEnd(); return 'comment'; }

        // a condition expression (on the condition: line or the lines below it)
        if (state.cond !== null && (state.afterKey || stream.string.slice(0, stream.pos).trim() === '' || state.inCond)) {
            state.inCond = true;
            return conditionToken(stream);
        }

        const before = stream.string.slice(0, stream.pos);
        const atLineStart = /^\s*(-\s+)*$/.test(before);
        if (atLineStart && stream.match(/^-(?=\s|$)/)) return 'punctuation';

        // key: at the start of the line (or after "- ")
        if (atLineStart && !state.afterKey) {
            const m = stream.match(/^((?:"[^"]*"|'[^']*'|[^\s:#][^:#]*?))(?=\s*:(\s|$))/, false);
            if (m) {
                const key = m[1];
                const indent = before.length;
                state.key = key.split('|')[0];
                state.keyIndent = indent;
                state.fullKey = key;
                if (indent === 0) { stream.match(key); state.pendingColon = true; return 'section'; }
                // Field|modifier|modifier: the field, then each modifier
                if (key.includes('|')) {
                    const field = key.split('|')[0];
                    if (field) { stream.match(field); state.modsLeft = true; return 'property'; }
                }
                stream.match(key);
                state.pendingColon = true;
                return 'property';
            }
        }
        if (state.modsLeft) {
            if (stream.match('|')) return 'operator';
            const m = stream.match(/^[^|:\s]+/);
            if (m) {
                if (stream.peek() !== '|') { state.modsLeft = false; state.pendingColon = true; }
                return MODIFIERS[m[0]] ? 'modifier' : 'invalid';
            }
            state.modsLeft = false;
        }
        if (state.pendingColon && stream.match(/^\s*:/)) {
            state.pendingColon = false;
            state.afterKey = true;
            const rest = stream.string.slice(stream.pos).trim();
            if (state.key === 'condition') { state.cond = state.keyIndent; state.inCond = false; }
            if (/^[|>][+-]?\d*$/.test(rest)) state.block = state.keyIndent;
            if (state.keyIndent === 0) { state.list = state.key; state.listIndent = 0; }
            return 'punctuation';
        }

        // values
        if (stream.match(/^[|>][+-]?\d*\s*$/)) return 'operator';
        if (stream.match(/^"(?:[^"\\]|\\.)*"?/) || stream.match(/^'(?:[^']|'')*'?/)) return valueKind(state, stream.current().slice(1, -1));
        if (stream.match(/^[\[\],{}]/)) return 'bracket';
        const m = stream.match(/^[^\s,\]#][^,\]#]*?(?=\s*(,|\]|\s#|$))/) || stream.match(/^\S+/);
        if (m) return valueKind(state, m[0]);
        stream.next();
        return null;
    },

    languageData: { commentTokens: { line: '#' } },
};

function valueKind(state, value) {
    const v = String(value).trim();
    if (state.key === 'status' && STATUS[v]) return 'atom';
    if (state.key === 'level' && LEVEL[v]) return 'atom';
    if ((state.key === 'tags' || state.list === 'tags') && /^[a-z0-9_-]+\./i.test(v)) return 'tag';
    if (ATOMS.has(v.toLowerCase())) return 'atom';
    if (/^-?\d+(\.\d+)?$/.test(v) || /^\d{4}[-/]\d{2}[-/]\d{2}$/.test(v)) return 'number';
    if (state.key === 'id' || /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(v)) return 'hex';
    return 'string';
}

function conditionToken(stream) {
    if (stream.match(/^[()]/)) return 'bracket';
    if (stream.match('|')) return 'invalid';
    const m = stream.match(/^[A-Za-z0-9_*.\-]+/);
    if (m) {
        const w = m[0].toLowerCase();
        if (KEYWORDS.has(w)) return 'keyword';
        if (/^\d+$/.test(w)) return 'number';
        return 'variable';
    }
    if (stream.match(/^["']/)) return 'punctuation';
    stream.next();
    return null;
}
