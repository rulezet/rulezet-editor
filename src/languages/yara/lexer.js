/**
 * YARA lexer: turns a whole document into tokens with offsets.
 * Used by the parser, the linter, the formatter and the completion
 * context. Highlighting uses the incremental tokenizer in highlight.js.
 */

export const T = {
    IDENT: 'ident',
    STRING_ID: 'string_id',   // $a  $a*  $
    COUNT: 'count',           // #a
    OFFSET: 'offset',         // @a
    LENGTH: 'length',         // !a
    TEXT: 'text',             // "..."
    HEX: 'hex',               // { 4D 5A }
    REGEX: 'regex',           // /abc/is
    NUMBER: 'number',
    PUNCT: 'punct',
    COMMENT: 'comment',
    INVALID: 'invalid',
};

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z0-9_]/;
const PUNCTS = ['..', '==', '!=', '<=', '>=', '<<', '>>', '{', '}', '(', ')', '[', ']', ':', '=', ',', '.',
    '<', '>', '+', '-', '*', '\\', '%', '&', '|', '^', '~'];

/**
 * @returns {{tokens: Array<{type, value, from, to}>, comments: Array, errors: Array}}
 */
export function lex(text) {
    const tokens = [];
    const comments = [];
    const errors = [];
    const n = text.length;
    let i = 0;
    let prev = null;          // last significant token

    const push = (type, from, to, extra) => {
        const tok = { type, value: text.slice(from, to), from, to, ...extra };
        if (type === T.COMMENT) comments.push(tok);
        else { tokens.push(tok); prev = tok; }
        return tok;
    };

    while (i < n) {
        const c = text[i];

        if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f' || c === '\v') { i++; continue; }

        // comments
        if (c === '/' && text[i + 1] === '/') {
            let j = i + 2;
            while (j < n && text[j] !== '\n') j++;
            push(T.COMMENT, i, j, { block: false });
            i = j;
            continue;
        }
        if (c === '/' && text[i + 1] === '*') {
            const end = text.indexOf('*/', i + 2);
            const j = end === -1 ? n : end + 2;
            if (end === -1) errors.push({ from: i, to: Math.min(n, i + 2), message: 'Unterminated block comment' });
            push(T.COMMENT, i, j, { block: true });
            i = j;
            continue;
        }

        // text string
        if (c === '"') {
            let j = i + 1;
            let closed = false;
            while (j < n) {
                if (text[j] === '\\') { j += 2; continue; }
                if (text[j] === '"') { closed = true; j++; break; }
                if (text[j] === '\n') break;
                j++;
            }
            if (!closed) errors.push({ from: i, to: j, message: 'Unterminated string' });
            push(T.TEXT, i, Math.min(j, n), { closed });
            i = Math.min(j, n);
            continue;
        }

        // hex string: "{" right after "=" (strings section)
        if (c === '{' && prev && prev.type === T.PUNCT && prev.value === '=') {
            const end = text.indexOf('}', i + 1);
            const j = end === -1 ? n : end + 1;
            if (end === -1) errors.push({ from: i, to: i + 1, message: 'Unterminated hex string' });
            push(T.HEX, i, j, { closed: end !== -1 });
            i = j;
            continue;
        }

        // regular expression: YARA has no "/" operator, so "/" always opens one
        if (c === '/') {
            let j = i + 1;
            let closed = false;
            let inClass = false;
            while (j < n && text[j] !== '\n') {
                const d = text[j];
                if (d === '\\') { j += 2; continue; }
                if (d === '[') inClass = true;
                else if (d === ']') inClass = false;
                else if (d === '/' && !inClass) { closed = true; j++; break; }
                j++;
            }
            if (closed) while (j < n && /[is]/.test(text[j])) j++;
            else errors.push({ from: i, to: j, message: 'Unterminated regular expression' });
            push(T.REGEX, i, Math.min(j, n), { closed });
            i = Math.min(j, n);
            continue;
        }

        // $a  $a*  $   #a  @a  !a
        if (c === '$' || c === '#' || c === '@' || (c === '!' && IDENT_START.test(text[i + 1] || ''))) {
            let j = i + 1;
            while (j < n && IDENT_PART.test(text[j])) j++;
            let wildcard = false;
            if (c === '$' && text[j] === '*') { wildcard = true; j++; }
            const type = c === '$' ? T.STRING_ID : c === '#' ? T.COUNT : c === '@' ? T.OFFSET : T.LENGTH;
            push(type, i, j, { name: text.slice(i + 1, wildcard ? j - 1 : j), wildcard });
            i = j;
            continue;
        }

        // numbers: 0x1F, 0o17, 10, 1.5, 10KB, 2MB
        if (/[0-9]/.test(c)) {
            let j = i;
            if (c === '0' && (text[i + 1] === 'x' || text[i + 1] === 'X')) {
                j += 2;
                while (j < n && /[0-9a-fA-F]/.test(text[j])) j++;
            } else if (c === '0' && text[i + 1] === 'o') {
                j += 2;
                while (j < n && /[0-7]/.test(text[j])) j++;
            } else {
                while (j < n && /[0-9]/.test(text[j])) j++;
                if (text[j] === '.' && /[0-9]/.test(text[j + 1] || '')) {
                    j++;
                    while (j < n && /[0-9]/.test(text[j])) j++;
                }
                if (text.startsWith('KB', j) || text.startsWith('MB', j)) j += 2;
            }
            if (j < n && IDENT_PART.test(text[j])) {
                let k = j;
                while (k < n && IDENT_PART.test(text[k])) k++;
                errors.push({ from: i, to: k, message: `Invalid number or identifier "${text.slice(i, k)}"` });
                push(T.INVALID, i, k);
                i = k;
                continue;
            }
            push(T.NUMBER, i, j);
            i = j;
            continue;
        }

        if (IDENT_START.test(c)) {
            let j = i + 1;
            while (j < n && IDENT_PART.test(text[j])) j++;
            push(T.IDENT, i, j);
            i = j;
            continue;
        }

        const p = PUNCTS.find(s => text.startsWith(s, i));
        if (p) {
            push(T.PUNCT, i, i + p.length);
            i += p.length;
            continue;
        }

        errors.push({ from: i, to: i + 1, message: `Unexpected character "${c}"` });
        push(T.INVALID, i, i + 1);
        i++;
    }
    return { tokens, comments, errors };
}
