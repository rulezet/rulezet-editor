/**
 * Incremental YARA tokenizer for highlighting. Engine-neutral: works on any
 * stream with match / next / peek / eat / eatWhile / skipToEnd / eol / sol
 * (CodeMirror's StringStream is one). Returns token kinds from the shared
 * vocabulary of rulezet-editor (see src/core/tokens.js).
 */
import { CONDITION_KEYWORDS, MODIFIERS, SECTIONS, RULE_KEYWORDS } from './keywords.js';
import { MODULES } from './modules.js';

const BUILTINS = new Set(Object.keys(CONDITION_KEYWORDS).filter(k => /int\d/.test(k)));

export const stream = {
    name: 'yara',

    startState() {
        return { comment: false, hex: false, section: null, expect: null, lastSig: '', inRule: false, afterDot: false };
    },

    copyState(s) { return { ...s }; },

    token(stream, state) {
        if (state.comment) {
            if (stream.match(/^.*?\*\//)) state.comment = false;
            else stream.skipToEnd();
            return 'comment';
        }
        if (state.hex) return hexToken(stream, state);

        if (stream.eatSpace()) return null;

        if (stream.match('//')) { stream.skipToEnd(); return 'comment'; }
        if (stream.match('/*')) {
            if (!stream.match(/^.*?\*\//)) { stream.skipToEnd(); state.comment = true; }
            return 'comment';
        }

        const set = (kind, sig) => { state.lastSig = sig ?? stream.current(); state.afterDot = false; return kind; };

        if (stream.peek() === '"') {
            stream.next();
            let escaped = false;
            let ch;
            while ((ch = stream.next()) != null) {
                if (ch === '"' && !escaped) break;
                escaped = !escaped && ch === '\\';
            }
            if (state.expect === 'import') { state.expect = null; return set('module', '"'); }
            return set('string', '"');
        }

        if (stream.peek() === '{' && state.lastSig === '=') {
            stream.next();
            state.hex = true;
            state.lastSig = '{';
            return 'hex';
        }

        if (stream.peek() === '/') {
            stream.next();
            let inClass = false;
            let ch;
            while ((ch = stream.next()) != null) {
                if (ch === '\\') { stream.next(); continue; }
                if (ch === '[') inClass = true;
                else if (ch === ']') inClass = false;
                else if (ch === '/' && !inClass) { stream.match(/^[is]*/); break; }
            }
            return set('regexp', '/');
        }

        if (stream.match(/^[$#@!][A-Za-z0-9_]*\*?/)) {
            const cur = stream.current();
            if (cur === '!') return set('operator');
            return set('variable', '$');
        }

        if (stream.match(/^0x[0-9a-fA-F]+|^0o[0-7]+|^\d+(\.\d+)?(KB|MB)?/)) return set('number');

        if (stream.match(/^[A-Za-z_][A-Za-z0-9_]*/)) {
            const w = stream.current();
            if (state.afterDot) { state.afterDot = false; state.lastSig = w; return stream.peek() === '(' ? 'function' : 'property'; }
            if (state.expect === 'name') { state.expect = 'tags'; state.lastSig = w; return 'definition'; }
            if (state.expect === 'tags' && state.lastSig !== '{') {
                if (state.tagMode) { state.lastSig = w; return 'tag'; }
            }
            if (w === 'rule') { state.expect = 'name'; state.section = null; return set('keyword'); }
            if (w === 'import' || w === 'include') { state.expect = 'import'; return set('keyword'); }
            if (RULE_KEYWORDS[w]) return set('keyword');
            if (SECTIONS[w] && stream.match(/^\s*:/, false)) { state.section = w; return set('section'); }
            if (state.section === 'meta' && stream.match(/^\s*=/, false)) return set('property');
            if (state.section === 'strings' && MODIFIERS[w]) return set('modifier');
            if (w === 'true' || w === 'false') return set('atom');
            if (BUILTINS.has(w)) return set('function');
            if (CONDITION_KEYWORDS[w]) return set('keyword');
            if (MODULES[w] && stream.match(/^\s*[.[]/, false)) return set('module');
            return set('name');
        }

        const ch = stream.next();
        if (ch === ':' && state.expect === 'tags') { state.tagMode = true; state.lastSig = ':'; return 'operator'; }
        if (ch === '{') { state.expect = null; state.tagMode = false; state.inRule = true; return set('bracket'); }
        if (ch === '}') { state.inRule = false; state.section = null; return set('bracket'); }
        if (ch === '.') {
            if (stream.eat('.')) return set('operator');
            state.lastSig = '.';
            state.afterDot = true;
            return 'operator';
        }
        if ('()[]'.includes(ch)) return set('bracket');
        if ('=<>!'.includes(ch)) {
            const two = stream.eat('=');
            return set('operator', ch === '=' && !two ? '=' : 'op');
        }
        return set('operator');
    },

    languageData: {
        commentTokens: { line: '//', block: { open: '/*', close: '*/' } },
        closeBrackets: { brackets: ['(', '[', '{', '"'] },
        indentOnInput: /^\s*(\}|meta:|strings:|condition:)$/,
    },
};

function hexToken(stream, state) {
    if (stream.eatSpace()) return null;
    if (stream.match('//')) { stream.skipToEnd(); return 'comment'; }
    if (stream.match(/^\/\*.*?\*\//)) return 'comment';
    if (stream.eat('}')) { state.hex = false; state.lastSig = '}'; return 'hex'; }
    if (stream.match(/^\[[^\]\n]*\]?/)) return 'hexJump';
    if (stream.match(/^[?]{2}|^[0-9a-fA-F]\?|^\?[0-9a-fA-F]/)) return 'hexWildcard';
    if (stream.match(/^~?[0-9a-fA-F]{2}/)) return 'hex';
    if (stream.match(/^[()|]/)) return 'hexJump';
    stream.next();
    return 'invalid';
}
