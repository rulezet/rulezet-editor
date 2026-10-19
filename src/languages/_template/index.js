/**
 * Template for a new language pack. Copy this folder to src/languages/<id>/,
 * then fill in what your format needs. Only `id` and `name` are required:
 * each extra field or function switches a feature on.
 *
 * Rules: no network, no DOM, no editor engine import. Pure data + functions.
 * Full reference: docs/language-pack.md
 */

const KEYWORDS = ['example', 'keyword'];

export default {
    id: 'template',            // unique, lower case
    name: 'Template',          // shown in the UI
    version: '0.1.0',
    maturity: 'basic',         // basic | standard | full
    extensions: ['.tpl'],
    validateAs: 'template',    // format name the host's validate() expects

    /** 0..1: how sure we are that `text` is this format (used by language: 'auto'). */
    detect(text) {
        return /^\s*example\b/m.test(text) ? 0.6 : 0;
    },

    /** Highlighting: an incremental tokenizer returning token kinds (see src/core/tokens.js). */
    stream: {
        startState: () => ({}),
        token(stream) {
            if (stream.eatSpace()) return null;
            if (stream.match('#')) { stream.skipToEnd(); return 'comment'; }
            if (stream.match(/^"(?:[^"\\]|\\.)*"?/)) return 'string';
            if (stream.match(/^\d+/)) return 'number';
            if (stream.match(/^[A-Za-z_]\w*/)) return KEYWORDS.includes(stream.current()) ? 'keyword' : 'name';
            stream.next();
            return 'operator';
        },
        languageData: { commentTokens: { line: '#' } },
    },

    snippets: [
        { label: 'example', type: 'snippet', snippet: 'example "${name}"' },
    ],

    /** Parse once per change; every other function receives this model. Must not throw. */
    parse(text) {
        return { text, rules: [], errors: [] };
    },

    /** [{ from, to, severity: 'error'|'warning'|'info', message, code, fixes?: [{ label, changes: [{from,to,insert}] }] }] */
    lint(model) {
        return [];
    },

    /** ctx: { text, pos, parsed, explicit } -> { from, options: [{ label, type, detail, info, apply?, snippet? }] } | null */
    complete(ctx) {
        const word = ctx.text.slice(0, ctx.pos).match(/\w*$/)[0];
        if (!word && !ctx.explicit) return null;
        return { from: ctx.pos - word.length, options: KEYWORDS.map(k => ({ label: k, type: 'keyword' })) };
    },

    // Optional, uncomment when ready:
    // hover(ctx)      -> { from, to, title, body, code? } | null
    // definition(ctx) -> { from, to } | null
    // references(ctx) -> { kind, name, ranges: [{from,to}] } | null
    // rename(ctx, newName) -> { changes } | { error }
    // format(model, options) -> { text, formatted, skipped }
    // splitRules(model) -> [{ name, from, to, kind, tags, detail, text, children }]
    // folding(model) -> [{ from, to }]
};
