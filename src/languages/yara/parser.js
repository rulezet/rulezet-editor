/**
 * Error-tolerant YARA parser. Gives the structure of every rule of a
 * document (offsets included) and keeps going after an error, so one
 * broken rule never hides the others.
 */
import { lex, T } from './lexer.js';
import { MODIFIERS, RESERVED } from './keywords.js';
import { checkCondition } from './condition.js';

const SECTION_NAMES = new Set(['meta', 'strings', 'condition']);

export function parse(text) {
    const { tokens, comments, errors: lexErrors } = lex(text);
    const errors = [...lexErrors];
    const imports = [];
    const includes = [];
    const rules = [];
    let i = 0;

    const tok = (k = 0) => tokens[i + k];
    const isIdent = (t, value) => t && t.type === T.IDENT && (value === undefined || t.value === value);
    const isPunct = (t, value) => t && t.type === T.PUNCT && t.value === value;
    const err = (from, to, message, extra) => errors.push({ from, to, message, ...extra });
    const startsRule = (k = 0) => {
        let j = k;
        while (isIdent(tok(j), 'private') || isIdent(tok(j), 'global')) j++;
        return isIdent(tok(j), 'rule');
    };
    const atTopLevelStart = () => startsRule() || isIdent(tok(), 'import') || isIdent(tok(), 'include');

    let garbageReported = false;
    while (i < tokens.length) {
        const t = tok();
        if (isIdent(t, 'import') || isIdent(t, 'include')) {
            const arg = tok(1);
            if (arg && arg.type === T.TEXT) {
                const entry = { name: arg.value.slice(1, -1), from: t.from, to: arg.to, nameFrom: arg.from + 1, nameTo: arg.to - 1 };
                (t.value === 'import' ? imports : includes).push(entry);
                i += 2;
            } else {
                err(t.from, t.to, `${t.value} needs a quoted name: ${t.value} "${t.value === 'import' ? 'pe' : 'file.yar'}"`);
                i += 1;
            }
            garbageReported = false;
            continue;
        }
        if (startsRule()) {
            rules.push(parseRule());
            garbageReported = false;
            continue;
        }
        if (!garbageReported) {
            err(t.from, t.to, `Unexpected "${t.value}": expected rule, import or include`);
            garbageReported = true;
        }
        i++;
    }

    function parseRule() {
        const start = tok();
        const rule = {
            name: '', nameFrom: start.from, nameTo: start.to,
            from: start.from, to: start.to,
            modifiers: [], tags: [], meta: [], strings: [],
            sections: {}, condition: null,
            openBrace: null, closeBrace: null, errors: [],
        };
        const ruleErr = (from, to, message, extra) => {
            const e = { from, to, message, ...extra };
            errors.push(e);
            rule.errors.push(e);
        };

        while (isIdent(tok(), 'private') || isIdent(tok(), 'global')) {
            rule.modifiers.push(tok().value);
            i++;
        }
        const kw = tok();
        i++;                       // "rule"
        rule.to = kw.to;
        const name = tok();
        if (!name || name.type !== T.IDENT) {
            ruleErr(kw.from, kw.to, 'Rule name expected after "rule"');
        } else {
            rule.name = name.value;
            rule.nameFrom = name.from;
            rule.nameTo = name.to;
            rule.to = name.to;
            if (RESERVED.has(name.value)) ruleErr(name.from, name.to, `"${name.value}" is a reserved keyword and cannot be a rule name`);
            if (name.value.length > 128) ruleErr(name.from, name.to, 'Rule name longer than 128 characters');
            i++;
        }

        if (isPunct(tok(), ':')) {
            i++;
            while (isIdent(tok()) && !isPunct(tok(), '{')) {
                rule.tags.push({ name: tok().value, from: tok().from, to: tok().to });
                rule.to = tok().to;
                i++;
            }
            if (!rule.tags.length) ruleErr(tokens[i - 1].from, tokens[i - 1].to, 'Tag expected after ":"');
        }

        if (!isPunct(tok(), '{')) {
            const at = tok() || tokens[i - 1];
            ruleErr(at.from, at.to, 'Expected "{" to open the rule body');
            // try to recover: skip to the next "{" before another rule starts
            while (tok() && !isPunct(tok(), '{') && !atTopLevelStart()) i++;
            if (!isPunct(tok(), '{')) return rule;
        }
        rule.openBrace = tok().from;
        i++;

        let current = null;
        let closed = false;
        while (i < tokens.length) {
            const t = tok();
            if (isPunct(t, '}')) {
                rule.closeBrace = t.from;
                rule.to = t.to;
                i++;
                closed = true;
                break;
            }
            if (atTopLevelStart()) {
                // a new rule or import starts: this rule never closed
                break;
            }
            if (isIdent(t) && SECTION_NAMES.has(t.value) && isPunct(tok(1), ':')) {
                if (rule.sections[t.value]) ruleErr(t.from, t.to, `Duplicate "${t.value}:" section`);
                current = t.value;
                rule.sections[current] = { from: t.from, to: tok(1).to, bodyFrom: tok(1).to };
                i += 2;
                if (current === 'condition') parseCondition();
                else if (current === 'meta') parseMeta();
                else parseStrings();
                if (current !== 'condition' && (current === 'meta' ? !rule.meta.length : !rule.strings.length)) {
                    const sec = rule.sections[current];
                    ruleErr(sec.from, sec.to, `Empty "${current}:" section: add ${current === 'meta' ? 'a key = value' : 'a string'} or remove it`, { code: 'empty-section' });
                }
                continue;
            }
            ruleErr(t.from, t.to, current
                ? `Unexpected "${t.value}" in ${current} section`
                : `Unexpected "${t.value}": expected meta:, strings: or condition:`);
            skipToRecovery();
        }

        if (!closed) {
            const last = tokens[i - 1];
            rule.to = last ? last.to : rule.to;
            const at = Math.max(rule.nameFrom, rule.to - 1);
            ruleErr(at, rule.to, `Rule "${rule.name}" is not closed: missing "}"`, { fix: { insertAt: rule.to, text: '\n}' } });
        }
        for (const sec of Object.values(rule.sections)) {
            sec.bodyTo = sec.bodyTo ?? rule.to;
        }
        if (!rule.sections.condition) {
            const at = rule.closeBrace ?? rule.nameFrom;
            ruleErr(at, rule.closeBrace != null ? at + 1 : rule.nameTo, `Rule "${rule.name}" has no condition: section`, { code: 'no-condition' });
        }
        return rule;

        function skipToRecovery() {
            i++;
            while (i < tokens.length) {
                const t = tok();
                if (isPunct(t, '}') || atTopLevelStart()) return;
                if (isIdent(t) && SECTION_NAMES.has(t.value) && isPunct(tok(1), ':')) return;
                if (current === 'strings' && t.type === T.STRING_ID) return;
                if (current === 'meta' && isIdent(t) && isPunct(tok(1), '=')) return;
                i++;
            }
        }

        function sectionEnd() {
            const t = tok();
            const sec = rule.sections[current];
            sec.bodyTo = t ? t.from : (tokens[i - 1] ? tokens[i - 1].to : sec.bodyFrom);
        }

        function parseMeta() {
            while (i < tokens.length) {
                const key = tok();
                if (!isIdent(key) || isPunct(tok(1), ':')) break;
                if (!isPunct(tok(1), '=')) {
                    ruleErr(key.from, key.to, `Expected "=" after meta key "${key.value}"`);
                    skipToRecovery();
                    continue;
                }
                let vt = tok(2);
                let neg = false;
                if (isPunct(vt, '-') && tok(3) && tok(3).type === T.NUMBER) { neg = true; vt = tok(3); }
                const ok = vt && (vt.type === T.TEXT || (vt.type === T.NUMBER && !vt.value.includes('.')) || isIdent(vt, 'true') || isIdent(vt, 'false'));
                if (!ok) {
                    ruleErr(key.from, (vt || key).to, `Meta "${key.value}" needs a value: "string", integer, true or false`);
                    i += 2;
                    skipToRecovery();
                    continue;
                }
                const valueFrom = neg ? tok(2).from : vt.from;
                rule.meta.push({
                    key: key.value, from: key.from, to: vt.to, keyFrom: key.from, keyTo: key.to,
                    value: vt.type === T.TEXT ? unquote(vt.value) : vt.value,
                    raw: text.slice(valueFrom, vt.to), valueFrom, valueTo: vt.to,
                    valueType: vt.type === T.TEXT ? 'string' : vt.type === T.NUMBER ? 'number' : 'boolean',
                });
                i += neg ? 4 : 3;
            }
            sectionEnd();
        }

        function parseStrings() {
            while (i < tokens.length) {
                const id = tok();
                if (id.type !== T.STRING_ID) break;
                if (!isPunct(tok(1), '=')) {
                    ruleErr(id.from, id.to, `Expected "=" after ${id.value}`);
                    skipToRecovery();
                    continue;
                }
                const vt = tok(2);
                const kind = vt && (vt.type === T.TEXT ? 'text' : vt.type === T.HEX ? 'hex' : vt.type === T.REGEX ? 'regex' : null);
                if (!kind) {
                    ruleErr(id.from, (vt || id).to, `${id.value} needs a value: "text", { hex } or /regex/`);
                    i += 2;
                    skipToRecovery();
                    continue;
                }
                if (id.wildcard) ruleErr(id.from, id.to, `"${id.value}": a string definition cannot use "*"`);
                const entry = {
                    id: id.value, name: id.name, from: id.from, to: vt.to, idFrom: id.from, idTo: id.to,
                    kind, raw: vt.value, valueFrom: vt.from, valueTo: vt.to, closed: vt.closed !== false,
                    modifiers: [],
                };
                i += 3;
                while (isIdent(tok()) && MODIFIERS[tok().value] && !isPunct(tok(1), ':')) {
                    const m = tok();
                    const mod = { name: m.value, from: m.from, to: m.to, args: null };
                    i++;
                    if (isPunct(tok(), '(')) {
                        const argsFrom = tok().from;
                        let depth = 0;
                        while (i < tokens.length) {
                            if (isPunct(tok(), '(')) depth++;
                            if (isPunct(tok(), ')')) { depth--; if (depth === 0) { i++; break; } }
                            i++;
                        }
                        mod.to = tokens[i - 1].to;
                        mod.args = text.slice(argsFrom + 1, mod.to - 1);
                    }
                    entry.modifiers.push(mod);
                    entry.to = mod.to;
                }
                // a word that is not a modifier right after a string, on the same line
                const next = tok();
                if (isIdent(next) && !isPunct(tok(1), ':') && !MODIFIERS[next.value]
                    && !text.slice(entry.to, next.from).includes('\n')) {
                    ruleErr(next.from, next.to, `Unknown string modifier "${next.value}"`, { code: 'unknown-modifier' });
                    i++;
                }
                rule.strings.push(entry);
            }
            sectionEnd();
        }

        function parseCondition() {
            const from = tok() ? tok().from : rule.sections.condition.bodyFrom;
            const condTokens = [];
            let depth = 0;
            while (i < tokens.length) {
                const t = tok();
                if (isPunct(t, '}')) break;   // never part of a condition
                if (startsRule() || isIdent(t, 'import') || isIdent(t, 'include')) break;
                if (isIdent(t) && SECTION_NAMES.has(t.value) && isPunct(tok(1), ':')) break;
                if (isPunct(t, '(')) depth++;
                if (isPunct(t, ')')) depth--;
                condTokens.push(t);
                i++;
            }
            const last = condTokens[condTokens.length - 1];
            rule.condition = { from, to: last ? last.to : from, tokens: condTokens, text: last ? text.slice(from, last.to) : '' };
            if (!condTokens.length) {
                const sec = rule.sections.condition;
                ruleErr(sec.from, sec.to, 'Empty condition');
            }
            void depth;      // parentheses are checked token by token below
            if (condTokens.length) {
                const imported = new Set(imports.map(m => m.name));
                for (const e of checkCondition(condTokens, { imports: imported, end: rule.condition.to })) ruleErr(e.from, e.to, e.message, { code: e.code });
            }
            sectionEnd();
        }
    }

    return { text, tokens, comments, imports, includes, rules, errors };
}

export function unquote(raw) {
    const body = raw.replace(/^"/, '').replace(/"$/, '');
    return body.replace(/\\(x[0-9a-fA-F]{2}|.)/g, (m, e) => {
        if (e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
        return { n: '\n', t: '\t', r: '\r', '\\': '\\', '"': '"' }[e] ?? m;
    });
}

/** Byte length of a text string value (escapes decoded). */
export function textByteLength(raw) {
    return unquote(raw).length;
}
