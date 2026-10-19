/**
 * Condition checker: follows libyara's grammar (grammar.y, 4.5) closely enough to report what
 * the compiler would refuse, before compiling: syntax, misplaced anonymous strings, module
 * member usage, function arguments, loop variables and types.
 *
 * Only the first syntax error is reported (the compiler stops there too); type errors are
 * reported only when the syntax is valid.
 *
 * Two kinds of expressions, as in the grammar:
 *   bool   true, $a, $a at 0, any of them, for ..., x == y, a and b, not a, a rule name
 *   prim   numbers, strings, filesize, #a, @a[i], uint32(0), pe.x, arithmetic
 * Comparisons and arithmetic take prim operands only, so "1 == 1 == 1" or "$a + 1" fail as in YARA.
 */
import { T } from './lexer.js';
import { MODULES } from './modules.js';

const INT_FUNCTIONS = new Set(['int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32',
    'int8be', 'int16be', 'int32be', 'uint8be', 'uint16be', 'uint32be']);
const KEYWORDS = new Set(['all', 'and', 'any', 'ascii', 'at', 'base64', 'base64wide', 'condition', 'contains',
    'defined', 'endswith', 'entrypoint', 'false', 'filesize', 'for', 'fullword', 'global', 'icontains',
    'iendswith', 'iequals', 'import', 'in', 'include', 'istartswith', 'matches', 'meta', 'nocase', 'none',
    'not', 'of', 'or', 'private', 'rule', 'startswith', 'strings', 'them', 'true', 'wide', 'xor', ...INT_FUNCTIONS]);
const STRING_OPS = new Set(['contains', 'icontains', 'startswith', 'istartswith', 'endswith', 'iendswith', 'iequals']);
const EQUALITY = new Set(['==', '!=']);
const RELATIONAL = new Set(['<', '<=', '>', '>=']);

// binding powers, from libyara's precedence table (lowest first)
const BP = { or: 1, and: 2, not: 3, eq: 4, rel: 5, of: 5.5, '|': 6, '^': 7, '&': 8, shift: 9, add: 10, mul: 11, unary: 12 };
const ARITH = { '|': BP['|'], '^': BP['^'], '&': BP['&'], '<<': BP.shift, '>>': BP.shift, '+': BP.add, '-': BP.add, '*': BP.mul, '\\': BP.mul, '%': BP.mul };
const MAX_DEPTH = 200;

class Stop extends Error {}

const describe = (t) => {
    if (!t) return 'end of condition';
    if (t.type === T.STRING_ID) return t.wildcard ? `string set "${t.value}"` : `"${t.value}"`;
    if (t.type === T.REGEX) return 'regular expression';
    if (t.type === T.TEXT) return 'text string';
    return `"${t.value}"`;
};
const isNum = (type) => type === 'integer' || type === 'float' || type === 'any';
const isInt = (type) => type === 'integer' || type === 'any';
const isStr = (type) => type === 'string' || type === 'any';
const typeName = (type) => type === 'bool' ? 'boolean' : type;

/**
 * @param tokens  condition tokens (from the parser)
 * @param ctx     { strings: Set of string names, rules: Set of known rule names, imports: Set, end }
 * @returns [{ from, to, message, code }]
 */
export function checkCondition(tokens, ctx = {}) {
    const errors = [];
    const typeErrors = [];
    let i = 0;
    let depth = 0;
    let anonymousOk = 0;          // > 0 inside "for ... of ... : ( )"
    const scopes = [];            // loop variables: [{ name -> type }]

    const tok = (k = 0) => tokens[i + k];
    const is = (t, v) => t && (t.type === T.PUNCT || t.type === T.IDENT) && t.value === v;
    const end = tokens.length ? tokens[tokens.length - 1].to : (ctx.end ?? 0);

    function fail(t, message, code = 'syntax') {
        const at = t || { from: end, to: end };
        errors.push({ from: at.from, to: Math.max(at.to, at.from + 1), message, code });
        throw new Stop();
    }
    const unexpected = (t, expected) => fail(t, `Unexpected ${describe(t)}${expected ? `: expected ${expected}` : ''}`);
    const typeError = (t, message) => { if (t) typeErrors.push({ from: t.from, to: t.to, message, code: 'type' }); };
    function expect(v, expected = `"${v}"`) {
        const t = tok();
        if (!is(t, v)) unexpected(t, expected);
        i++;
        return t;
    }
    const lookupVar = (name) => {
        for (let k = scopes.length - 1; k >= 0; k--) if (scopes[k].has(name)) return scopes[k].get(name);
        return undefined;
    };

    // ── expressions ──
    // returns { kind: 'bool' | 'prim', type, tok }
    function expression(minBp = 0) {
        if (++depth > MAX_DEPTH) fail(tok(), 'Condition nested too deeply');
        let left = prefix();
        for (;;) {
            const t = tok();
            if (!t) break;
            const v = t.value;
            if (t.type === T.IDENT && (v === 'and' || v === 'or')) {
                const bp = BP[v];
                if (bp <= minBp) break;
                i++;
                expression(bp);
                left = { kind: 'bool', type: 'bool', tok: t };
                continue;
            }
            if (t.type === T.PUNCT && (EQUALITY.has(v) || RELATIONAL.has(v)) || t.type === T.IDENT && (STRING_OPS.has(v) || v === 'matches')) {
                const bp = EQUALITY.has(v) || STRING_OPS.has(v) || v === 'matches' ? BP.eq : BP.rel;
                if (bp <= minBp) break;
                if (left.kind !== 'prim') unexpected(t);
                i++;
                if (v === 'matches') {
                    const r = tok();
                    if (!r || r.type !== T.REGEX) unexpected(r, 'a regular expression');
                    i++;
                    if (!isStr(left.type)) typeError(left.tok, `Wrong type "${typeName(left.type)}" for "matches": a string is needed`);
                } else {
                    const right = expression(bp);
                    if (right.kind !== 'prim') unexpected(right.tok);
                    if (STRING_OPS.has(v)) {
                        for (const side of [left, right]) if (!isStr(side.type)) typeError(side.tok, `Wrong type "${typeName(side.type)}" for "${v}": a string is needed`);
                    } else if (!(isNum(left.type) && isNum(right.type)) && !(isStr(left.type) && isStr(right.type))) {
                        typeError(t, `Type mismatch: ${typeName(left.type)} ${v} ${typeName(right.type)}`);
                    }
                }
                left = { kind: 'bool', type: 'bool', tok: t };
                // comparisons do not chain: "a == b == c" is refused
                const n = tok();
                if (n && (n.type === T.PUNCT && (EQUALITY.has(n.value) || RELATIONAL.has(n.value)) || n.type === T.IDENT && (STRING_OPS.has(n.value) || n.value === 'matches'))) unexpected(n);
                continue;
            }
            if (t.type === T.PUNCT && v === '%' && is(tok(1), 'of')) {
                // "50% of them"
                if (BP.of <= minBp) break;
                if (left.kind !== 'prim') unexpected(t);
                if (left.tok && left.tok.type === T.NUMBER && /^\d+$/.test(left.tok.value) && (Number(left.tok.value) < 1 || Number(left.tok.value) > 100)) {
                    fail(left.tok, 'A percentage must be between 1 and 100', 'percentage');
                }
                i += 2;
                ofSet(t);
                left = { kind: 'bool', type: 'bool', tok: t };
                continue;
            }
            if (t.type === T.PUNCT && ARITH[v]) {
                const bp = ARITH[v];
                if (bp <= minBp) break;
                if (left.kind !== 'prim') unexpected(t);
                i++;
                const right = expression(bp);
                if (right.kind !== 'prim') unexpected(right.tok);
                const intOnly = !['+', '-', '*', '\\', '%'].includes(v) || v === '%';
                const ok = intOnly ? isInt(left.type) && isInt(right.type) : isNum(left.type) && isNum(right.type);
                if (!ok) typeError(t, `Type mismatch: ${typeName(left.type)} ${v} ${typeName(right.type)}`);
                const type = left.type === 'float' || right.type === 'float' ? 'float' : (left.type === 'any' || right.type === 'any' ? 'any' : 'integer');
                left = { kind: 'prim', type: intOnly ? 'integer' : type, tok: t };
                continue;
            }
            if (is(t, 'of')) {
                if (BP.of <= minBp) break;
                if (left.kind !== 'prim') unexpected(t);
                i++;
                ofSet(t);
                left = { kind: 'bool', type: 'bool', tok: t };
                continue;
            }
            break;
        }
        depth--;
        return left;
    }

    function prefix() {
        const t = tok();
        if (!t) unexpected(t, 'an expression');
        const v = t.value;
        const prim = (type) => ({ kind: 'prim', type, tok: t });
        const bool = { kind: 'bool', type: 'bool', tok: t };

        if (t.type === T.NUMBER) { i++; return prim(/\./.test(v) ? 'float' : 'integer'); }
        if (t.type === T.TEXT) { i++; return prim('string'); }
        if (t.type === T.REGEX) unexpected(t);
        if (t.type === T.STRING_ID) {
            if (t.wildcard) unexpected(t);
            if (t.name === '' && !anonymousOk) fail(t, '"$" alone only works inside "for ... of ... : (...)"', 'anonymous-string');
            i++;
            if (is(tok(), 'at')) { i++; operand('integer'); }
            else if (is(tok(), 'in')) { i++; range(); }
            return bool;
        }
        if (t.type === T.COUNT) {
            if (t.name === '' && !anonymousOk) fail(t, '"#" alone only works inside "for ... of ... : (...)"', 'anonymous-string');
            i++;
            if (is(tok(), 'in')) { i++; range(); }
            return prim('integer');
        }
        if (t.type === T.OFFSET || t.type === T.LENGTH) {
            if (t.name === '' && !anonymousOk) fail(t, `"${v}" alone only works inside "for ... of ... : (...)"`, 'anonymous-string');
            i++;
            if (is(tok(), '[')) { i++; operand(null); expect(']'); }
            return prim('integer');
        }
        if (t.type === T.PUNCT) {
            if (v === '(') {
                i++;
                const inner = expression(0);
                expect(')', '")"');
                return { ...inner, tok: inner.tok || t };
            }
            if (v === '-' || v === '~') {
                i++;
                const operandExpr = expression(BP.unary);
                if (operandExpr.kind !== 'prim') unexpected(operandExpr.tok);
                if (v === '~' ? !isInt(operandExpr.type) : !isNum(operandExpr.type)) typeError(t, `Type mismatch: ${v}${typeName(operandExpr.type)}`);
                return prim(v === '~' ? 'integer' : operandExpr.type);
            }
            unexpected(t);
        }
        if (t.type !== T.IDENT) unexpected(t);

        switch (v) {
            case 'true': case 'false': i++; return bool;
            case 'not': i++; expression(BP.not); return bool;
            case 'defined': i++; expression(BP.not); return bool;
            case 'filesize': case 'entrypoint': i++; return prim('integer');
            case 'all': case 'any': case 'none':
                i++;
                if (!is(tok(), 'of')) unexpected(tok(), '"of"');
                i++;
                ofSet(t);
                return bool;
            case 'for': i++; forLoop(t); return bool;
        }
        if (INT_FUNCTIONS.has(v)) {
            i++;
            expect('(', '"("');
            operand('integer');
            expect(')', '")"');
            return prim('integer');
        }
        if (v === 'with') fail(t, '"with" is not supported by YARA 4.5 (YARA-X only)', 'unsupported');
        if (KEYWORDS.has(v)) unexpected(t);
        return identifier();
    }

    /** prim operand of an integer slot (at, ranges, indexes, int functions) */
    function operand(type) {
        const e = expression(BP.of);
        if (e.kind !== 'prim') unexpected(e.tok);
        if (type === 'integer' && !isInt(e.type)) typeError(e.tok, `Wrong type "${typeName(e.type)}": an integer is needed`);
        return e;
    }

    function range() {
        expect('(', '"(" to open a range (a..b)');
        operand('integer');
        expect('..', '".."');
        operand('integer');
        expect(')', '")"');
    }

    /** after "of": them | ($a, $b*) | (rule1, rule2*), then "in (range)" or "at n" for strings */
    function ofSet(quantifier) {
        const t = tok();
        if (is(t, 'them')) {
            i++;
            ctx.onThem && ctx.onThem(t);
        } else if (is(t, '(')) {
            i++;
            const first = tok();
            const strings = first && first.type === T.STRING_ID;
            if (!first || (!strings && first.type !== T.IDENT) || (first.type === T.IDENT && KEYWORDS.has(first.value))) {
                unexpected(first, 'a string identifier or a rule name');
            }
            for (;;) {
                const item = tok();
                if (strings) {
                    if (!item || item.type !== T.STRING_ID) unexpected(item, 'a string identifier');
                    i++;
                } else {
                    if (!item || item.type !== T.IDENT || KEYWORDS.has(item.value)) unexpected(item, 'a rule name');
                    i++;
                    if (is(tok(), '*') && tok().from === item.to) { i++; ctx.onRuleSet && ctx.onRuleSet(item, true); }
                    else ctx.onRuleSet && ctx.onRuleSet(item, false);
                }
                if (is(tok(), ',')) { i++; continue; }
                if (is(tok(), ')')) { i++; break; }
                unexpected(tok(), '"," or ")"');
            }
            if (!strings) return;
        } else {
            unexpected(t, '"them" or "("');
        }
        if (is(tok(), 'in')) { i++; range(); }
        else if (is(tok(), 'at')) { i++; operand('integer'); }
        void quantifier;
    }

    function forLoop(forTok) {
        // quantifier: all | any | none | expression
        const q = tok();
        if (is(q, 'all') || is(q, 'any') || is(q, 'none')) i++;
        else {
            const e = expression(BP.of);
            if (e.kind !== 'prim') unexpected(e.tok);
        }
        if (is(tok(), 'of')) {
            i++;
            const t = tok();
            if (!is(t, 'them') && !is(t, '(')) unexpected(t, '"them" or "("');
            ofSet(forTok);
            expect(':', '":"');
            expect('(', '"("');
            anonymousOk++;
            expression(0);
            anonymousOk--;
            expect(')', '")"');
            return;
        }
        // for any i, j in <iterator> : ( ... )
        const vars = [];
        while (tok() && tok().type === T.IDENT && !KEYWORDS.has(tok().value)) {
            vars.push(tok());
            i++;
            if (is(tok(), ',')) { i++; continue; }
            break;
        }
        if (!vars.length) unexpected(tok(), '"of" or a loop variable');
        expect('in', '"in"');
        const iter = iterator();
        if (iter.count && iter.count !== vars.length) {
            fail(vars[0], `This iterator gives ${iter.count} value${iter.count > 1 ? 's' : ''} per loop, but ${vars.length} variable${vars.length > 1 ? 's are' : ' is'} declared`, 'loop-variables');
        }
        expect(':', '":"');
        expect('(', '"("');
        scopes.push(new Map(vars.map((v, k) => [v.value, iter.types[k] || 'any'])));
        ctx.onLoopVars && ctx.onLoopVars(vars);
        expression(0);
        scopes.pop();
        expect(')', '")"');
    }

    /** (a..b) | (x, y, z) | module array or dictionary */
    function iterator() {
        if (is(tok(), '(')) {
            i++;
            const first = expression(BP.of);
            if (first.kind !== 'prim') unexpected(first.tok);
            if (is(tok(), '..')) {
                i++;
                operand('integer');
                expect(')', '")"');
                return { count: 1, types: ['integer'] };
            }
            while (is(tok(), ',')) {
                i++;
                const e = expression(BP.of);
                if (e.kind !== 'prim') unexpected(e.tok);
            }
            expect(')', '")"');
            return { count: 1, types: [first.type] };
        }
        const t = tok();
        if (!t || t.type !== T.IDENT || KEYWORDS.has(t.value)) unexpected(t, 'a range (a..b), a list (a, b) or an array');
        const e = identifier({ iterable: true });
        const node = e.node;
        const item = node && (node.fields ? { kind: 'struct', fields: node.fields } : node.type);
        if (node && node.kind === 'array') return { count: 1, types: [item] };
        if (node && node.kind === 'dict') return { count: 2, types: ['string', item] };
        if (node) fail(t, `"${e.path}" cannot be iterated: an array or a dictionary is needed`, 'module-member');
        return { count: 0, types: [] };
    }

    /**
     * identifier ( "." name | "[" expr "]" | "(" args ")" )*
     * Module paths are checked against the module data; loop variables and rule names pass.
     */
    function identifier({ iterable = false } = {}) {
        const t = tok();
        i++;
        const name = t.value;
        const varType = lookupVar(name);
        const structVar = varType && typeof varType === 'object';
        if (varType !== undefined && !structVar && !is(tok(), '.') && !is(tok(), '[') && !is(tok(), '(')) return { kind: 'prim', type: varType, tok: t };

        const mod = structVar ? { fields: varType.fields } : MODULES[name];
        if (!mod) {
            if (varType !== undefined) {
                // a structure from "for any s in pe.sections": s.name, unknown shape here
                skipAccessors();
                return { kind: 'prim', type: 'any', tok: t };
            }
            if (is(tok(), '(')) fail(t, `"${name}" is not a function`, 'unknown-identifier');
            if (is(tok(), '.') || is(tok(), '[')) {
                ctx.onUnknownRoot && ctx.onUnknownRoot(t);
                skipAccessors();
                return { kind: 'prim', type: 'any', tok: t };
            }
            ctx.onRuleRef && ctx.onRuleRef(t);
            return { kind: 'bool', type: 'bool', tok: t };
        }
        if (!structVar && ctx.imports && !ctx.imports.has(name)) {
            // reported by the linter with a fix; keep checking the rest
            skipAccessors();
            return { kind: 'prim', type: 'any', tok: t };
        }

        let node = { kind: structVar ? 'struct' : 'module', fields: mod.fields };
        let path = name;
        let last = t;
        for (;;) {
            const n = tok();
            if (is(n, '.')) {
                i++;
                const member = tok();
                if (!member || member.type !== T.IDENT) unexpected(member, 'a field name');
                i++;
                if (node.kind !== 'module' && node.kind !== 'struct') fail(member, `"${path}" has no fields: use ${node.kind === 'array' ? '[index]' : node.kind === 'dict' ? '["key"]' : 'it as a value'}`, 'module-member');
                const child = node.fields && node.fields[member.value];
                if (!child) fail(member, `"${member.value}" is not a field of ${path}`, 'module-member');
                node = child;
                path += '.' + member.value;
                last = member;
                continue;
            }
            if (is(n, '[')) {
                i++;
                if (node.kind === 'array') {
                    operand('integer');
                } else if (node.kind === 'dict') {
                    const k = expression(BP.of);
                    if (k.kind !== 'prim') unexpected(k.tok);
                    if (!isStr(k.type)) typeError(k.tok, 'Dictionary keys are strings');
                } else {
                    fail(n, `"${path}" cannot be indexed`, 'module-member');
                }
                expect(']', '"]"');
                node = node.fields ? { kind: 'struct', fields: node.fields } : { kind: 'value', type: node.type };
                path += '[]';
                last = n;
                continue;
            }
            if (is(n, '(')) {
                if (node.kind !== 'function') fail(last, `"${path}" is not a function`, 'module-member');
                i++;
                const args = [];
                if (!is(tok(), ')')) {
                    for (;;) {
                        const a = tok();
                        if (a && a.type === T.REGEX) { i++; args.push({ type: 'regex', tok: a }); }
                        else {
                            const e = expression(0);
                            args.push({ type: e.kind === 'bool' ? 'boolean' : e.type, tok: e.tok });
                        }
                        if (is(tok(), ',')) { i++; continue; }
                        break;
                    }
                }
                const close = expect(')', '"," or ")"');
                const match = node.overloads.find(o => o.args.length === args.length
                    && o.args.every((type, k) => args[k].type === 'any' || type === args[k].type
                        || (type === 'boolean' && args[k].type !== 'regex')));
                if (!match) {
                    const sigs = node.overloads.map(o => `(${o.args.join(', ')})`).join(' or ');
                    typeError({ from: last.from, to: close.to }, `Wrong arguments for ${path}: expected ${sigs}`);
                }
                const ret = match ? match.ret : (node.overloads[0] && node.overloads[0].ret) || 'any';
                node = { kind: 'value', type: ret === 'boolean' ? 'integer' : ret };
                path += '()';
                last = close;
                continue;
            }
            break;
        }
        if (node.kind === 'function') fail(last, `"${path}" is a function: call it with (...)`, 'module-member');
        if (!iterable && (node.kind === 'array' || node.kind === 'dict' || node.kind === 'struct' || node.kind === 'module')) {
            fail(last, `"${path}" cannot be used as a value${node.kind === 'array' ? ': index it with [i] or loop over it' : node.kind === 'dict' ? ': use ["key"]' : ''}`, 'module-member');
        }
        return { kind: 'prim', type: node.type || 'any', tok: t, node, path };
    }

    /** skips .x [..] (..) after an identifier whose shape is unknown */
    function skipAccessors() {
        for (;;) {
            if (is(tok(), '.') && tok(1) && tok(1).type === T.IDENT) { i += 2; continue; }
            if (is(tok(), '[') || is(tok(), '(')) {
                const open = tok().value;
                const close = open === '[' ? ']' : ')';
                i++;
                if (!is(tok(), close)) {
                    for (;;) {
                        if (tok() && tok().type === T.REGEX) i++;
                        else expression(0);
                        if (open === '(' && is(tok(), ',')) { i++; continue; }
                        break;
                    }
                }
                expect(close, `"${close}"`);
                continue;
            }
            return;
        }
    }

    try {
        if (!tokens.length) return [];
        expression(0);
        if (i < tokens.length) unexpected(tok(), '"and", "or" or the end of the condition');
    } catch (e) {
        if (!(e instanceof Stop)) {
            // never let a checker bug break the editor
            return errors;
        }
    }
    return errors.length ? errors : typeErrors;
}
