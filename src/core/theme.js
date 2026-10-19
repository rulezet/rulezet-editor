/**
 * Editor theme driven by CSS variables (--rze-*), so light/dark switching is a
 * class change on the wrapper and hosts can restyle without touching JS.
 * Default values live in rulezet-editor.css.
 */
import { EditorView } from '@codemirror/view';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags as t } from '@lezer/highlight';
import { hexTag, hexJumpTag, hexWildcardTag, sectionTag } from './tokens.js';

const v = (name) => `var(--rze-${name})`;

export const highlightStyle = HighlightStyle.define([
    { tag: t.keyword, color: v('keyword'), fontWeight: '500' },
    { tag: sectionTag, color: v('section'), fontWeight: '600' },
    { tag: t.string, color: v('string') },
    { tag: t.regexp, color: v('regexp') },
    { tag: t.escape, color: v('escape') },
    { tag: t.number, color: v('number') },
    { tag: t.bool, color: v('atom') },
    { tag: t.comment, color: v('comment'), fontStyle: 'italic' },
    { tag: t.special(t.variableName), color: v('variable') },
    { tag: t.variableName, color: v('name') },
    { tag: t.definition(t.variableName), color: v('definition'), fontWeight: '600' },
    { tag: t.propertyName, color: v('property') },
    { tag: t.function(t.variableName), color: v('function') },
    { tag: t.namespace, color: v('module') },
    { tag: t.modifier, color: v('modifier') },
    { tag: t.typeName, color: v('modifier') },
    { tag: t.tagName, color: v('tag') },
    { tag: t.operator, color: v('operator') },
    { tag: t.bracket, color: v('bracket') },
    { tag: hexTag, color: v('hex') },
    { tag: hexJumpTag, color: v('hex-jump'), fontWeight: '600' },
    { tag: hexWildcardTag, color: v('hex-wildcard') },
    { tag: t.invalid, color: v('invalid'), textDecoration: 'underline wavy' },
    { tag: t.meta, color: v('comment') },
    { tag: t.heading, color: v('section'), fontWeight: '600' },
]);

export const baseTheme = EditorView.theme({
    '&': { color: v('fg'), backgroundColor: v('bg'), height: '100%', fontSize: v('font-size') },
    '.cm-content': { caretColor: v('caret'), fontFamily: v('font') },
    '.cm-scroller': { fontFamily: v('font'), lineHeight: '1.55' },
    '&.cm-focused .cm-cursor': { borderLeftColor: v('caret') },
    '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': { backgroundColor: v('selection') + ' !important' },
    '.cm-activeLine': { backgroundColor: v('active-line') },
    '.cm-gutters': { backgroundColor: v('gutter-bg'), color: v('gutter-fg'), borderRight: `1px solid ${v('border')}` },
    '.cm-activeLineGutter': { backgroundColor: v('active-line'), color: v('fg') },
    '.cm-foldPlaceholder': { backgroundColor: v('panel-bg'), border: `1px solid ${v('border')}`, color: v('muted') },
    '.cm-matchingBracket': { backgroundColor: v('bracket-match'), outline: `1px solid ${v('border')}` },
    '.cm-selectionMatch': { backgroundColor: v('selection-match') },
    '.cm-searchMatch': { backgroundColor: v('search-match'), outline: `1px solid ${v('border')}` },
    '.cm-searchMatch.cm-searchMatch-selected': { backgroundColor: v('search-current'), outline: `1px solid ${v('warning')}` },
    '.cm-panel.cm-search': { padding: '6px 10px', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '4px 6px', fontSize: '12px' },
    '.cm-panel.cm-search label': { display: 'inline-flex', alignItems: 'center', gap: '3px', color: v('muted') },
    '.cm-panel.cm-search [name=close]': { position: 'static', marginLeft: 'auto', fontSize: '16px', cursor: 'pointer' },
    '.cm-panel.cm-search .cm-textfield': { minWidth: '180px', padding: '3px 6px' },
    '.cm-tooltip': { backgroundColor: v('panel-bg'), color: v('fg'), border: `1px solid ${v('border')}`, borderRadius: '6px', boxShadow: '0 6px 24px rgba(0,0,0,.18)' },
    '.cm-tooltip-autocomplete > ul > li[aria-selected]': { backgroundColor: v('accent'), color: '#fff' },
    '.cm-tooltip-autocomplete > ul': { fontFamily: v('font') },
    '.cm-completionDetail': { color: v('muted'), fontStyle: 'normal', marginLeft: '1em' },
    '.cm-completionInfo': { padding: '6px 10px', maxWidth: '420px' },
    '.cm-panels': { backgroundColor: v('panel-bg'), color: v('fg') },
    '.cm-panels.cm-panels-top': { borderBottom: `1px solid ${v('border')}` },
    '.cm-panels.cm-panels-bottom': { borderTop: `1px solid ${v('border')}` },
    '.cm-panel input, .cm-panel button': { color: v('fg') },
    '.cm-textfield': { backgroundColor: v('bg'), border: `1px solid ${v('border')}`, borderRadius: '4px' },
    '.cm-button': { backgroundImage: 'none', backgroundColor: v('bg'), border: `1px solid ${v('border')}`, borderRadius: '4px' },
    '.cm-lintRange-error': { backgroundImage: 'none', textDecoration: `underline wavy ${v('error')}`, textUnderlineOffset: '3px' },
    '.cm-lintRange-warning': { backgroundImage: 'none', textDecoration: `underline wavy ${v('warning')}`, textUnderlineOffset: '3px' },
    '.cm-lintRange-info': { backgroundImage: 'none', textDecoration: `underline dotted ${v('info')}`, textUnderlineOffset: '3px' },
    '.cm-lintRange-hint': { backgroundImage: 'none', textDecoration: `underline dotted ${v('muted')}` },
    '.cm-diagnostic': { fontFamily: 'inherit' },
    '.cm-diagnostic-error': { borderLeft: `4px solid ${v('error')}` },
    '.cm-diagnostic-warning': { borderLeft: `4px solid ${v('warning')}` },
    '.cm-diagnostic-info': { borderLeft: `4px solid ${v('info')}` },
    '.cm-diagnosticAction': { backgroundColor: v('accent'), borderRadius: '4px' },
    '.cm-diagnosticSource': { color: v('muted') },
    '.rze-ref': { backgroundColor: v('ref') , borderRadius: '2px' },
    '.rze-ref-def': { backgroundColor: v('ref-def'), borderRadius: '2px' },
    '.rze-link': { textDecoration: 'underline', cursor: 'pointer' },
});

export const themeExtensions = [baseTheme, syntaxHighlighting(highlightStyle)];
