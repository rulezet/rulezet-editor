/**
 * "Try" panel: a small sample typed or pasted (text with \xNN escapes, or hex bytes), run against
 * one rule of the document in the browser — every string with its matches, the condition as a
 * tree (each and / or / not / N of… with its value), the verdict. Plain DOM; the language pack
 * does the work (pack.debug.evaluate), so other formats can bring their own.
 *
 * state: { open, mode: 'text' | 'hex', input, rule, result, error }
 */
import { h, icon } from './dom.js';

const VALUE = (v) => (v === null || v === undefined ? '?' : v === true ? 'true' : v === false ? 'false' : typeof v === 'number' ? String(v) : String(v));
const TONE = (v) => (v === null || v === undefined ? 'muted' : v === true ? 'ok' : v === false ? 'error' : 'info');
const VERDICT = { match: ['ok', 'tryMatch'], no_match: ['error', 'tryNoMatch'], unknown: ['muted', 'tryUnknown'] };

export function renderTry(el, state, cb) {
    const { t } = cb;
    const prev = el.querySelector('textarea');
    const focused = prev && document.activeElement === prev ? [prev.selectionStart, prev.selectionEnd] : null;

    const head = h('div', { class: 'rze-panel-head rze-try-head' },
        h('strong', { class: 'rze-tests-title' }, icon('search'), t('try')),
        state.rules.length > 1 ? h('select', { class: 'rze-try-rule', title: t('tryRule'), onchange: e => cb.onRule(e.target.value || null) },
            h('option', { value: '', text: t('fUnderCursor'), selected: !state.rule }),
            ...state.rules.map(n => h('option', { value: n, text: n, selected: state.rule === n }))) : '',
        h('div', { class: 'rze-try-modes', role: 'radiogroup' },
            ...['text', 'hex'].map(m => h('button', { type: 'button', class: state.mode === m ? 'rze-on' : '', onclick: () => cb.onMode(m) },
                t(m === 'text' ? 'tryText' : 'tryHex')))),
        h('span', { class: 'rze-toolbar-fill' }),
        h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: cb.onClose }, icon('close')));

    const input = h('textarea', {
        class: 'rze-try-input rze-mono', spellcheck: 'false', rows: 4, value: state.input,
        placeholder: state.mode === 'hex' ? '4D 5A 90 00 03 00 …' : t('tryPlaceholder'),
        oninput: e => cb.onInput(e.target.value),
    });

    const body = h('div', { class: 'rze-try-body' }, input,
        h('div', { class: 'rze-try-hint', text: state.mode === 'hex' ? t('tryHexHint') : t('tryTextHint') }));

    const r = state.result;
    if (state.error) body.appendChild(h('div', { class: 'rze-tests-note rze-tone-error' }, icon('error'), h('span', { text: state.error })));
    else if (!r) body.appendChild(h('div', { class: 'rze-empty', text: t('tryNoRule') }));
    else {
        const [tone, key] = VERDICT[r.verdict];
        body.appendChild(h('div', { class: `rze-try-verdict rze-tone-${tone}` },
            h('b', { text: r.rule }), h('span', { text: t(key) }), h('small', { text: t('tryBytes', { n: r.size }) })));

        if (r.strings.length) {
            body.appendChild(h('div', { class: 'rze-try-caption', text: t('tryStrings') }));
            body.appendChild(h('div', { class: 'rze-try-strings' }, ...r.strings.map(s => stringRow(s, cb))));
        }
        body.appendChild(h('div', { class: 'rze-try-caption', text: t('tryCondition') }));
        body.appendChild(h('ul', { class: 'rze-try-tree' }, treeNode(r.condition, cb)));
        body.appendChild(h('div', { class: 'rze-try-hint', text: t('tryLimits') }));
    }

    el.replaceChildren(head, body);
    if (focused) {
        const ta = el.querySelector('textarea');
        ta.focus();
        ta.setSelectionRange(focused[0], focused[1]);
    }
}

function stringRow(s, cb) {
    const { t } = cb;
    const state = s.unsupported ? null : s.hits.length > 0;
    const offsets = s.hits.slice(0, 8).map(x => '0x' + x.offset.toString(16).toUpperCase()).join(', ')
        + (s.hits.length > 8 ? ` … (${s.hits.length})` : '');
    return h('div', { class: `rze-try-string rze-tone-${TONE(state)}` },
        h('button', { type: 'button', class: 'rze-tests-chip', title: t('tShowInRule'), onclick: () => cb.onGoto(s.from) }, s.id),
        h('span', { class: 'rze-tests-kind', text: s.kind }),
        s.modifiers.length ? h('span', { class: 'rze-try-mods rze-mono', text: s.modifiers.join(' ') }) : '',
        h('span', { class: 'rze-toolbar-fill' }),
        h('span', { class: 'rze-try-state', text: s.unsupported ? '?' : s.hits.length ? t('tryFound', { n: s.hits.length }) : t('tryNotFound') }),
        s.hits.length ? h('span', { class: 'rze-try-offsets rze-mono', text: offsets }) : '',
        s.unsupported || s.note ? h('div', { class: 'rze-try-note', text: s.unsupported || s.note }) : '');
}

function treeNode(n, cb) {
    const kids = n.children || [];
    return h('li', { class: `rze-try-node rze-tone-${TONE(n.value === null ? null : typeof n.value === 'number' && n.kind !== 'number' && n.kind !== 'arith' ? n.value !== 0 : n.value)}` },
        h('div', { class: 'rze-try-line' },
            h('span', { class: 'rze-try-dot' }),
            n.kind === 'and' || n.kind === 'or' || n.kind === 'not' ? h('b', { class: 'rze-try-op', text: n.kind.toUpperCase() }) : '',
            h('code', { class: 'rze-try-text', text: n.text, title: n.text }),
            h('span', { class: 'rze-try-value', text: VALUE(n.value) }),
            n.note ? h('small', { class: 'rze-try-note-inline', text: n.note }) : ''),
        kids.length ? h('ul', {}, ...kids.map(k => treeNode(k, cb))) : '');
}
