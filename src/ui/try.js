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
const VERDICT = {
    match:    { tone: 'ok',    mark: '✓', title: 'tryMatch' },
    no_match: { tone: 'error', mark: '✗', title: 'tryNoMatch' },
    unknown:  { tone: 'muted', mark: '?', title: 'tryUnknown' },
};
const truth = (n) => (n.value === null || n.value === undefined ? null
    : typeof n.value === 'number' && n.kind !== 'number' && n.kind !== 'arith' ? n.value !== 0 : !!n.value);

export function renderTry(el, state, cb) {
    const { t } = cb;
    el._tryLast = [state, cb];
    const focused = el._tryInput && document.activeElement === el._tryInput;

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

    // the sample box is kept from one render to the next (the result re-renders while typing or
    // pasting): same element, so its text, caret, selection and undo history stay as they are
    const placeholder = state.mode === 'hex' ? '4D 5A 90 00 03 00 …' : t('tryPlaceholder');
    let input = el._tryInput;
    if (!input) {
        input = el._tryInput = h('textarea', { class: 'rze-try-input rze-mono', spellcheck: 'false', rows: 4 });
        input.addEventListener('input', () => el._tryOnInput && el._tryOnInput(input.value));
    }
    el._tryOnInput = cb.onInput;
    if (input.value !== state.input) input.value = state.input;
    input.placeholder = placeholder;

    const body = h('div', { class: 'rze-try-body' }, input,
        h('div', { class: 'rze-try-hint', text: state.mode === 'hex' ? t('tryHexHint') : t('tryTextHint') }));

    const r = state.result;
    if (state.error) body.appendChild(h('div', { class: 'rze-tests-note rze-tone-error' }, icon('error'), h('span', { text: state.error })));
    else if (!r) body.appendChild(h('div', { class: 'rze-empty', text: t('tryNoRule') }));
    else if (!String(state.input || '').trim()) body.appendChild(h('div', { class: 'rze-empty', text: t('tryEmpty') }));
    else {
        body.appendChild(verdictCard(r, cb));

        body.appendChild(details(el, r, cb));
        body.appendChild(h('div', { class: 'rze-try-hint', text: t('tryLimits') }));
    }

    // the body is rebuilt: keep where it was scrolled (typing, folding)
    const oldBody = el.querySelector('.rze-try-body');
    const scrollTop = oldBody ? oldBody.scrollTop : 0;
    el.replaceChildren(head, body);
    body.scrollTop = scrollTop;
    if (focused) input.focus({ preventScroll: true });
}

/**
 * The answer first, in words: MATCH / NO MATCH / CAN'T TELL, then why — the parts of the
 * condition that fail (or still need the real engine) — and which strings were found.
 */
function verdictCard(r, cb) {
    const { t } = cb;
    const v = VERDICT[r.verdict];
    const parts = r.condition.kind === 'and' ? r.condition.children || [] : [r.condition];
    const failing = parts.filter(p => truth(p) === false);
    const pending = parts.filter(p => truth(p) === null);
    const found = r.strings.filter(x => !x.unsupported && x.hits.length);
    const missing = r.strings.filter(x => !x.unsupported && !x.hits.length);

    const why = r.verdict === 'match' ? h('div', { class: 'rze-try-why', text: t('tryWhyMatch') })
        : h('div', { class: 'rze-try-why' },
            h('span', { text: r.verdict === 'no_match' ? t('tryWhyFails') : t('tryWhyPending') }),
            ...(r.verdict === 'no_match' ? failing : pending).map(p =>
                h('code', { class: `rze-try-part rze-tone-${v.tone}`, text: p.text, title: p.note || p.text })),
            r.verdict === 'unknown' ? h('span', { class: 'rze-try-why-end', text: t('tryWhyPendingEnd') }) : '');

    const chips = (list, tone) => list.map(x => h('button', { type: 'button', class: `rze-tests-chip rze-try-chip rze-tone-${tone}`,
        title: t('tShowInRule'), onclick: () => cb.onGoto(x.from) }, x.id));
    return h('div', { class: `rze-try-verdict rze-tone-${v.tone}` },
        h('div', { class: 'rze-try-verdict-head' },
            h('span', { class: 'rze-try-mark', text: v.mark }),
            h('strong', { class: 'rze-try-answer', text: t(v.title) }),
            h('span', { class: 'rze-toolbar-fill' }),
            h('small', { text: t('tryBytes', { n: r.size }) })),
        why,
        r.strings.length ? h('div', { class: 'rze-try-found' },
            h('span', { class: 'rze-try-found-label', text: t('tryFoundLabel') }),
            ...(found.length ? chips(found, 'ok') : [h('em', { text: t('tryNone') })]),
            missing.length ? h('span', { class: 'rze-try-found-label rze-try-found-sep', text: t('tryMissingLabel') }) : '',
            ...chips(missing, 'error')) : '');
}

/** One string: its line (id, kind, found or not) and, unfolded, its modifiers, offsets and notes. */
function stringRow(s, cb, ctx) {
    const { t } = cb;
    const { el, v, q, hit } = ctx;
    const state = s.unsupported ? null : s.hits.length > 0;
    const offsets = s.hits.slice(0, 8).map(x => '0x' + x.offset.toString(16).toUpperCase()).join(', ')
        + (s.hits.length > 8 ? ` … (${s.hits.length})` : '');
    const key = `s:${s.id}`;
    const open = !v.closed.has(key);
    const more = [
        s.modifiers.length ? h('span', { class: 'rze-try-mods rze-mono', text: s.modifiers.join(' ') }) : '',
        s.hits.length ? h('span', { class: 'rze-try-offsets rze-mono', text: offsets }) : '',
        s.unsupported || s.note ? h('div', { class: 'rze-try-note', text: s.unsupported || s.note }) : '',
    ].filter(Boolean);
    return h('div', { class: `rze-try-string rze-tone-${TONE(state)}${q && hit(s.id) ? ' rze-try-hit' : ''}` },
        h('div', { class: `rze-try-string-head${more.length ? ' rze-try-foldable' : ''}`, 'data-try-key': key, onclick: more.length ? () => toggle(el, key) : null },
            more.length ? caret(open) : h('span', { class: 'rze-try-caret' }),
            h('button', { type: 'button', class: 'rze-tests-chip', title: t('tShowInRule'),
                onclick: (e) => { e.stopPropagation(); cb.onGoto(s.from); } }, s.id),
            h('span', { class: 'rze-tests-kind', text: s.kind }),
            h('span', { class: 'rze-toolbar-fill' }),
            h('span', { class: 'rze-try-state', text: s.unsupported ? '?' : s.hits.length ? t('tryFound', { n: s.hits.length }) : t('tryNotFound') })),
        open && more.length ? h('div', { class: 'rze-try-string-more' }, ...more) : '');
}

// ── details under the verdict: strings and condition, foldable, with a search ─────────────────
//
// What is folded and what is searched is kept on the panel element (el._tryView), so it survives
// the re-render that follows every keystroke in the sample.

function view(el) {
    return el._tryView || (el._tryView = { query: '', closed: new Set(), search: null });
}

function rerender(el) {
    const [state, cb] = el._tryLast;
    renderTry(el, state, cb);
}

/** Fold / unfold `key`; the clicked line stays at the same place on screen. */
function toggle(el, key) {
    const v = view(el);
    const find = () => el.querySelector(`[data-try-key="${CSS.escape(key)}"]`);
    const before = find();
    const top = before ? before.getBoundingClientRect().top : null;
    if (v.closed.has(key)) v.closed.delete(key); else v.closed.add(key);
    rerender(el);
    const after = find();
    const body = el.querySelector('.rze-try-body');
    if (top !== null && after && body) body.scrollTop += after.getBoundingClientRect().top - top;
}

const caret = (open) => h('span', { class: 'rze-try-caret', text: open ? '▾' : '▸' });

function details(el, r, cb) {
    const { t } = cb;
    const v = view(el);
    const q = v.query.trim().toLowerCase();
    const hit = (text) => !!q && String(text || '').toLowerCase().includes(q);

    // the search box is kept from one render to the next too (focus and caret stay)
    if (!v.search) {
        v.search = h('input', { type: 'search', class: 'rze-try-search-input', placeholder: t('trySearch') });
        v.search.addEventListener('input', () => { v.query = v.search.value; rerender(el); v.search.focus({ preventScroll: true }); });
    }
    const keys = [];
    const walk = (n, path) => { if ((n.children || []).length) { keys.push(path); n.children.forEach((c, i) => walk(c, `${path}.${i}`)); } };
    walk(r.condition, 'c');
    const bar = h('div', { class: 'rze-try-search' }, icon('search'), v.search,
        h('button', { type: 'button', class: 'rze-btn rze-btn-sm', onclick: () => { v.closed.clear(); rerender(el); } }, t('tryExpandAll')),
        h('button', { type: 'button', class: 'rze-btn rze-btn-sm', onclick: () => { keys.concat(['strings'], r.strings.map(x => `s:${x.id}`)).forEach(k => v.closed.add(k)); rerender(el); } }, t('tryCollapseAll')));

    const out = h('div', { class: 'rze-try-details' }, bar);

    if (r.strings.length) {
        const rows = r.strings.filter(x => !q || [x.id, x.kind, ...(x.modifiers || []), x.note, x.unsupported].some(hit));
        const open = !v.closed.has('strings') || !!q;
        out.appendChild(h('button', { type: 'button', class: 'rze-try-caption rze-try-section', 'data-try-key': 'strings', 'aria-expanded': String(open), onclick: () => toggle(el, 'strings') },
            caret(open), t('tryStrings'), h('span', { class: 'rze-try-count', text: q ? `${rows.length} / ${r.strings.length}` : String(r.strings.length) })));
        if (open) out.appendChild(rows.length
            ? h('div', { class: 'rze-try-strings' }, ...rows.map(x => stringRow(x, cb, { el, v, q, hit })))
            : h('div', { class: 'rze-empty', text: t('tryNoHit') }));
    }

    const tree = treeNode(r.condition, 'c', { el, cb, q, hit, v });
    const open = !v.closed.has('cond') || !!q;
    out.appendChild(h('button', { type: 'button', class: 'rze-try-caption rze-try-section', 'data-try-key': 'cond', 'aria-expanded': String(open), onclick: () => toggle(el, 'cond') },
        caret(open), t('tryCondition')));
    if (open) out.appendChild(tree ? h('ul', { class: 'rze-try-tree' }, tree) : h('div', { class: 'rze-empty', text: t('tryNoHit') }));
    return out;
}

/** One node of the condition; null when a search is on and neither it nor a child matches. */
function treeNode(n, path, ctx) {
    const { el, q, hit, v } = ctx;
    const kids = (n.children || []).map((k, i) => treeNode(k, `${path}.${i}`, ctx)).filter(Boolean);
    const self = hit(n.text) || hit(n.note) || hit(VALUE(n.value));
    if (q && !self && !kids.length) return null;
    const foldable = (n.children || []).length > 0;
    const open = foldable && (!v.closed.has(path) || (!!q && kids.length > 0));
    return h('li', { class: `rze-try-node rze-tone-${TONE(truth(n))}${self ? ' rze-try-hit' : ''}` },
        h('div', { class: `rze-try-line${foldable ? ' rze-try-foldable' : ''}`, 'data-try-key': path, onclick: foldable ? () => toggle(el, path) : null },
            foldable ? caret(open) : h('span', { class: 'rze-try-dot' }),
            n.kind === 'and' || n.kind === 'or' || n.kind === 'not' ? h('b', { class: 'rze-try-op', text: n.kind.toUpperCase() }) : '',
            h('code', { class: 'rze-try-text', text: n.text, title: n.text }),
            h('span', { class: 'rze-try-value', text: VALUE(n.value) }),
            n.note ? h('small', { class: 'rze-try-note-inline', text: n.note }) : ''),
        open && kids.length ? h('ul', {}, ...kids) : '');
}
