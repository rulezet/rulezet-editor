/**
 * Test panel: choose sample sets, run the document on them (host: rulezet-tester), watch every
 * sample turn into a verdict, search and filter the results, open a sample to see each match in
 * its surroundings (hex + ASCII, the match highlighted) while the matched strings light up in the
 * rule. Plain DOM, the same for every format; the pack's `test` profile only says how a hit reads
 * (hitLabel) and where it points in the rule (locate).
 *
 * state: { sets, chosen: Set, expanded: Set, focus, query, filter, limits, run, error, loading, stale, starting }
 */
import { h, icon } from './dom.js';

const OUTCOME = {
    detected:       { tone: 'ok',      key: 'tDetected' },
    clean:          { tone: 'ok',      key: 'tClean' },
    missed:         { tone: 'error',   key: 'tMissed' },
    false_positive: { tone: 'error',   key: 'tFalsePositive' },
    matched:        { tone: 'info',    key: 'tMatched' },
    not_matched:    { tone: 'muted',   key: 'tNotMatched' },
    timeout:        { tone: 'warning', key: 'tTimeout' },
    error:          { tone: 'error',   key: 'tError' },
};
const KIND_KEY = { benign: 'tBenign', malicious: 'tMalicious', synthetic: 'tSynthetic' };
const FILTERS = [
    { id: 'all',     key: 'tAll',            test: () => true },
    { id: 'match',   key: 'tWithMatches',    test: s => s.verdict === 'match' },
    { id: 'fp',      key: 'tFalsePositives', test: s => s.outcome === 'false_positive', tone: 'error' },
    { id: 'missed',  key: 'tMissedPlural',   test: s => s.outcome === 'missed', tone: 'error' },
    { id: 'problem', key: 'tProblems',       test: s => s.verdict === 'error' || s.verdict === 'timeout', tone: 'warning' },
];
const PAGE = 100;

export function renderTests(el, state, cb) {
    const { t } = cb;
    const run = state.run;
    const busy = state.starting || (run && (run.status === 'queued' || run.status === 'running'));

    // keep what the user is doing across re-renders (polling re-renders every few hundred ms)
    const prevBody = el.querySelector('.rze-tests-body');
    const scrollTop = prevBody ? prevBody.scrollTop : 0;
    const inner = {};
    el.querySelectorAll('[data-scroll-key]').forEach(n => { inner[n.dataset.scrollKey] = n.scrollTop; });
    const prevSearch = el.querySelector('.rze-tests-search input');
    const searchFocused = prevSearch && document.activeElement === prevSearch;
    const caret = searchFocused ? [prevSearch.selectionStart, prevSearch.selectionEnd] : null;
    const prevSetsSearch = el.querySelector('[data-sets-search]');
    const setsCaret = prevSetsSearch && document.activeElement === prevSetsSearch
        ? [prevSetsSearch.selectionStart, prevSetsSearch.selectionEnd] : null;

    const head = h('div', { class: 'rze-panel-head rze-tests-head' },
        h('strong', { class: 'rze-tests-title' }, icon('play'), t('tests')),
        run ? summary(run, t) : '',
        h('span', { class: 'rze-toolbar-fill' }),
        h('button', {
            type: 'button', class: 'rze-btn rze-btn-primary', disabled: busy || !state.chosen.size || state.loading,
            title: `${t('tRun')} (Ctrl+Shift+Enter)`, onclick: cb.onRun,
        }, icon(busy ? 'cloud' : 'play'), h('span', { class: 'rze-btn-label', text: busy ? t('tRunning') : t('tRun') })),
        h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: cb.onClose }, icon('close')));

    const body = h('div', { class: 'rze-tests-body' });

    // ── sets to run on ──
    if (state.loading) body.appendChild(h('div', { class: 'rze-empty', text: t('tLoading') }));
    else if (!state.sets || !state.sets.length) body.appendChild(h('div', { class: 'rze-empty', text: state.error || t('tNoSets') }));
    else body.appendChild(renderSets(state, cb, busy));

    if (state.error && state.sets && state.sets.length) body.appendChild(note('error', state.error));
    if (run && run.error) body.appendChild(note('error', run.error));
    if (run && state.stale) body.appendChild(note('muted', t('tStale')));

    // ── search + filters ──
    let searchInput = null;
    if (run) {
        const counts = Object.fromEntries(FILTERS.map(f => [f.id, run.samples.filter(f.test).length]));
        searchInput = h('input', {
            type: 'search', value: state.query, placeholder: t('tSearch'), 'aria-label': t('tSearch'),
            oninput: e => cb.onQuery(e.target.value),
            onkeydown: e => { if (e.key === 'Escape' && state.query) { e.preventDefault(); cb.onQuery(''); } },
        });
        body.appendChild(h('div', { class: 'rze-tests-tools' },
            h('label', { class: 'rze-tests-search' }, icon('search'), searchInput),
            h('div', { class: 'rze-tests-filters', role: 'tablist' },
                ...FILTERS.map(f => h('button', {
                    type: 'button', role: 'tab', 'aria-selected': String(state.filter === f.id),
                    class: `rze-tests-filter${state.filter === f.id ? ' rze-on' : ''}${f.tone && counts[f.id] ? ` rze-tone-${f.tone}` : ''}`,
                    disabled: f.id !== 'all' && !counts[f.id] && state.filter !== f.id,
                    onclick: () => cb.onFilter(f.id),
                }, t(f.key), h('b', { text: String(counts[f.id]) }))))));
    }

    // ── results, one card per set ──
    if (run) {
        const filter = FILTERS.find(f => f.id === state.filter) || FILTERS[0];
        const q = state.query.trim().toLowerCase();
        const matchesQuery = (s) => !q || [s.label, s.sha256, s.outcome, s.verdict, ...(s.hits || []).map(x => `${x.rule} ${x.item || ''}`)]
            .some(v => v && String(v).toLowerCase().includes(q));
        let shownTotal = 0;
        for (const set of run.sets) {
            const all = run.samples.filter(x => x.set === set.id);
            const samples = all.filter(s => filter.test(s) && matchesQuery(s));
            if (!samples.length && (q || filter.id !== 'all')) continue;
            shownTotal += samples.length;
            const limit = state.limits[set.id] || PAGE;
            const bad = set.false_positives || set.missed;
            body.appendChild(h('section', { class: `rze-tests-card${bad ? ' rze-tests-card-bad' : ''}` },
                h('header', { class: 'rze-tests-card-head' },
                    h('span', { class: 'rze-tests-card-name', text: set.name }),
                    kindBadge(set.kind, t),
                    h('span', { class: 'rze-tests-card-line', text: groupLine(set, t) }),
                    samples.length !== all.length ? h('span', { class: 'rze-tests-card-line', text: `· ${t('tShown', { n: samples.length })}` }) : '',
                    h('span', { class: 'rze-toolbar-fill' }),
                    h('span', { class: 'rze-tests-mini', title: `${set.done} / ${set.total}` },
                        h('span', { style: { width: `${set.total ? Math.round((set.done / set.total) * 100) : 0}%` } }))),
                ...samples.slice(0, limit).map(smp => sampleRow(smp, state, cb)),
                samples.length > limit ? h('button', { type: 'button', class: 'rze-tests-more-btn', onclick: () => cb.onMore(set.id) },
                    t('tShowMore', { n: Math.min(200, samples.length - limit), total: samples.length - limit })) : ''));
        }
        if (!shownTotal && (q || filter.id !== 'all')) body.appendChild(h('div', { class: 'rze-empty', text: t('tNoResult') }));
    }

    el.replaceChildren(head, body);
    body.scrollTop = scrollTop;
    el.querySelectorAll('[data-scroll-key]').forEach(n => { if (inner[n.dataset.scrollKey]) n.scrollTop = inner[n.dataset.scrollKey]; });
    if (searchFocused && searchInput) {
        searchInput.focus();
        searchInput.setSelectionRange(caret[0], caret[1]);
    }
    const setsSearch = setsCaret && el.querySelector('[data-sets-search]');
    if (setsSearch) {
        setsSearch.focus();
        setsSearch.setSelectionRange(setsCaret[0], setsCaret[1]);
    }
}

function summary(run, t) {
    const s = run.summary;
    const pill = (tone, n, label, title) => h('span', { class: `rze-tests-kpi rze-tone-${n ? tone : 'muted'}`, title },
        h('b', { text: String(n) }), label);
    return h('span', { class: 'rze-tests-kpis' },
        pill('error', s.false_positives, s.false_positives === 1 ? t('tFalsePositiveOne') : t('tFalsePositives'), t('tFpHint')),
        pill('error', s.missed, t('tMissedPlural'), t('tMissedHint')),
        pill('ok', s.detected, t('tDetectedPlural'), t('tDetectedHint')),
        s.timeouts ? pill('warning', s.timeouts, t('tTimeouts')) : '',
        s.errors ? pill('warning', s.errors, t('tErrors')) : '',
        h('span', { class: 'rze-tests-progress-text', text: `${s.done} / ${s.total}` }),
        h('span', { class: 'rze-tests-mini rze-tests-mini-wide' },
            h('span', { style: { width: `${s.total ? Math.round((s.done / s.total) * 100) : 0}%` } })));
}

// sample sets, grouped by what they prove: malicious first (detections), then benign (false
// positives), then crafted test files; sets of a kind the tester does not know go last
const KIND_ORDER = ['malicious', 'benign', 'synthetic'];
const KIND_HINT = { malicious: 'tKindMaliciousHint', benign: 'tKindBenignHint', synthetic: 'tKindSyntheticHint' };

function renderSets(state, cb, busy) {
    const { t } = cb;
    const sets = state.sets;
    const chosen = sets.filter(s => state.chosen.has(s.id));
    const samples = chosen.reduce((n, s) => n + (s.count || 0), 0);
    const open = state.setsOpen !== false;
    const query = (state.setsQuery || '').trim().toLowerCase();

    const head = h('div', { class: 'rze-sets-head' },
        h('button', {
            type: 'button', class: 'rze-sets-toggle', 'aria-expanded': String(open),
            onclick: () => cb.onSetsOpen(!open),
        }, h('span', { class: `rze-sets-chevron${open ? ' rze-open' : ''}`, text: '▸' }),
            h('span', { class: 'rze-tests-caption', text: t('tSets') }),
            h('span', { class: 'rze-sets-summary', text: t('tSetsSummary', { n: chosen.length, total: sets.length, samples }) })),
        h('span', { class: 'rze-toolbar-fill' }),
        open ? h('button', { type: 'button', class: 'rze-link-btn', disabled: busy, onclick: () => cb.onToggleSets(sets.map(x => x.id), true), text: t('tSelectAll') }) : '',
        open ? h('button', { type: 'button', class: 'rze-link-btn', disabled: busy, onclick: () => cb.onToggleSets(sets.map(x => x.id), false), text: t('tSelectNone') }) : '');
    if (!open) return h('div', { class: 'rze-sets rze-sets-closed', role: 'group', 'aria-label': t('tSets') }, head);

    const wrap = h('div', { class: 'rze-sets', role: 'group', 'aria-label': t('tSets') }, head);
    if (sets.length > 6) {
        wrap.appendChild(h('label', { class: 'rze-sets-search' }, icon('search'),
            h('input', { type: 'search', value: state.setsQuery || '', placeholder: t('tSetsSearch'), 'data-sets-search': '1',
                         oninput: e => cb.onSetsQuery(e.target.value) })));
    }
    const kinds = [...KIND_ORDER, ...new Set(sets.map(x => x.kind).filter(k => !KIND_ORDER.includes(k)))];
    for (const kind of kinds) {
        const all = sets.filter(x => x.kind === kind);
        const shown = all.filter(x => !query || [x.name, x.description, x.source, ...Object.entries(x.labels || {}).flat()]
            .some(v => String(v || '').toLowerCase().includes(query)));
        if (!shown.length) continue;
        const on = all.filter(x => state.chosen.has(x.id)).length;
        const box = h('input', { type: 'checkbox', checked: on === all.length, disabled: busy,
                                 onchange: e => cb.onToggleSets(all.map(x => x.id), e.target.checked) });
        box.indeterminate = on > 0 && on < all.length;
        wrap.appendChild(h('div', { class: `rze-sets-group rze-group-${kind}` },
            h('label', { class: 'rze-sets-group-head' }, box, kindBadge(kind, t),
                h('span', { class: 'rze-sets-group-hint', text: KIND_HINT[kind] ? t(KIND_HINT[kind]) : '' }),
                h('span', { class: 'rze-toolbar-fill' }),
                h('span', { class: 'rze-tests-muted', text: t('tSetsChosen', { n: on, total: all.length }) })),
            ...shown.map(set => setRow(set, state, cb, busy))));
    }
    return wrap;
}

function setRow(set, state, cb, busy) {
    const { t } = cb;
    const on = state.chosen.has(set.id);
    const labels = Object.entries(set.labels || {});
    return h('label', { class: `rze-set${on ? ' rze-on' : ''}`, title: set.description || '' },
        h('input', { type: 'checkbox', checked: on, disabled: busy, onchange: e => cb.onToggleSet(set.id, e.target.checked) }),
        h('span', { class: 'rze-set-main' },
            h('span', { class: 'rze-set-name', text: set.name }),
            set.description ? h('span', { class: 'rze-set-desc', text: set.description }) : '',
            (labels.length || set.source || set.encrypted || (set.tlp && set.tlp !== 'clear'))
                ? h('span', { class: 'rze-set-meta' },
                    ...labels.map(([k, v]) => h('span', { class: 'rze-set-chip', text: `${k}: ${v}` })),
                    set.encrypted ? h('span', { class: 'rze-set-chip rze-set-chip-lock' }, icon('lock'), h('span', { text: t('tEncrypted') })) : '',
                    set.tlp && set.tlp !== 'clear' ? h('span', { class: 'rze-set-chip', text: `TLP:${set.tlp.toUpperCase()}` }) : '',
                    set.source ? h('span', { class: 'rze-set-source', text: set.source }) : '')
                : ''),
        h('span', { class: 'rze-set-count' }, h('b', { text: String(set.count ?? 0) }), h('span', { text: t('tSamplesWord') })));
}

function kindBadge(kind, t) {
    return h('span', { class: `rze-tests-kind rze-kind-${kind}`, text: t(KIND_KEY[kind] || kind) });
}

function note(tone, text) {
    return h('div', { class: `rze-tests-note rze-tone-${tone}` }, icon(tone === 'error' ? 'error' : 'info'), h('span', { text }));
}

function groupLine(set, t) {
    const parts = [`${set.done} / ${set.total}`];
    if (set.kind === 'benign') parts.push(`${set.false_positives} ${set.false_positives === 1 ? t('tFalsePositiveOne') : t('tFalsePositives')}`);
    else if (set.kind === 'malicious') parts.push(`${set.matched} ${t('tDetectedPlural')}`, `${set.missed} ${t('tMissedPlural')}`);
    else parts.push(`${set.matched} ${t('tMatched').toLowerCase()}`);
    return parts.join(' · ');
}

/** Hits grouped by what matched in the rule ($a: 17 times). */
function groups(hits) {
    const by = new Map();
    for (const hit of hits) {
        const key = `${hit.rule}\u0000${hit.item || ''}`;
        if (!by.has(key)) by.set(key, { rule: hit.rule, item: hit.item, hits: [] });
        by.get(key).hits.push(hit);
    }
    return [...by.values()];
}

function sampleRow(smp, state, { t, profile, onHit, onToggleSample }) {
    const open = state.expanded.has(smp.id);
    const focused = state.focus === smp.id;
    const o = OUTCOME[smp.outcome];
    const tone = smp.verdict === 'pending' ? 'pending' : (o ? o.tone : 'muted');
    const hits = smp.hits || [];
    const canOpen = hits.length > 0 || !!smp.error;
    const g = groups(hits);
    const total = smp.hit_total || hits.length;

    const row = h('div', {
        class: `rze-tests-row rze-row-${tone}${open ? ' rze-open' : ''}${focused ? ' rze-focused' : ''}${canOpen ? ' rze-clickable' : ''}`,
        role: canOpen ? 'button' : null, tabindex: canOpen ? '0' : null, 'aria-expanded': canOpen ? String(open) : null,
        onclick: canOpen ? () => onToggleSample(smp.id) : null,
        onkeydown: canOpen ? (e) => { if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); onToggleSample(smp.id); } } : null,
    },
        h('span', { class: `rze-tests-badge rze-tone-${tone}`, text: smp.verdict === 'pending' ? t('tPending') : (o ? t(o.key) : smp.verdict) }),
        h('span', { class: 'rze-tests-label', title: smp.label, text: smp.label }),
        h('span', { class: 'rze-tests-chips' },
            ...g.slice(0, 4).map(x => h('button', {
                type: 'button', class: 'rze-tests-chip', title: t('tShowInRule'),
                onclick: (e) => { e.stopPropagation(); onHit(x.hits[0], smp.id); },
            }, h('span', { text: x.item || x.rule }), h('b', { text: `×${x.hits.length}` }))),
            g.length > 4 ? h('span', { class: 'rze-tests-more', text: `+${g.length - 4}` }) : ''),
        h('span', { class: 'rze-tests-meta', text: [formatSize(smp.size), smp.time_ms != null ? `${smp.time_ms} ms` : ''].filter(Boolean).join(' · ') }),
        canOpen ? h('span', { class: 'rze-tests-chevron', text: open ? '▾' : '▸' }) : h('span', { class: 'rze-tests-chevron' }));

    if (!open) return row;

    const detail = h('div', { class: 'rze-tests-detail' },
        h('div', { class: 'rze-tests-facts' },
            fact('SHA-256', smp.sha256, true),
            fact(t('tSize'), smp.size != null ? `${formatSize(smp.size)} (${smp.size} B)` : ''),
            fact(t('tHits'), total > hits.length ? t('tHitsShown', { shown: hits.length, total }) : String(total)),
            smp.expected && smp.expected !== 'unknown' ? fact(t('tExpected'), smp.expected === 'match' ? t('tExpectMatch') : t('tExpectNoMatch')) : ''),
        smp.error ? note('error', smp.error) : '',
        hits.length && !state.stale ? h('div', { class: 'rze-tests-legend' }, h('span', { class: 'rze-test-mark', text: '$str' }), t('tHighlightLegend')) : '',
        ...g.map(x => h('div', { class: 'rze-tests-hitgroup' },
            h('div', { class: 'rze-tests-hitgroup-head' },
                h('button', { type: 'button', class: 'rze-tests-chip', title: t('tShowInRule'), onclick: () => onHit(x.hits[0], smp.id) },
                    h('span', { text: x.item || t('tCondition') })),
                h('span', { class: 'rze-tests-muted', text: `${t('rule')} ${x.rule} · ${x.hits.length} ${x.hits.length === 1 ? t('tHitOne') : t('tHitMany')}` })),
            x.hits[0].where && x.hits[0].where.kind === 'offset'
                ? h('div', { class: 'rze-tests-hits-wrap', 'data-scroll-key': `${smp.id}\u0000${x.rule}\u0000${x.item}` },
                    h('table', { class: 'rze-tests-hits' },
                        h('thead', {}, h('tr', {},
                            h('th', { class: 'rze-col-offset', text: t('tWhere') }),
                            h('th', { class: 'rze-col-len', text: t('tLength') }),
                            h('th', { text: t('tInContext') }))),
                        h('tbody', {}, ...x.hits.map(hit => h('tr', { title: t('tShowInRule'), onclick: () => onHit(hit, smp.id) },
                            h('td', { class: 'rze-mono', text: where(hit, profile) }),
                            h('td', { class: 'rze-mono', text: hit.where.length != null ? `${hit.where.length} B` : '' }),
                            h('td', {}, contextView(hit)))))))
                : h('div', { class: 'rze-tests-muted rze-tests-cond', text: t('tConditionOnly') }))));
    return h('div', { class: `rze-tests-item${focused ? ' rze-focused' : ''}` }, row, detail);
}

/** The match in its surroundings: ASCII line and hex line, the matched bytes highlighted. */
function contextView(hit) {
    const before = bytes(hit.before);
    const match = bytes(hit.data);
    const after = bytes(hit.after);
    const truncated = hit.where && hit.where.length > match.length;
    const ascii = (arr) => arr.map(c => (c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '·')).join('');
    const hex = (arr) => arr.map(c => c.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    return h('div', { class: 'rze-tests-ctx' },
        h('div', { class: 'rze-tests-ctx-ascii rze-mono' },
            h('span', { class: 'rze-tests-ctx-dim', text: ascii(before) }),
            h('mark', { text: ascii(match) + (truncated ? '…' : '') }),
            h('span', { class: 'rze-tests-ctx-dim', text: ascii(after) })),
        h('div', { class: 'rze-tests-ctx-hex rze-mono' },
            h('span', { class: 'rze-tests-ctx-dim', text: before.length ? hex(before) + ' ' : '' }),
            h('mark', { text: hex(match) + (truncated ? ' …' : '') }),
            h('span', { class: 'rze-tests-ctx-dim', text: after.length ? ' ' + hex(after) : '' })));
}

function bytes(hexStr) {
    if (!hexStr) return [];
    const out = [];
    for (let i = 0; i + 1 < hexStr.length; i += 2) out.push(parseInt(hexStr.slice(i, i + 2), 16));
    return out;
}

function fact(label, value, mono = false) {
    if (!value) return '';
    return h('div', { class: 'rze-tests-fact' }, h('span', { text: label }), h('b', { class: mono ? 'rze-mono' : '', text: value }));
}

function where(hit, profile) {
    const w = hit.where || {};
    if (w.kind === 'offset') return `0x${w.offset.toString(16).padStart(8, '0')}`;
    return profile && profile.hitLabel ? profile.hitLabel(hit) : (w.kind || '');
}

function formatSize(n) {
    if (n == null) return '';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
