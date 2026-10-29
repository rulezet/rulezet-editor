/**
 * "Checks" panel: every opinion on the document in one place, one section each.
 *
 *   1. the host's own check (Rulezet: its compiler, with the rules the document needs) — the one
 *      that decides whether the rules can be saved;
 *   2. the host's external tools (Rulezet: YARA-X, the CCCS YARA standard, yaraQA) — advice only.
 *
 * Plain DOM. A remark with a line jumps there on click; a tool that offers a corrected version
 * (YARA-X formatting, CCCS metadata) gets an "Apply" button, enabled while the document is still
 * the one that was checked.
 *
 * state: { open, running, error, host: { name, ok, items } | null, tools: { id: result } | null, stale }
 *   result: { available, ok, reason?, errors[], warnings[], fixed_text? }
 *   item:   { message, line?, column?, code?, level|severity, rule?, detail?, element? }
 */
import { h, icon } from './dom.js';

const TOOLS = {
    yarax: { name: 'YARA-X', about: 'The new YARA engine (VirusTotal): diagnostics and formatter', apply: 'Apply YARA-X formatting', url: 'https://github.com/VirusTotal/yara-x' },
    cccs: { name: 'CCCS YARA standard', about: 'Metadata checked against the CCCS specification', apply: 'Apply CCCS metadata', url: 'https://github.com/CybercentreCanada/CCCS-Yara' },
    yaraqa: { name: 'yaraQA', about: 'Logic and performance advice on strings and conditions', apply: null, url: 'https://github.com/Neo23x0/yaraQA' },
};

const level = (d) => d.level || d.severity || 'warning';

function items(list, cb) {
    return h('ul', { class: 'rze-checks-list' }, ...list.map(d => h('li', {
        class: `rze-checks-item rze-sev-${level(d) === 'error' ? 'error' : level(d) === 'info' ? 'info' : 'warning'}${d.line ? ' rze-clickable' : ''}`,
        onclick: d.line ? () => cb.onGoto(d.line, d.column) : null,
    },
        d.line ? h('span', { class: 'rze-checks-pos', text: `${cb.t('line')} ${d.line}` }) : '',
        d.rule ? h('span', { class: 'rze-checks-pos', text: d.rule }) : '',
        h('span', { class: 'rze-checks-msg', text: d.message || '' }),
        d.code ? h('span', { class: 'rze-checks-code', text: d.code }) : '',
        // what the tool says about it (CCCS: the field's purpose and accepted values; yaraQA: its advice;
        // YARA-X: the full diagnostic) and, when there is one, the line to add / the element concerned
        d.detail ? h('div', { class: 'rze-checks-explain', text: d.detail }) : '',
        d.element ? h('div', { class: 'rze-checks-detail' }, h('code', { text: d.element })) : '')));
}

function section({ title, sub, tone, badge, body, actions = [], link }) {
    return h('section', { class: `rze-checks-section rze-tone-${tone}` },
        h('div', { class: 'rze-checks-section-head' },
            h('strong', { text: title }),
            link ? h('a', { href: link, target: '_blank', rel: 'noopener', class: 'rze-checks-link', text: '↗' }) : '',
            h('span', { class: `rze-checks-badge rze-tone-${tone}`, text: badge })),
        sub ? h('div', { class: 'rze-checks-sub', text: sub }) : '',
        body || '',
        actions.length ? h('div', { class: 'rze-checks-actions' }, ...actions) : '');
}

export function renderChecks(el, state, cb) {
    const { t } = cb;
    const count = (r) => (r.errors || []).length + (r.warnings || []).length;
    const head = h('div', { class: 'rze-panel-head' },
        h('strong', { class: 'rze-tests-title' }, icon('ok'), t('checks')),
        h('span', { class: 'rze-checks-hint', text: t('checksHint') }),
        h('button', { type: 'button', class: 'rze-btn rze-btn-primary', disabled: state.running, onclick: cb.onRun, 'aria-busy': state.running ? 'true' : 'false' },
            state.running ? h('span', { class: 'rze-spinner', 'aria-hidden': 'true' }) : icon('play'),
            state.running ? t('checksRunning') : t('checksRun')),
        h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: cb.onClose }, icon('close')));

    const sections = [];
    // while it runs: one line per check, each with its spinner, so it is clear something is happening
    if (state.running) {
        const names = [cb.hostName, ...(cb.toolNames || [])].filter(Boolean);
        sections.push(h('div', { class: 'rze-checks-running', role: 'status', 'aria-live': 'polite' },
            ...names.map(n => h('div', { class: 'rze-checks-running-row' }, h('span', { class: 'rze-spinner' }), h('span', { text: t('checksRunningOne', { name: n }) })))));
        el.replaceChildren(head, h('div', { class: 'rze-checks-body' }, ...sections));
        return;
    }
    if (state.error) sections.push(h('div', { class: 'rze-checks-error', text: state.error }));
    if (state.stale && (state.host || state.tools)) sections.push(h('div', { class: 'rze-checks-stale', text: t('checksStale') }));

    if (state.host) {
        const errs = state.host.items.filter(d => level(d) === 'error');
        sections.push(section({
            title: `${state.host.name} — ${t('checksHost')}`, sub: t('checksHostSub'),
            tone: errs.length ? 'error' : state.host.items.length ? 'warning' : 'ok',
            badge: errs.length ? t('checksErrors', { n: errs.length }) : state.host.items.length ? t('checksRemarks', { n: state.host.items.length }) : t('checksValid'),
            body: state.host.items.length ? items(state.host.items, cb) : null,
        }));
    }
    for (const [id, r] of Object.entries(state.tools || {})) {
        const info = TOOLS[id] || { name: id, about: '', apply: null };
        const n = r.available ? count(r) : 0;
        const actions = info.apply && r.fixed_text ? [h('button', { type: 'button', class: 'rze-btn', disabled: state.stale,
            title: state.stale ? t('checksStale') : '', onclick: () => cb.onApply(id) }, icon('edit'), info.apply)] : [];
        sections.push(section({
            title: info.name, sub: r.available ? `${info.about} — ${t('checksAdvice')}` : r.reason, link: info.url,
            tone: !r.available ? 'muted' : n ? 'warning' : 'ok',
            badge: !r.available ? t('checksOff') : n ? t('checksRemarks', { n }) : t('checksNone'),
            body: r.available && n ? items([...(r.errors || []), ...(r.warnings || [])], cb) : null,
            actions,
        }));
    }
    if (!sections.length) sections.push(h('div', { class: 'rze-checks-empty', text: t('checksEmpty') }));
    el.replaceChildren(head, h('div', { class: 'rze-checks-body' }, ...sections));
}
