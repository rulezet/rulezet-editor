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
 *   result: { available, ok, reason?, meta?: { name, about, url, apply? },
 *             errors[], warnings[]   remarks (a line jumps to it)
 *             infos[]?               notes, folded
 *             outputs[]?             { label, text, ok?, detail?, rule?, line? }: something to read or copy (a SIEM query),
 *                                    green when ok, red when not (ok: false)
 *             score?                 { value, max, parts: { dimension: value } }: a gauge, green ≥ 80 %, orange ≥ 50 %
 *             fixed_text? }          a corrected document: "Apply" button (meta.apply)
 *   item:   { message, line?, column?, code?, level|severity, rule?, detail?, element?, url? }
 * The host describes its tools (meta): a new format brings its tools without touching this file;
 * TOOLS below only names the ones of hosts that send no meta.
 */
import { h, icon } from './dom.js';

export const TOOLS = {
    yarax: { name: 'YARA-X', about: 'The new YARA engine (VirusTotal): diagnostics and formatter', apply: 'Apply YARA-X formatting', url: 'https://github.com/VirusTotal/yara-x' },
    cccs: { name: 'CCCS YARA standard', about: 'Metadata checked against the CCCS specification', apply: 'Apply CCCS metadata', url: 'https://github.com/CybercentreCanada/CCCS-Yara' },
    yaraqa: { name: 'yaraQA', about: 'Logic and performance advice on strings and conditions', apply: null, url: 'https://github.com/Neo23x0/yaraQA' },
    siem: { name: 'SIEM conversion (pySigma)', about: 'The rule as a query for each SIEM, or why it cannot be converted', apply: null, url: 'https://github.com/SigmaHQ/pySigma' },
    sigmahq: { name: 'SigmaHQ conventions', about: 'What the SigmaHQ repository enforces on its rules, and the file name it would give', apply: null, url: 'https://github.com/SigmaHQ/sigma/blob/master/tests/test_rules.py' },
    sigmalint: { name: 'sigmalint', about: 'Findings by quality dimension and a score out of 100', apply: null, url: 'https://github.com/ni5h4nt/sigmalint' },
    rsigma: { name: 'rsigma lint', about: 'The Sigma 2.1 specification checks of rsigma', apply: null, url: 'https://rsigma.io/' },
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
        // a link the tool gives (the rule it is a copy of…), opened without jumping to the line
        d.url ? h('a', { class: 'rze-checks-open', href: d.url, target: '_blank', rel: 'noopener', text: cb.t('openIt'), onclick: (e) => e.stopPropagation() }) : '',
        // what the tool says about it (CCCS: the field's purpose and accepted values; yaraQA: its advice;
        // YARA-X: the full diagnostic) and, when there is one, the line to add / the element concerned
        d.detail ? h('div', { class: 'rze-checks-explain', text: d.detail }) : '',
        d.element ? h('div', { class: 'rze-checks-detail' }, h('code', { text: d.element })) : '')));
}

function section({ title, sub, tone, badge, body, actions = [], link, score = null }) {
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
    for (const [id, r] of Object.entries(state.tools || {})) sections.push(toolSection(id, r, state, cb));
    if (!sections.length) sections.push(h('div', { class: 'rze-checks-empty', text: t('checksEmpty') }));
    el.replaceChildren(head, h('div', { class: 'rze-checks-body' }, ...sections));
}

/** One external tool: status, score, outputs, remarks, notes. */
function toolSection(id, r, state, cb) {
    const { t } = cb;
    const info = { ...(TOOLS[id] || { name: id, about: '' }), ...(r.meta || {}) };
    if (!r.available) {
        return section({ title: info.name, sub: r.reason, link: info.url, tone: 'muted', badge: t('checksOff') });
    }
    // older hosts sent notes as warnings with level info
    const remarks = [...(r.errors || []), ...(r.warnings || []).filter(w => level(w) !== 'info')];
    const infos = [...(r.infos || []), ...(r.warnings || []).filter(w => level(w) === 'info')];
    const outputs = r.outputs || [];
    const failed = outputs.filter(o => o.ok === false).length;
    const errs = remarks.filter(d => level(d) === 'error').length;
    const scoreTone = r.score ? toneOf(r.score.value / (r.score.max || 100)) : null;
    // one output that failed (a SIEM that cannot take the rule, 4 / 5): the section is red too, and its
    // line; every output green: the section is green
    const tone = errs || failed ? 'error' : remarks.length ? 'warning' : scoreTone || 'ok';
    const badge = errs ? t('checksErrors', { n: errs })
        : outputs.length && outputs.some(o => o.ok !== undefined) ? t('checksOutputsOk', { ok: outputs.length - failed, n: outputs.length })
            : remarks.length ? t('checksRemarks', { n: remarks.length }) : t('checksNone');
    const actions = info.apply && r.fixed_text ? [h('button', { type: 'button', class: 'rze-btn', disabled: state.stale,
        title: state.stale ? t('checksStale') : '', onclick: () => cb.onApply(id) }, icon('edit'), info.apply)] : [];
    const body = [
        r.score ? scoreView(r.score) : '',
        outputs.length ? h('div', { class: 'rze-checks-outputs' }, ...outputs.map(o => outputView(o, cb))) : '',
        remarks.length ? items(remarks, cb) : '',
        infos.length ? h('details', { class: 'rze-checks-notes' },
            h('summary', { text: t('checksNotes', { n: infos.length }) }), items(infos.map(x => ({ ...x, level: 'info' })), cb)) : '',
    ].filter(Boolean);
    return section({ title: info.name, sub: `${info.about || ''}${info.about ? ' — ' : ''}${t('checksAdvice')}`, link: info.url,
        tone, badge, body: body.length ? h('div', { class: 'rze-checks-tool-body' }, ...body) : null, actions, score: r.score ? scoreTone : null });
}

function toneOf(ratio) {
    return ratio >= 0.8 ? 'ok' : ratio >= 0.5 ? 'warning' : 'error';
}

/** A score as a gauge, coloured by how good it is, with each dimension below. */
function scoreView(score) {
    const max = score.max || 100;
    const tone = toneOf(score.value / max);
    return h('div', { class: `rze-checks-score rze-tone-${tone}` },
        h('div', { class: 'rze-checks-score-head' },
            h('b', { class: 'rze-checks-score-value', text: `${score.value}` }), h('span', { class: 'rze-checks-score-max', text: ` / ${max}` }),
            h('div', { class: 'rze-checks-gauge' }, h('span', { style: { width: `${Math.max(0, Math.min(100, (score.value / max) * 100))}%` } }))),
        score.parts ? h('div', { class: 'rze-checks-score-parts' }, ...Object.entries(score.parts).map(([k, v]) =>
            h('span', { class: `rze-checks-score-part rze-tone-${toneOf(v / max)}` }, h('span', { text: k }), h('b', { text: String(v) })))) : '');
}

/** One output (a query…): green ✓ when it worked, red ✗ when not; open it to read or copy. */
function outputView(o, cb) {
    const state = o.ok === false ? 'bad' : o.ok === true ? 'good' : 'plain';
    const copy = h('button', { type: 'button', class: 'rze-btn rze-checks-copy', onclick: (e) => {
        e.preventDefault();
        try { navigator.clipboard.writeText(o.text || ''); e.currentTarget.textContent = cb.t('copied'); } catch { /* no clipboard */ }
    } }, cb.t('copy'));
    return h('details', { class: `rze-checks-output rze-checks-output-${state}` },
        h('summary', {},
            h('div', { class: 'rze-checks-output-line' },
                h('span', { class: 'rze-checks-output-mark', text: state === 'bad' ? '✗' : state === 'good' ? '✓' : '•' }),
                h('span', { class: 'rze-checks-output-label', text: o.label }),
                o.rule ? h('span', { class: 'rze-checks-pos', text: o.rule }) : ''),
            // visible without opening: what it says (fields, size…) and the start of the text
            o.detail ? h('div', { class: 'rze-checks-output-detail', text: o.detail }) : '',
            h('code', { class: 'rze-checks-output-preview', text: (o.text || '').split('\n')[0].slice(0, 160) })),
        h('div', { class: 'rze-checks-output-body' }, h('pre', { class: 'rze-mono', text: o.text || '' }), o.ok === false ? '' : copy));
}

