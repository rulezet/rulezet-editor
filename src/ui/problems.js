/** Problems panel: every diagnostic, grouped by rule, with quick fixes. */
import { h, icon } from './dom.js';

export function renderProblems(el, diagnostics, { t, rules, onSelect, onFix, onClose }) {
    const ruleOf = (d) => rules.find(r => d.from >= r.from && d.from <= r.to);
    const groups = new Map();
    for (const d of diagnostics) {
        const r = ruleOf(d);
        const key = r ? `${r.from}` : 'doc';
        if (!groups.has(key)) groups.set(key, { title: r ? r.name : 'Document', items: [] });
        groups.get(key).items.push(d);
    }

    const body = h('div', { class: 'rze-problems-body' });
    if (!diagnostics.length) body.appendChild(h('div', { class: 'rze-empty' }, icon('ok', 'rze-sev-ok'), ' ', t('noProblems')));
    for (const g of groups.values()) {
        body.appendChild(h('div', { class: 'rze-problems-group', text: `${g.title} (${g.items.length})` }));
        for (const d of g.items) {
            const sev = d.severity === 'hint' ? 'info' : d.severity;
            body.appendChild(h('div', { class: 'rze-problem', role: 'button', tabindex: '0', onclick: () => onSelect(d), onkeydown: e => { if (e.key === 'Enter') onSelect(d); } },
                icon(sev, `rze-sev-${sev}`),
                h('span', { class: 'rze-problem-msg', text: d.message }),
                d.source ? h('span', { class: 'rze-problem-src', text: d.source }) : '',
                h('span', { class: 'rze-problem-pos', text: `${t('line')} ${d.line}, ${t('col')} ${d.column}` }),
                ...(d.actions || []).map(a => h('button', {
                    type: 'button', class: 'rze-btn rze-btn-fix',
                    onclick: (e) => { e.stopPropagation(); onFix(d, a); },
                }, a.name)),
            ));
        }
    }

    const counts = { error: 0, warning: 0, info: 0 };
    for (const d of diagnostics) counts[d.severity === 'hint' ? 'info' : d.severity]++;
    el.replaceChildren(
        h('div', { class: 'rze-panel-head' },
            h('strong', { text: t('problems') }),
            h('span', { class: 'rze-sev-error', text: `${counts.error} ${t('errors')}` }),
            h('span', { class: 'rze-sev-warning', text: `${counts.warning} ${t('warnings')}` }),
            h('span', { class: 'rze-sev-info', text: `${counts.info} ${t('infos')}` }),
            h('span', { class: 'rze-toolbar-fill' }),
            h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: onClose }, icon('close'))),
        body,
    );
}
