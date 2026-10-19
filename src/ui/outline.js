/** Rules panel: every rule of the document with its status, strings and actions. */
import { h, icon } from './dom.js';

export function renderOutline(el, rules, { t, filter, onFilter, onSelect, onSelectChild, onCopy, onClose, activeFrom }) {
    const q = filter.trim().toLowerCase();
    const shown = q ? rules.filter(r => r.name.toLowerCase().includes(q) || (r.tags || []).some(tag => tag.toLowerCase().includes(q))) : rules;
    const totals = rules.reduce((a, r) => ({ e: a.e + r.errors, w: a.w + r.warnings }), { e: 0, w: 0 });

    const prevInput = el.querySelector('.rze-outline-filter');
    const hadFocus = prevInput && document.activeElement === prevInput;
    const caret = hadFocus ? prevInput.selectionStart : null;

    const input = h('input', {
        class: 'rze-outline-filter', type: 'search', placeholder: t('filterRules'), value: filter,
        'aria-label': t('filterRules'), oninput: e => onFilter(e.target.value),
        onkeydown: e => { if (e.key === 'Enter' && shown[0]) onSelect(shown[0]); },
    });

    const list = h('ul', { class: 'rze-outline-list' });
    for (const r of shown) {
        const status = r.errors ? 'error' : r.warnings ? 'warning' : 'ok';
        const head = h('div', { class: 'rze-outline-head' },
            icon(status, `rze-sev-${status}`),
            h('button', { type: 'button', class: 'rze-outline-name', title: `${r.kind} ${r.name}`, onclick: () => onSelect(r) }, r.name),
            r.errors || r.warnings ? h('span', { class: 'rze-outline-count', text: `${r.errors ? r.errors + 'E' : ''}${r.errors && r.warnings ? ' ' : ''}${r.warnings ? r.warnings + 'W' : ''}` }) : '',
            h('button', { type: 'button', class: 'rze-icon-btn', title: t('copy'), 'aria-label': `${t('copy')} ${r.name}`, onclick: () => onCopy(r) }, icon('copy')),
        );
        const a = r.annotation;
        const note = a ? h('div', { class: `rze-outline-note rze-tone-${a.tone || 'info'}` },
            ...(a.notes || []).map(n => h('div', { text: n })),
            ...(a.links || []).map(l => h('a', { href: l.url, target: '_blank', rel: 'noopener', text: l.label }))) : '';
        const meta = h('div', { class: 'rze-outline-meta' },
            a && a.badge ? h('span', { class: `rze-chip rze-badge rze-tone-${a.tone || 'info'}`, text: a.badge }) : '',
            r.kind !== 'rule' ? h('span', { class: 'rze-chip', text: r.kind }) : '',
            ...(r.tags || []).map(tag => h('span', { class: 'rze-chip rze-chip-tag', text: tag })),
            r.detail ? h('div', { class: 'rze-outline-detail', text: r.detail }) : '',
        );
        const children = (r.children || []).length ? h('ul', { class: 'rze-outline-children' },
            ...r.children.map(c => h('li', {},
                h('button', { type: 'button', class: 'rze-outline-child', onclick: () => onSelectChild(c), title: c.kind },
                    h('span', { class: 'rze-outline-child-name', text: c.name }),
                    h('span', { class: 'rze-outline-child-kind', text: c.kind }))))) : '';
        list.appendChild(h('li', { class: `rze-outline-item${r.from === activeFrom ? ' rze-active' : ''}`, 'data-from': r.from }, head, meta, note, children));
    }

    el.replaceChildren(
        h('div', { class: 'rze-panel-head' },
            h('strong', { text: `${t('outline')} (${rules.length})` }),
            totals.e || totals.w ? h('span', { class: 'rze-outline-totals' },
                totals.e ? h('span', { class: 'rze-sev-error', text: `${totals.e} ${t('errors')}` }) : '',
                totals.w ? h('span', { class: 'rze-sev-warning', text: `${totals.w} ${t('warnings')}` }) : '') : '',
            h('span', { class: 'rze-toolbar-fill' }),
            h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: onClose }, icon('close'))),
        rules.length > 3 ? input : '',
        rules.length ? list : h('div', { class: 'rze-empty', text: t('noRules') }),
    );
    if (hadFocus) {
        const again = el.querySelector('.rze-outline-filter');
        if (again) { again.focus(); again.setSelectionRange(caret, caret); }
    }
}
