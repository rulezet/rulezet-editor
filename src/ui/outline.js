/** Rules panel: every rule of the document with its status, strings and actions.
 *
 *  compact: titles only (each rule's arrow still opens its details); flipped: the rules whose
 *  details are shown the other way round (opened in compact mode, closed otherwise); expanded:
 *  the rules whose long lists are shown in full. A rule with hundreds of strings, tags or notes
 *  only shows the first ones, with "Show all N" — so a huge rule never breaks the panel. */
import { h, icon } from './dom.js';

const LIMIT = { children: 12, tags: 8, notes: 4 };

export function renderOutline(el, rules, { t, filter, onFilter, onSelect, onSelectChild, onCopy, onToggleLock, onClose, activeFrom,
                                           compact = false, onCompact = null, flipped = new Set(), onFlip = null, expanded = new Set(), onExpand = null }) {
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
        const key = r.name || String(r.from);
        const open = compact !== flipped.has(key);
        const full = expanded.has(key);
        const cut = (list, n) => (full ? list : list.slice(0, n));
        const more = (list, n) => (list.length > n && onExpand ? h('button', { type: 'button', class: 'rze-outline-more', onclick: () => onExpand(key) },
            full ? t('showLess') : t('showAll', { n: list.length })) : '');
        const head = h('div', { class: 'rze-outline-head' },
            onFlip ? h('button', { type: 'button', class: 'rze-icon-btn rze-outline-chevron', 'aria-expanded': String(open),
                'aria-label': `${open ? t('collapse') : t('expand')} ${r.name}`, title: open ? t('collapse') : t('expand'),
                onclick: () => onFlip(key) }, icon(open ? 'collapse' : 'expand')) : '',
            icon(status, `rze-sev-${status}`),
            h('button', { type: 'button', class: 'rze-outline-name', title: `${r.kind} ${r.name}`, onclick: () => onSelect(r) }, r.name),
            r.errors || r.warnings ? h('span', { class: 'rze-outline-count', text: `${r.errors ? r.errors + 'E' : ''}${r.errors && r.warnings ? ' ' : ''}${r.warnings ? r.warnings + 'W' : ''}` }) : '',
            onToggleLock ? h('button', {
                type: 'button', class: `rze-icon-btn rze-outline-lock${r.locked ? ' rze-on' : ''}`,
                disabled: !!r.locked && !r.locked.canUnlock,
                title: r.locked ? (r.locked.canUnlock ? t('unlockRule') : t('lockedReadOnly')) : t('lockRuleHint'),
                'aria-label': `${r.locked ? t('unlock') : t('lockRule')} ${r.name}`,
                onclick: () => onToggleLock(r),
            }, icon(r.locked ? 'lock' : 'unlock')) : '',
            h('button', { type: 'button', class: 'rze-icon-btn', title: t('copy'), 'aria-label': `${t('copy')} ${r.name}`, onclick: () => onCopy(r) }, icon('copy')),
        );
        const a = r.annotation;
        if (!open) {                                     // titles only: the head, nothing else
            list.appendChild(h('li', { class: `rze-outline-item rze-outline-closed${r.from === activeFrom ? ' rze-active' : ''}`, 'data-from': r.from }, head));
            continue;
        }
        const notes = (a && a.notes) || [];
        const tags = r.tags || [];
        const kids = r.children || [];
        const note = a ? h('div', { class: `rze-outline-note rze-tone-${a.tone || 'info'}` },
            ...cut(notes, LIMIT.notes).map(n => h('div', { class: 'rze-outline-note-line', text: n })), more(notes, LIMIT.notes),
            ...(a.links || []).map(l => h('a', { href: l.url, target: '_blank', rel: 'noopener', text: l.label }))) : '';
        const meta = h('div', { class: 'rze-outline-meta' },
            r.locked ? h('span', { class: 'rze-chip rze-chip-lock', title: r.locked.label, text: '🔒 ' + (r.locked.label || 'locked') }) : '',
            a && a.badge ? h('span', { class: `rze-chip rze-badge rze-tone-${a.tone || 'info'}`, text: a.badge }) : '',
            r.kind !== 'rule' ? h('span', { class: 'rze-chip', text: r.kind }) : '',
            ...cut(tags, LIMIT.tags).map(tag => h('span', { class: 'rze-chip rze-chip-tag', text: tag })),
            !full && tags.length > LIMIT.tags ? h('span', { class: 'rze-chip', text: `+${tags.length - LIMIT.tags}` }) : '',
            r.detail ? h('div', { class: 'rze-outline-detail', text: r.detail }) : '',
        );
        const children = kids.length ? h('ul', { class: 'rze-outline-children' },
            ...cut(kids, LIMIT.children).map(c => h('li', {},
                h('button', { type: 'button', class: 'rze-outline-child', onclick: () => onSelectChild(c), title: c.kind },
                    h('span', { class: 'rze-outline-child-name', text: c.name }),
                    h('span', { class: 'rze-outline-child-kind', text: c.kind })))),
            kids.length > LIMIT.children ? h('li', {}, more(kids, LIMIT.children)) : '') : '';
        list.appendChild(h('li', { class: `rze-outline-item${r.from === activeFrom ? ' rze-active' : ''}`, 'data-from': r.from }, head, meta, note, children));
    }

    el.replaceChildren(
        h('div', { class: 'rze-panel-head' },
            h('strong', { text: `${t('outline')} (${rules.length})` }),
            totals.e || totals.w ? h('span', { class: 'rze-outline-totals' },
                totals.e ? h('span', { class: 'rze-sev-error', text: `${totals.e} ${t('errors')}` }) : '',
                totals.w ? h('span', { class: 'rze-sev-warning', text: `${totals.w} ${t('warnings')}` }) : '') : '',
            h('span', { class: 'rze-toolbar-fill' }),
            onCompact && rules.length ? h('button', { type: 'button', class: `rze-btn rze-outline-compact${compact ? ' rze-on' : ''}`,
                'aria-pressed': String(compact), title: compact ? t('outlineDetails') : t('outlineTitles'), onclick: onCompact },
                icon(compact ? 'expand' : 'collapse'), compact ? t('outlineDetails') : t('outlineTitles')) : '',
            h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: onClose }, icon('close'))),
        rules.length > 3 ? input : '',
        rules.length ? list : h('div', { class: 'rze-empty', text: t('noRules') }),
    );
    if (hadFocus) {
        const again = el.querySelector('.rze-outline-filter');
        if (again) { again.focus(); again.setSelectionRange(caret, caret); }
    }
}
