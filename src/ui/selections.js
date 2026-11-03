/**
 * The "selections" section of the Fields panel, for formats whose detection is groups of
 * field / modifiers / values matched against an event, combined by a condition (Sigma). The
 * pack (pack.selections) reads and writes the rule; this file only draws the form.
 *
 * view.selections: { data: { logsource, searches, condition }, spec: pack.selections, fields: [names] }
 * callbacks: onLogsource(key, value), onSearch(index | null, search), onSearchRemove(index), onCondition(text), onCondOp(op)
 */
import { h, icon } from './dom.js';
import { conditionBlock } from './fields.js';

let lists = 0;          // unique datalist ids per render

const lines = (v) => String(v || '').split('\n').map(x => x.trim()).filter(Boolean);

export function selectionsSection(view, cb) {
    const { t } = cb;
    const { data, spec, fields } = view.selections;
    const locked = view.locked;
    const L = spec.labels || {};
    const id = `rze-sel-${++lists}`;
    const enter = (e) => { if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); e.target.blur(); } };

    // log source: category / product / service, each with its known values
    const logsource = h('div', { class: 'rze-sel-logsource' }, ...spec.logsourceKeys.map(({ key, help }) => h('label', { class: 'rze-sel-ls', title: help },
        h('span', { class: 'rze-muted', text: key }),
        h('input', { class: 'rze-field-input rze-mono', type: 'text', value: data.logsource[key] || '', list: `${id}-${key}`, disabled: locked,
            'data-focus-key': `ls:${key}`, onchange: e => cb.onLogsource(key, e.target.value), onkeydown: enter }),
        h('datalist', { id: `${id}-${key}` }, ...(spec.logsourceValues[key] || []).map(v => h('option', { value: v }))))));

    const fieldList = h('datalist', { id: `${id}-fields` }, ...fields.map(f => h('option', { value: f })));

    const searches = data.searches.map((s) => {
        const key = `sel:${s.index}`;
        const put = (patch) => cb.onSearch(s.index, { ...s, ...patch });
        const head = h('div', { class: 'rze-sel-head' },
            h('input', { class: 'rze-field-input rze-mono rze-sel-name', type: 'text', value: s.name, disabled: locked, 'data-focus-key': `${key}:name`,
                title: t('selRename'), onchange: e => put({ name: e.target.value.trim() }), onkeydown: enter }),
            h('span', { class: `rze-fields-badge rze-sel-kind${/^filter/i.test(s.name) ? ' rze-sel-filter' : ''}`, text: s.kind === 'keywords' ? t('selKeywords') : /^filter/i.test(s.name) ? t('selFilter') : t('selSelection') }),
            h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': t('selRemove'), title: t('selRemove'), disabled: locked,
                onclick: () => cb.onSearchRemove(s.index) }, icon('close')));
        if (s.kind === 'complex') {
            return h('div', { class: 'rze-sel' }, head,
                h('div', { class: 'rze-fields-note', text: t('selComplex') }),
                h('pre', { class: 'rze-sel-raw rze-mono', text: s.text }));
        }
        if (s.kind === 'keywords') {
            return h('div', { class: 'rze-sel' }, head,
                h('textarea', { class: 'rze-field-input rze-mono rze-sel-values', rows: Math.min(6, Math.max(2, s.keywords.length)), disabled: locked,
                    'data-focus-key': `${key}:kw`, placeholder: t('selOnePerLine'), onchange: e => put({ keywords: lines(e.target.value) }) }, s.keywords.join('\n')));
        }
        const rows = s.items.map((it, i) => {
            const putItem = (patch) => put({ items: s.items.map((x, j) => (j === i ? { ...x, ...patch } : x)) });
            const toggle = (m) => putItem({ modifiers: it.modifiers.includes(m) ? it.modifiers.filter(x => x !== m) : [...it.modifiers, m] });
            const extra = it.modifiers.filter(m => !spec.modifiers.includes(m));
            return h('div', { class: 'rze-sel-item' },
                h('div', { class: 'rze-sel-item-main' },
                    h('input', { class: 'rze-field-input rze-mono rze-sel-field', type: 'text', value: it.field, list: `${id}-fields`, disabled: locked,
                        placeholder: t('selField'), 'data-focus-key': `${key}:${i}:field`, onchange: e => putItem({ field: e.target.value.trim() }), onkeydown: enter }),
                    h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': t('selRemoveField'), title: t('selRemoveField'), disabled: locked,
                        onclick: () => put({ items: s.items.filter((_, j) => j !== i) }) }, icon('close'))),
                h('div', { class: 'rze-str-mods' },
                    ...spec.modifiers.map(m => h('span', { class: `rze-str-mod${it.modifiers.includes(m) ? ' rze-on' : ''}` },
                        h('button', { type: 'button', disabled: locked, title: spec.modifierHelp[m] || '', onclick: () => toggle(m) }, m))),
                    ...extra.map(m => h('span', { class: 'rze-str-mod rze-on' }, h('button', { type: 'button', disabled: locked, title: spec.modifierHelp[m] || '', onclick: () => toggle(m) }, m))),
                    h('select', { class: 'rze-field-input rze-sel-more', disabled: locked, 'aria-label': t('selMoreModifiers'),
                        onchange: e => { if (e.target.value) toggle(e.target.value); } },
                        h('option', { value: '', text: t('selMoreModifiers') }),
                        ...spec.allModifiers.filter(m => !spec.modifiers.includes(m) && !it.modifiers.includes(m)).map(m => h('option', { value: m, text: m, title: spec.modifierHelp[m] || '' })))),
                h('textarea', { class: 'rze-field-input rze-mono rze-sel-values', rows: Math.min(6, Math.max(1, it.values.length)), disabled: locked,
                    'data-focus-key': `${key}:${i}:values`, placeholder: t('selOnePerLine'), onchange: e => putItem({ values: lines(e.target.value) }) }, it.values.join('\n')),
                it.values.length > 1 ? h('div', { class: 'rze-muted rze-sel-hint', text: it.modifiers.includes('all') ? t('selAllOf') : t('selAnyOf') }) : '');
        });
        return h('div', { class: `rze-sel${/^filter/i.test(s.name) ? ' rze-sel-is-filter' : ''}` }, head, ...rows,
            s.items.length > 1 ? h('div', { class: 'rze-muted rze-sel-hint', text: t('selEveryField') }) : '',
            h('button', { type: 'button', class: 'rze-btn rze-sel-add-field', disabled: locked,
                onclick: () => put({ items: [...s.items, { field: '', modifiers: [], values: [] }] }) }, icon('plus'), t('selAddField')));
    });

    const add = (filter, keywords = false) => cb.onSearch(null, keywords
        ? { name: data.searches.some(s => s.name === 'keywords') ? spec.newName(data.searches) : 'keywords', kind: 'keywords', keywords: ['change me'] }
        : { name: spec.newName(data.searches, filter), kind: 'fields', items: [{ field: filter ? 'ParentImage' : (fields[0] || 'Image'), modifiers: ['endswith'], values: [filter ? '\\legit.exe' : '\\change_me.exe'] }] });

    const cond = conditionBlock(view, cb, {
        condition: data.condition, split: spec.splitCondition, join: spec.joinCondition,
        clauses: spec.clauses(data.searches), onCondition: cb.onCondition, empty: null,
    });

    return h('section', { class: 'rze-body rze-sel-section' },
        h('div', { class: 'rze-body-title' }, h('strong', { text: L.logsource || t('selLogsource') }), h('span', { class: 'rze-muted', text: L.hint || t('fBodyHint') })),
        logsource,
        h('div', { class: 'rze-field-label' }, h('span', { text: L.searches || t('selSearches') }), h('span', { class: 'rze-fields-badge', text: String(data.searches.length) })),
        fieldList,
        ...searches,
        h('div', { class: 'rze-sel-adds' },
            h('button', { type: 'button', class: 'rze-btn', disabled: locked, onclick: () => add(false) }, icon('plus'), t('selAddSelection')),
            h('button', { type: 'button', class: 'rze-btn', disabled: locked, onclick: () => add(true) }, icon('plus'), t('selAddFilter')),
            h('button', { type: 'button', class: 'rze-btn', disabled: locked, onclick: () => add(false, true) }, icon('plus'), t('selAddKeywords'))),
        ...cond);
}
