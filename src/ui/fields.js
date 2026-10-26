/**
 * Fields panel: the host's fields (title, description, CVE, tags...) for one rule of the document,
 * each one optionally written into the rule (YARA `meta:`), with the differences between the two
 * shown and resolved explicitly. Plain DOM; the logic is in core/fields.js.
 *
 * view: { defs, rules: [names], rule, state, statusOf(def), ruleValueOf(def), suggest, ui, loading, error }
 * ui:   { formats: field id, select: field id, selectQuery, browse: { field, path, labels, page, data, loading, error } }
 */
import { h, icon } from './dom.js';
import { chipColor, isMinVersion, stepVersion, textOn, toMetaValue, validItem } from '../core/fields.js';

const STATUS = {
    synced:   { tone: 'ok',      key: 'fSynced' },
    same:     { tone: 'muted',   key: 'fSame' },
    kept:     { tone: 'info',    key: 'fKept' },
    conflict: { tone: 'warning', key: 'fConflict' },
    host:     { tone: 'muted',   key: 'fHostOnly' },
    rule:     { tone: 'info',    key: 'fFromRule' },
    empty:    { tone: 'muted',   key: '' },
};

export function renderFields(el, view, cb) {
    const { t } = cb;
    // keep focus / caret / scroll across re-renders (every keystroke in the editor re-renders)
    const active = document.activeElement;
    const focusKey = active && el.contains(active) ? active.dataset.focusKey : null;
    const caret = focusKey && 'selectionStart' in active ? [active.selectionStart, active.selectionEnd] : null;
    const prevBody = el.querySelector('.rze-fields-body');
    const scrollTop = prevBody ? prevBody.scrollTop : 0;
    const inner = {};
    el.querySelectorAll('[data-scroll-key]').forEach(n => { inner[n.dataset.scrollKey] = n.scrollTop; });

    const head = h('div', { class: 'rze-panel-head' },
        h('strong', { text: t('fields') }),
        h('span', { class: 'rze-toolbar-fill' }),
        h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: cb.onClose }, icon('close')));

    const body = h('div', { class: 'rze-fields-body' });
    if (view.loading) body.appendChild(h('div', { class: 'rze-empty', text: t('fLoading') }));
    else if (view.error) body.appendChild(h('div', { class: 'rze-empty rze-sev-error', text: view.error }));
    else {
        if (view.rules.length) body.appendChild(h('label', { class: 'rze-fields-rule' },
            h('span', { text: t('rule') }),
            h('select', { 'data-focus-key': '__rule', onchange: e => cb.onPickRule(e.target.value) },
                h('option', { value: '', text: t('fUnderCursor'), selected: !view.picked }),
                ...view.rules.map(n => h('option', { value: n, text: n, selected: view.picked === n })))));
        if (!view.rule) body.appendChild(h('div', { class: 'rze-empty', text: t('noRuleHere') }));
        else {
            const conflicts = view.defs.filter(d => view.statusOf(d) === 'conflict').length;
            body.appendChild(view.draft
                ? h('div', { class: 'rze-fields-note rze-fields-draft' }, icon('plus'), h('span', { text: t('fDraft') }))
                : h('div', { class: 'rze-fields-intro' },
                    h('b', { class: 'rze-mono', text: view.rule }),
                    conflicts ? h('span', { class: 'rze-fields-badge rze-tone-warning', text: t('fConflicts', { n: conflicts }) }) : ''));
            if (view.locked) body.appendChild(h('div', { class: 'rze-fields-note', text: t('fLocked') }));
            for (const def of view.defs) body.appendChild(fieldRow(def, view, cb));
            if (view.body) body.appendChild(bodySection(view, cb));
        }
    }

    el.replaceChildren(head, body);
    body.scrollTop = scrollTop;
    el.querySelectorAll('[data-scroll-key]').forEach(n => { if (inner[n.dataset.scrollKey]) n.scrollTop = inner[n.dataset.scrollKey]; });
    if (focusKey) {
        const again = el.querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`);
        if (again) {
            again.focus();
            if (caret && 'setSelectionRange' in again) { try { again.setSelectionRange(caret[0], caret[1]); } catch { /* not a text input */ } }
        }
    }
}

function fieldRow(def, view, cb) {
    const { t } = cb;
    const state = view.state;
    const status = view.statusOf(def);
    const st = STATUS[status];
    const ruleValue = view.ruleValueOf(def);
    const key = def.meta && def.meta.key;
    const id = def.id;            // not the rule's name: the title field renames the rule while typing

    const label = h('div', { class: 'rze-field-label' },
        h('span', { text: def.label + (def.required ? ' *' : '') }),
        def.help ? h('span', { class: 'rze-field-help', title: def.help, text: '?' }) : '',
        st && st.key ? h('span', { class: `rze-fields-badge rze-tone-${st.tone}`, text: t(st.key) }) : '');

    const input = editorFor(def, state.values[def.id], view, cb, id);

    const report = key ? h('label', { class: `rze-field-report${view.locked ? ' rze-disabled' : ''}`, title: t('fReportHint', { key }) },
        h('input', { type: 'checkbox', checked: !!state.report[def.id], disabled: view.locked, 'data-focus-key': `${id}\u0000report`,
            onchange: e => cb.onReport(def, e.target.checked) }),
        h('span', {}, t('fReport'), ' ', h('code', { text: `${key} = …` }))) : h('div', { class: 'rze-field-report rze-muted', text: t('fHostField') });

    const parts = [label, input, report];
    if (status === 'conflict') {
        parts.push(h('div', { class: 'rze-field-conflict' },
            h('div', {}, t('fRuleSays'), ' ', h('code', { text: toMetaValue(def, ruleValue) })),
            h('div', { class: 'rze-field-actions' },
                h('button', { type: 'button', class: 'rze-btn', onclick: () => cb.onResolve(def, 'rule') }, t('fUseRule')),
                h('button', { type: 'button', class: 'rze-btn', disabled: view.locked, onclick: () => cb.onResolve(def, 'mine') }, t('fWriteMine')),
                h('button', { type: 'button', class: 'rze-btn', onclick: () => cb.onResolve(def, 'keep') }, t('fKeepDifferent'))),
            h('div', { class: 'rze-field-hint', text: t('fKeepHint') })));
    } else if (status === 'kept') {
        parts.push(h('div', { class: 'rze-field-kept' },
            h('span', {}, t('fRuleSays'), ' ', h('code', { text: toMetaValue(def, ruleValue) })),
            h('button', { type: 'button', class: 'rze-link-btn', onclick: () => cb.onResolve(def, 'undo') }, t('fReconsider'))));
    }
    return h('div', { class: `rze-field rze-field-${status}` }, ...parts);
}

function editorFor(def, value, view, cb, id) {
    const { t } = cb;
    if (def.type === 'version') return versionEditor(def, value, view, cb, id);
    if (def.type === 'select') return def.searchable ? searchableSelect(def, value, view, cb, id) : plainSelect(def, value, cb, id);
    if (def.type === 'textarea') {
        return h('textarea', { class: 'rze-field-input', rows: '3', 'data-focus-key': id, placeholder: def.placeholder || '',
            onchange: e => cb.onValue(def, e.target.value) }, value || '');
    }
    if (def.type === 'list') return listEditor(def, value || [], view, cb, id);
    const input = h('input', { class: 'rze-field-input', type: 'text', value: value || '', 'data-focus-key': id, placeholder: def.placeholder || '',
        onchange: e => cb.onValue(def, e.target.value),
        onkeydown: e => { if (e.key === 'Enter') { e.preventDefault(); e.target.blur(); } } });
    if (!def.me || !view.me) return input;
    return h('div', { class: 'rze-field-row' }, input,
        h('button', { type: 'button', class: 'rze-field-me', title: t('fMeHint', { name: view.me }), onclick: () => cb.onValue(def, view.me) }, t('fMe')));
}

function plainSelect(def, value, cb, id) {
    return h('select', { class: 'rze-field-input', 'data-focus-key': id, onchange: e => cb.onValue(def, e.target.value) },
        h('option', { value: '', text: '—' }),
        ...(def.options || []).map(o => h('option', { value: o.value, text: o.label ?? o.value, selected: String(o.value) === String(value) })));
}

/** Rulezet's VersionPicker: −/+ only, major.minor, never below the minimum. */
function versionEditor(def, value, view, cb, id) {
    const opts = def.version || {};
    const current = value || opts.min || '1.0';
    return h('div', { class: 'rze-field-version' },
        h('button', { type: 'button', class: 'rze-field-step', 'aria-label': 'Previous version', 'data-focus-key': `${id}\u0000minus`,
            disabled: isMinVersion(current, opts), onclick: () => cb.onValue(def, stepVersion(current, -1, opts)) }, '−'),
        h('span', { class: 'rze-field-version-value rze-mono', text: value ? value : `${current}` }),
        h('button', { type: 'button', class: 'rze-field-step rze-field-step-plus', 'aria-label': 'Next version', 'data-focus-key': `${id}\u0000plus`,
            onclick: () => cb.onValue(def, stepVersion(current, 1, opts)) }, '+'));
}

/** Rulezet's LicenseInput: type to filter, one choice, clearable. */
function searchableSelect(def, value, view, cb, id) {
    const { t } = cb;
    const ui = view.ui || {};
    const open = ui.select === def.id;
    const q = open ? (ui.selectQuery || '') : '';
    const options = (def.options || []).filter(o => !q || String(o.label ?? o.value).toLowerCase().includes(q.toLowerCase()));
    const current = (def.options || []).find(o => String(o.value) === String(value));
    return h('div', { class: 'rze-field-combo' },
        h('div', { class: 'rze-field-combo-box' },
            h('input', { class: 'rze-field-input', type: 'text', 'data-focus-key': id,
                value: open ? q : (current ? (current.label ?? current.value) : (value || '')),
                placeholder: def.placeholder || t('fSearchOption'),
                onfocus: () => { if (!open) cb.onSelect(def, ''); },
                oninput: e => cb.onSelect(def, e.target.value),
                onkeydown: e => {
                    if (e.key === 'Enter') { e.preventDefault(); if (options[0]) { cb.onValue(def, options[0].value); cb.onSelect(null); } }
                    if (e.key === 'Escape') cb.onSelect(null);
                },
                onblur: () => setTimeout(() => cb.onSelect(null, null, def.id), 150) }),
            value ? h('button', { type: 'button', class: 'rze-field-clear', 'aria-label': 'Clear', onclick: () => cb.onValue(def, '') }, '×') : ''),
        open ? h('ul', { class: 'rze-field-suggest', role: 'listbox' },
            ...(options.length ? options.slice(0, 200).map(o => h('li', {
                role: 'option', class: String(o.value) === String(value) ? 'rze-on' : '',
                onmousedown: e => { e.preventDefault(); cb.onValue(def, o.value); cb.onSelect(null); },
            }, h('span', { text: o.label ?? o.value }))) : [h('li', { class: 'rze-muted', text: t('fNoMatch') })])) : '');
}

/** Lists: Rulezet's VulnerabilityInput / AttackInput / TagInput, one shared look. */
function listEditor(def, items, view, cb, id) {
    const { t } = cb;
    const ui = view.ui || {};
    const sug = view.suggest && view.suggest.field === def.id ? view.suggest : null;
    const query = sug ? sug.query : '';
    const full = def.max && items.length >= def.max;
    const has = (item) => items.some(i => String(i.value).toLowerCase() === String(item.value).toLowerCase());
    const add = (raw) => {
        const item = def.kinds && !raw.kind ? { ...raw, kind: def.kinds[0].value } : raw;
        if (has(item)) return;
        cb.onValue(def, def.max === 1 ? [item] : (full ? items : [...items, item]));
    };
    const typed = query.trim();
    const typedValid = def.free !== false && typed && validItem(def, typed);
    const addTyped = () => {
        if (!typedValid) return false;
        const v = def.upper ? typed.toUpperCase() : typed;
        add({ value: v, label: v });
        cb.onSuggest(def, '');
        return true;
    };

    const chips = items.map((item, i) => {
        const bg = chipColor(def, item);
        return h('span', { class: `rze-field-chip${bg ? ' rze-colored' : ''}`, title: item.detail || item.label || '',
            style: bg ? { background: bg, color: textOn(bg) || '#fff', borderColor: bg } : null },
            h('span', { class: 'rze-field-chip-label', text: item.label ?? item.value }),
            item.detail && def.chipDetail ? h('small', { text: item.detail }) : '',
            def.kinds ? h('select', { class: 'rze-field-chip-kind', title: t('fKind'),
                onchange: e => cb.onValue(def, items.map((x, j) => (j === i ? { ...x, kind: e.target.value } : x))) },
                ...def.kinds.map(k => h('option', { value: k.value, text: k.label, selected: (item.kind || def.kinds[0].value) === k.value }))) : '',
            h('button', { type: 'button', 'aria-label': `Remove ${item.label ?? item.value}`,
                onclick: () => cb.onValue(def, items.filter((_, j) => j !== i)) }, '×'));
    });

    const formatMenu = def.formats && def.formats.length ? h('div', { class: 'rze-field-formats' },
        h('button', { type: 'button', class: 'rze-field-format-btn', 'aria-expanded': String(ui.formats === def.id),
            onclick: () => cb.onFormats(ui.formats === def.id ? null : def) }, t('fFormat'), ' ▾'),
        ui.formats === def.id ? h('ul', { class: 'rze-field-suggest rze-field-format-menu' },
            ...def.formats.map(f => h('li', { onmousedown: e => { e.preventDefault(); cb.onFormats(null); cb.onSuggest(def, f.prefix, { focus: id }); } },
                h('span', { text: f.label }), h('small', { class: 'rze-mono', text: f.prefix })))) : '') : '';

    const input = h('input', {
        class: 'rze-field-chip-input', type: 'text', 'data-focus-key': id, value: query, disabled: !!full && def.max !== 1,
        placeholder: full && def.max !== 1 ? t('fMaxReached', { n: def.max }) : (def.placeholder || t('fAdd')),
        oninput: e => cb.onSuggest(def, e.target.value),
        onkeydown: e => {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (addTyped()) return;
                if (sug && sug.items[0]) { add(sug.items[0]); cb.onSuggest(def, ''); }
            } else if (e.key === 'Backspace' && !e.target.value && items.length) {
                cb.onValue(def, items.slice(0, -1));
            } else if (e.key === 'Escape') {
                cb.onSuggest(def, '');
            }
        },
    });

    const parts = [h('div', { class: 'rze-field-list-box' },
        formatMenu,
        h('div', { class: 'rze-field-chips' }, ...chips, input),
        def.free !== false && def.pattern ? h('button', { type: 'button', class: `rze-field-add${typedValid ? ' rze-on' : ''}`,
            disabled: !typedValid, 'aria-label': t('fAdd'), onclick: addTyped }, '+') : '',
        def.browse ? h('button', { type: 'button', class: `rze-field-browse-btn${ui.browse && ui.browse.field === def.id ? ' rze-on' : ''}`,
            title: t('fBrowse'), onclick: () => (ui.browse && ui.browse.field === def.id) ? cb.onBrowseClose() : cb.onBrowse(def, []) }, '☰') : '')];

    // live feedback, as the vulnerability picker does
    if (def.pattern && def.free !== false && typed.length > 2) {
        parts.push(h('div', { class: `rze-field-hint ${typedValid ? 'rze-sev-ok' : 'rze-sev-error'}` },
            typedValid ? t('fValid') : t('fInvalidFor', { what: (typed.split(/[-_:]/)[0] || typed).toUpperCase() })));
    }
    if (sug && sug.items.length) {
        parts.push(h('ul', { class: 'rze-field-suggest', role: 'listbox' },
            ...sug.items.map(s => h('li', {
                role: 'option', class: has(s) ? 'rze-on' : '',
                onmousedown: e => { e.preventDefault(); add(s); cb.onSuggest(def, ''); },
            }, h('span', { class: 'rze-field-opt-label' }, s.color ? h('i', { class: 'rze-dot', style: { background: s.color } }) : '', s.label ?? s.value),
               s.detail ? h('small', { text: s.detail }) : ''))));
    }
    if (ui.browse && ui.browse.field === def.id) parts.push(browsePane(def, ui.browse, items, add, view, cb));
    return h('div', { class: 'rze-field-list' }, ...parts);
}

/** Folder drill-down (tag namespaces, ATT&CK tactics), loaded a level at a time from the host. */
function browsePane(def, b, items, add, view, cb) {
    const { t } = cb;
    const selected = (it) => items.some(i => String(i.value) === String(it.value));
    const crumbs = [h('button', { type: 'button', class: 'rze-link-btn', onclick: () => cb.onBrowse(def, []) }, def.label)];
    b.path.forEach((p, i) => crumbs.push(h('span', { class: 'rze-muted', text: ' › ' }),
        h('button', { type: 'button', class: 'rze-link-btn', onclick: () => cb.onBrowse(def, b.path.slice(0, i + 1)) }, b.labels[i] || p)));
    const data = b.data || {};
    let lastGroup = null;
    const folders = [];
    for (const f of data.folders || []) {
        if (f.group && f.group !== lastGroup) { lastGroup = f.group; folders.push(h('li', { class: 'rze-field-browse-group', text: f.group })); }
        folders.push(h('li', { class: 'rze-field-browse-folder', onclick: () => cb.onBrowse(def, [...b.path, f.id], 1, f.label) },
            f.color ? h('i', { class: 'rze-dot', style: { background: f.color } }) : '',
            h('span', { text: f.label || '—' }), f.count != null ? h('small', { text: String(f.count) }) : '', h('span', { class: 'rze-muted', text: '›' })));
    }
    const rows = (data.items || []).map(it => h('li', {
        class: `rze-field-browse-item${selected(it) ? ' rze-on' : ''}`,
        onclick: () => selected(it) ? cb.onValue(def, items.filter(i => String(i.value) !== String(it.value))) : add(it),
    },
        h('span', { class: 'rze-field-check', text: selected(it) ? '✓' : '' }),
        it.color ? h('i', { class: 'rze-dot', style: { background: it.color } }) : '',
        h('span', { class: 'rze-field-opt-label', text: it.label ?? it.value }),
        it.detail ? h('small', { text: it.detail }) : ''));
    return h('div', { class: 'rze-field-browse' },
        h('div', { class: 'rze-field-browse-head' }, ...crumbs, h('span', { class: 'rze-toolbar-fill' }),
            h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: cb.onBrowseClose }, icon('close'))),
        b.loading ? h('div', { class: 'rze-empty', text: t('fLoading') }) : '',
        b.error ? h('div', { class: 'rze-empty rze-sev-error', text: b.error }) : '',
        h('ul', { class: 'rze-field-browse-list', 'data-scroll-key': `browse:${def.id}` }, ...folders, ...rows,
            !b.loading && !folders.length && !rows.length ? h('li', { class: 'rze-muted rze-field-browse-empty', text: t('fNoMatch') }) : ''),
        data.has_more ? h('button', { type: 'button', class: 'rze-tests-more-btn', onclick: () => cb.onBrowse(def, b.path, (b.page || 1) + 1, null, true) }, t('fMore')) : '');
}

/** Strings & condition of the rule as a form, written into the rule as they change. */
function bodySection(view, cb) {
    const { t } = cb;
    const b = view.body;
    const locked = view.locked;
    const allowed = view.bodyModifiers || {};
    const rows = b.strings.map((s) => {
        const key = `str:${s.index}`;
        const put = (patch) => cb.onString(s.index, { ...s, ...patch });
        const has = (name) => s.modifiers.some(m => m.name === name);
        const mods = (allowed[s.kind] || []).map(name => {
            const on = has(name);
            const mod = s.modifiers.find(m => m.name === name);
            return h('span', { class: `rze-str-mod${on ? ' rze-on' : ''}` },
                h('button', { type: 'button', disabled: locked,
                    onclick: () => put({ modifiers: on ? s.modifiers.filter(m => m.name !== name) : [...s.modifiers, { name, args: null }] }) }, name),
                on && (name === 'xor' || name.startsWith('base64'))
                    ? h('input', { class: 'rze-str-mod-args', type: 'text', value: mod.args || '', placeholder: name === 'xor' ? '0x01-0xff' : 'alphabet',
                        'data-focus-key': `${key}:${name}`, disabled: locked,
                        onchange: e => put({ modifiers: s.modifiers.map(m => (m.name === name ? { name, args: e.target.value.trim() || null } : m)) }) }) : '');
        });
        return h('div', { class: 'rze-str' },
            h('div', { class: 'rze-str-main' },
                h('input', { class: 'rze-field-input rze-str-id rze-mono', type: 'text', value: s.id, 'data-focus-key': `${key}:id`, disabled: locked,
                    onchange: e => put({ id: e.target.value }) }),
                h('select', { class: 'rze-field-input rze-str-kind', 'data-focus-key': `${key}:kind`, disabled: locked,
                    onchange: e => put({ kind: e.target.value, modifiers: s.modifiers.filter(m => (allowed[e.target.value] || []).includes(m.name)) }) },
                    ...['text', 'hex', 'regex'].map(k => h('option', { value: k, text: t(`fKind_${k}`), selected: k === s.kind }))),
                h('button', { type: 'button', class: 'rze-icon-btn rze-str-del', 'aria-label': t('fRemoveString'), disabled: locked,
                    onclick: () => cb.onStringRemove(s.index) }, icon('close'))),
            h('input', { class: 'rze-field-input rze-mono rze-str-value', type: 'text', value: s.value, 'data-focus-key': `${key}:value`, disabled: locked,
                placeholder: s.kind === 'hex' ? '4D 5A ?? [2-4] 00' : s.kind === 'regex' ? '/https?:\\/\\/[a-z]+/' : 'text to find',
                onchange: e => put({ value: e.target.value }), onkeydown: e => { if (e.key === 'Enter') { e.preventDefault(); e.target.blur(); } } }),
            mods.length ? h('div', { class: 'rze-str-mods' }, ...mods) : '');
    });
    const ids = b.strings.map(s => s.id).filter(Boolean);
    const insert = (snippet) => cb.onCondition(b.condition && b.condition !== 'true' ? `${b.condition} and ${snippet}` : snippet);
    return h('section', { class: 'rze-body' },
        h('div', { class: 'rze-body-title' }, h('strong', { text: t('fBody') }), h('span', { class: 'rze-muted', text: t('fBodyHint') })),
        h('div', { class: 'rze-field-label' }, h('span', { text: t('fStrings') }), h('span', { class: 'rze-fields-badge', text: String(b.strings.length) })),
        ...rows,
        h('button', { type: 'button', class: 'rze-btn rze-str-add', disabled: locked,
            onclick: () => cb.onString(null, { id: nextId(ids), kind: 'text', value: 'change me', modifiers: [] }) }, icon('plus'), t('fAddString')),
        h('div', { class: 'rze-field-label' }, h('span', { text: t('fCondition') })),
        h('textarea', { class: 'rze-field-input rze-mono rze-cond', rows: '3', 'data-focus-key': 'condition', disabled: locked,
            onchange: e => cb.onCondition(e.target.value) }, b.condition || ''),
        h('div', { class: 'rze-cond-quick' },
            ...['any of them', 'all of them'].map(q => h('button', { type: 'button', class: 'rze-field-chip rze-cond-chip', disabled: locked, onclick: () => cb.onCondition(q) }, q)),
            ...ids.map(id => h('button', { type: 'button', class: 'rze-field-chip rze-cond-chip rze-mono', disabled: locked, title: t('fAndString', { id }), onclick: () => insert(id) }, `+ ${id}`))));
}

function nextId(ids) {
    let n = ids.length + 1;
    while (ids.includes(`$s${n}`)) n++;
    return `$s${n}`;
}
