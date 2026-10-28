/**
 * "New rule from template" gallery: the language pack's templates (pack.templates) grouped by
 * category, a filter, the selected template's description and its full text as a preview;
 * "Insert" puts it at the end of the document (its imports at the top), placeholders ready to fill
 * with Tab. Plain DOM overlay inside the editor; Esc closes it.
 *
 *   new TemplateGallery(root, t, viewer).open(templates, (template) => insert(template))
 *
 * viewer(parent, text) -> view with destroy(): shows the preview highlighted (the editor gives a
 * read-only CodeMirror view in the pack's language); without it, a plain <pre>.
 */
import { h, icon } from './dom.js';

export class TemplateGallery {
    constructor(root, t, viewer = null) {
        this.root = root;
        this.t = t;
        this.viewer = viewer;
        this.previewView = null;
        this.onKey = (e) => {
            if (!this.el) return;
            if (e.key === 'Escape') { e.preventDefault(); this.close(); }
            if (e.key === 'Enter' && this.selected && document.activeElement !== this.insertBtn) { e.preventDefault(); this.pick(); }
        };
    }

    open(templates, onPick) {
        this.close();
        this.templates = templates;
        this.onPick = onPick;
        this.query = '';
        this.selected = templates[0] || null;
        this.el = h('div', { class: 'rze-gallery', role: 'dialog', 'aria-modal': 'true', 'aria-label': this.t('tplTitle'),
                             onmousedown: e => { if (e.target === this.el) this.close(); } });
        this.root.appendChild(this.el);
        document.addEventListener('keydown', this.onKey, true);
        this.render();
        const input = this.el.querySelector('.rze-gallery-search input');
        if (input) input.focus();
    }

    close() {
        if (!this.el) return;
        this._dropPreview();
        this.el.remove();
        this.el = null;
        document.removeEventListener('keydown', this.onKey, true);
    }

    pick() {
        const tpl = this.selected;
        this.close();
        if (tpl && this.onPick) this.onPick(tpl);
    }

    _dropPreview() {
        if (this.previewView) { this.previewView.destroy(); this.previewView = null; }
    }

    _preview(text) {
        this._dropPreview();
        if (!this.viewer) return h('pre', { class: 'rze-gallery-preview rze-mono', text });
        const box = h('div', { class: 'rze-gallery-preview rze-gallery-code' });
        this.previewView = this.viewer(box, text);
        return box;
    }

    render() {
        const t = this.t;
        const q = this.query.trim().toLowerCase();
        const shown = this.templates.filter(x => !q || [x.label, x.category, x.description, x.id].some(v => String(v || '').toLowerCase().includes(q)));
        if (this.selected && !shown.includes(this.selected)) this.selected = shown[0] || null;
        const groups = [];
        for (const tpl of shown) {
            let g = groups.find(x => x.category === tpl.category);
            if (!g) groups.push(g = { category: tpl.category, items: [] });
            g.items.push(tpl);
        }
        const list = h('div', { class: 'rze-gallery-list', role: 'listbox' },
            ...groups.map(g => h('div', { class: 'rze-gallery-group' },
                h('div', { class: 'rze-gallery-cat', text: g.category }),
                ...g.items.map(tpl => h('button', {
                    type: 'button', role: 'option', class: `rze-gallery-item${tpl === this.selected ? ' rze-on' : ''}`,
                    onclick: () => { this.selected = tpl; this.render(); }, ondblclick: () => { this.selected = tpl; this.pick(); },
                }, h('span', { class: 'rze-gallery-label', text: tpl.label }),
                   tpl.imports && tpl.imports.length ? h('small', { class: 'rze-gallery-imports', text: tpl.imports.map(m => `import ${m}`).join(' · ') }) : '')))),
            shown.length ? '' : h('div', { class: 'rze-muted rze-gallery-empty', text: t('fNoMatch') }));

        const tpl = this.selected;
        this.insertBtn = h('button', { type: 'button', class: 'rze-btn rze-btn-primary', disabled: !tpl, onclick: () => this.pick() },
            icon('plus'), h('span', { text: t('tplInsert') }));
        const detail = h('div', { class: 'rze-gallery-detail' },
            tpl ? h('div', { class: 'rze-gallery-detail-head' }, h('strong', { text: tpl.label }), h('span', { class: 'rze-tests-kind', text: tpl.category })) : '',
            tpl ? h('p', { class: 'rze-gallery-desc', text: tpl.description }) : '',
            tpl ? this._preview(preview(tpl.snippet)) : '',
            h('div', { class: 'rze-gallery-foot' },
                h('span', { class: 'rze-gallery-hint', text: t('tplHint') }),
                h('span', { class: 'rze-toolbar-fill' }),
                h('button', { type: 'button', class: 'rze-btn', onclick: () => this.close() }, t('cancel')),
                this.insertBtn));

        const search = h('label', { class: 'rze-gallery-search' }, icon('search'),
            h('input', { type: 'search', value: this.query, placeholder: t('tplFilter'),
                oninput: e => { this.query = e.target.value; const pos = e.target.selectionStart; this.render();
                    const inp = this.el.querySelector('.rze-gallery-search input'); inp.focus(); inp.setSelectionRange(pos, pos); } }));
        this.el.replaceChildren(h('div', { class: 'rze-gallery-box' },
            h('div', { class: 'rze-gallery-head' }, h('strong', {}, icon('plus'), ' ', t('tplTitle')),
                h('span', { class: 'rze-gallery-sub', text: t('tplSub') }), h('span', { class: 'rze-toolbar-fill' }),
                h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': 'Close', onclick: () => this.close() }, icon('close'))),
            search,
            h('div', { class: 'rze-gallery-main' }, list, detail)));
    }
}

/**
 * Give every ${placeholder} of a template its own explicit tab stop, in reading order:
 * ${70} -> ${1:70}. CodeMirror reads a bare number as a tab-stop index with no text, so
 * `score = ${70}` used to be inserted as `score = ` (same for ${2}, ${5}…); and two fields
 * with the same text would be edited together. Text with ':' or '}' escaped stays as is.
 */
export function numberSnippetFields(snippet) {
    let n = 0;
    return snippet.replace(/\$\{((?:\\[{}]|[^{}])*)\}/g, (_, text) => `\${${++n}:${text}}`);
}

/** The snippet as it will read once inserted: placeholders show their default text. */
export function preview(snippet) {
    return snippet.replace(/\$\{([^}]*)\}/g, '$1').replace(/\{\{uuid\}\}/g, '<uuid>').replace(/\{\{date\}\}/g, '<today>');
}
