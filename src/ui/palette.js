/** Command palette (Ctrl+Shift+P / F1): fuzzy filter, arrows, Enter. */
import { h, icon } from './dom.js';

export class CommandPalette {
    constructor(root, t) {
        this.root = root;
        this.t = t;
        this.el = h('div', { class: 'rze-palette', hidden: true, role: 'dialog', 'aria-label': t('palette') });
        this.el.addEventListener('mousedown', e => { if (e.target === this.el) this.close(); });
        root.appendChild(this.el);
    }

    open(commands) {
        this.commands = commands;
        this.index = 0;
        this.previousFocus = document.activeElement;
        this.input = h('input', {
            class: 'rze-palette-input', type: 'text', placeholder: this.t('filterCommands'), 'aria-label': this.t('filterCommands'),
            oninput: () => { this.index = 0; this.renderList(); },
            onkeydown: e => this.onKey(e),
        });
        this.list = h('ul', { class: 'rze-palette-list', role: 'listbox' });
        this.el.replaceChildren(h('div', { class: 'rze-palette-box' }, h('div', { class: 'rze-palette-search' }, icon('search'), this.input), this.list));
        this.el.hidden = false;
        this.renderList();
        this.input.focus();
    }

    /** One-line input in the palette box. Resolves to the text, or null when cancelled. */
    prompt({ label, placeholder = '', value = '' }) {
        if (this._resolve) this._resolve(null);
        this.previousFocus = document.activeElement;
        return new Promise(resolve => {
            this._resolve = resolve;
            const done = (v) => { const r = this._resolve; this._resolve = null; this.close(); if (r) r(v); };
            const input = h('input', {
                class: 'rze-palette-input', type: 'text', placeholder, value, 'aria-label': label,
                onkeydown: e => {
                    if (e.key === 'Enter') { e.preventDefault(); done(input.value); }
                    if (e.key === 'Escape') { e.preventDefault(); done(null); }
                },
            });
            this.el.replaceChildren(h('div', { class: 'rze-palette-box' },
                h('div', { class: 'rze-palette-prompt', text: label }),
                h('div', { class: 'rze-palette-search' }, icon('edit'), input)));
            this.el.hidden = false;
            input.focus();
            input.select();
        });
    }

    close() {
        if (this._resolve) { const r = this._resolve; this._resolve = null; r(null); }
        this.el.hidden = true;
        if (this.previousFocus && this.previousFocus.focus) this.previousFocus.focus();
    }

    filtered() {
        const q = this.input.value.trim().toLowerCase();
        if (!q) return this.commands;
        return this.commands
            .map(c => ({ c, score: fuzzy(q, c.label.toLowerCase()) }))
            .filter(x => x.score > 0)
            .sort((a, b) => b.score - a.score)
            .map(x => x.c);
    }

    renderList() {
        const items = this.filtered();
        this.items = items;
        this.list.replaceChildren(...items.slice(0, 60).map((c, i) => h('li', {
            role: 'option', 'aria-selected': i === this.index ? 'true' : 'false',
            class: `rze-palette-item${i === this.index ? ' rze-active' : ''}`,
            onmousedown: e => { e.preventDefault(); this.run(c); },
        }, h('span', { text: c.label }), c.key ? h('kbd', { text: c.key }) : '')));
        const active = this.list.children[this.index];
        if (active) active.scrollIntoView({ block: 'nearest' });
    }

    onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); this.close(); return; }
        if (e.key === 'ArrowDown') { e.preventDefault(); this.index = Math.min(this.index + 1, this.items.length - 1); this.renderList(); return; }
        if (e.key === 'ArrowUp') { e.preventDefault(); this.index = Math.max(this.index - 1, 0); this.renderList(); return; }
        if (e.key === 'Enter') { e.preventDefault(); const c = this.items[this.index]; if (c) this.run(c); }
    }

    run(c) {
        this.close();
        setTimeout(() => c.run(), 0);
    }
}

/** Subsequence match; consecutive and word-start hits score higher. */
function fuzzy(q, s) {
    if (s.includes(q)) return 100 - s.indexOf(q);
    let score = 0;
    let j = 0;
    let streak = 0;
    for (let i = 0; i < s.length && j < q.length; i++) {
        if (s[i] === q[j]) {
            j++;
            streak++;
            score += 1 + streak + (i === 0 || s[i - 1] === ' ' ? 3 : 0);
        } else {
            streak = 0;
        }
    }
    return j === q.length ? score : 0;
}
