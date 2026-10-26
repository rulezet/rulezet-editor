/**
 * Guided tutorial: one step per feature, the element it is about highlighted (the rest dimmed),
 * an explanation, an example, and often a "Try it" button that does the thing for real.
 * Plain DOM, inside the editor's root; Esc closes, ← / → move.
 *
 *   new Tour(root, steps, t).start()
 *   step: { title, body, example?, keys?, target?: () => Element | null, try?: { label, run() } }
 */
import { h, icon } from './dom.js';

export class Tour {
    constructor(root, steps, t, { onStep = null } = {}) {
        this.root = root;
        this.steps = steps;
        this.t = t;
        this.onStep = onStep;           // called before each step (e.g. close a menu a "Try it" opened)
        this.index = 0;
        this.onKey = (e) => {
            if (!this.el) return;
            if (e.key === 'Escape') { e.preventDefault(); this.close(); }
            else if (e.key === 'ArrowRight') { e.preventDefault(); this.go(this.index + 1); }
            else if (e.key === 'ArrowLeft') { e.preventDefault(); this.go(this.index - 1); }
        };
        this.onResize = () => this.place();
    }

    start(index = 0) {
        this.close();
        this.el = h('div', { class: 'rze-tour', role: 'dialog', 'aria-modal': 'true', 'aria-label': this.t('tutorial') });
        this.spot = h('div', { class: 'rze-tour-spot' });
        this.card = h('div', { class: 'rze-tour-card' });
        this.el.append(this.spot, this.card);
        this.root.appendChild(this.el);
        document.addEventListener('keydown', this.onKey, true);
        window.addEventListener('resize', this.onResize);
        this.go(index);
    }

    close() {
        if (!this.el) return;
        this.el.remove();
        this.el = null;
        document.removeEventListener('keydown', this.onKey, true);
        window.removeEventListener('resize', this.onResize);
    }

    go(index) {
        if (index < 0 || index >= this.steps.length) { if (index >= this.steps.length) this.close(); return; }
        this.index = index;
        if (this.onStep) { try { this.onStep(index); } catch { /* a host hook must not stop the tour */ } }
        const step = this.steps[index];
        const t = this.t;
        const last = index === this.steps.length - 1;
        this.card.replaceChildren(
            h('div', { class: 'rze-tour-head' },
                h('span', { class: 'rze-tour-count', text: `${index + 1} / ${this.steps.length}` }),
                h('strong', { text: step.title }),
                h('button', { type: 'button', class: 'rze-icon-btn', 'aria-label': t('tourClose'), onclick: () => this.close() }, icon('close'))),
            h('div', { class: 'rze-tour-body' }, ...paragraphs(step.body)),
            step.example ? h('pre', { class: 'rze-tour-example' }, step.example) : '',
            step.keys ? h('div', { class: 'rze-tour-keys' }, ...step.keys.map(([k, what]) => h('div', {}, h('kbd', { text: k }), h('span', { text: what })))) : '',
            h('div', { class: 'rze-tour-foot' },
                h('div', { class: 'rze-tour-dots' }, ...this.steps.map((_, i) => h('button', {
                    type: 'button', class: `rze-tour-dot${i === index ? ' rze-on' : ''}`, 'aria-label': `${i + 1}`, onclick: () => this.go(i),
                }))),
                h('span', { class: 'rze-toolbar-fill' }),
                step.try ? h('button', { type: 'button', class: 'rze-btn rze-tour-try', onclick: () => { step.try.run(); requestAnimationFrame(() => this.place()); } },
                    icon('play'), h('span', { text: step.try.label })) : '',
                index ? h('button', { type: 'button', class: 'rze-btn', onclick: () => this.go(index - 1) }, t('tourBack')) : '',
                h('button', { type: 'button', class: 'rze-btn rze-btn-primary', onclick: () => this.go(index + 1) }, last ? t('tourDone') : t('tourNext'))));
        requestAnimationFrame(() => this.place());
    }

    /** Spotlight on the step's element; the card next to it, kept inside the editor. */
    place() {
        if (!this.el) return;
        const step = this.steps[this.index];
        const box = this.root.getBoundingClientRect();
        let target = null;
        try { target = step.target ? step.target() : null; } catch { target = null; }
        const r = target && target.offsetParent !== null ? target.getBoundingClientRect() : null;
        const pad = 6;
        if (r && r.width && r.height) {
            Object.assign(this.spot.style, {
                display: 'block', left: `${r.left - box.left - pad}px`, top: `${r.top - box.top - pad}px`,
                width: `${r.width + pad * 2}px`, height: `${r.height + pad * 2}px`,
            });
        } else {
            Object.assign(this.spot.style, { display: 'block', left: `${box.width / 2}px`, top: `${box.height / 2}px`, width: '0px', height: '0px' });
        }
        const card = this.card.getBoundingClientRect();
        const W = Math.min(card.width || 380, box.width - 24);
        let left = r ? r.left - box.left : (box.width - W) / 2;
        let top = r ? r.bottom - box.top + 14 : (box.height - (card.height || 200)) / 2;
        if (r && top + (card.height || 200) > box.height - 8) top = r.top - box.top - (card.height || 200) - 14;   // above
        if (r && top < 8) {                                                                        // beside
            top = Math.max(8, r.top - box.top);
            left = r.left - box.left - W - 14 > 8 ? r.left - box.left - W - 14 : r.right - box.left + 14;
        }
        left = Math.max(12, Math.min(left, box.width - W - 12));
        top = Math.max(8, Math.min(top, box.height - (card.height || 200) - 8));
        Object.assign(this.card.style, { left: `${left}px`, top: `${top}px` });
        if (target && target.scrollIntoView && r && (r.top < 0 || r.bottom > window.innerHeight)) target.scrollIntoView({ block: 'nearest' });
    }
}

function paragraphs(text) {
    return String(text || '').split('\n\n').map(p => h('p', {}, ...inlineCode(p)));
}

/** `code` spans in a paragraph. */
function inlineCode(text) {
    return text.split(/(`[^`]+`)/).map(part => (part.startsWith('`') && part.endsWith('`') ? h('code', { text: part.slice(1, -1) }) : part));
}
