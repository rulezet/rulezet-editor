/**
 * Mouse-resizable panels: a thin handle next to a panel; dragging it sets the panel's width or
 * height, remembered per viewer (localStorage). The handle is a sibling of the panel (panels
 * re-render their content freely) and hides itself when the panel is hidden (CSS :has).
 *
 *   resizable(panelEl, { axis: 'x' | 'y', side: 'before' | 'after', key, min, max })
 *     axis x, handle before the panel: dragging left widens it (side panels on the right);
 *     axis y, handle before the panel: dragging up heightens it (bottom panels);
 *     axis y, handle after the element: dragging down heightens it (the whole editor).
 */
import { h } from './dom.js';

const PREFIX = 'rulezet-editor:size:';

function load(key) {
    try { const v = Number(window.localStorage.getItem(PREFIX + key)); return v > 0 ? v : null; } catch { return null; }
}

function save(key, value) {
    try { window.localStorage.setItem(PREFIX + key, String(Math.round(value))); } catch { /* storage blocked */ }
}

export function resizable(el, { axis = 'x', side = 'before', key, min = 120, max = () => Infinity, onResize = null } = {}) {
    const prop = axis === 'x' ? 'width' : 'height';
    const apply = (size) => {
        const limit = typeof max === 'function' ? max() : max;
        const v = Math.max(min, Math.min(size, limit));
        el.style[prop] = `${v}px`;
        if (axis === 'x') { el.style.maxWidth = 'none'; el.style.flex = `0 0 ${v}px`; } else { el.style.maxHeight = 'none'; }
        return v;
    };
    const saved = key ? load(key) : null;
    if (saved) apply(saved);

    const handle = h('div', {
        class: `rze-resize rze-resize-${axis}`, role: 'separator', tabindex: '0',
        'aria-orientation': axis === 'x' ? 'vertical' : 'horizontal', title: 'Drag to resize (double-click: default size)',
    });
    el.insertAdjacentElement(side === 'before' ? 'beforebegin' : 'afterend', handle);

    handle.addEventListener('pointerdown', (e) => {
        if (e.button !== 0) return;
        e.preventDefault();
        handle.setPointerCapture(e.pointerId);
        const start = axis === 'x' ? e.clientX : e.clientY;
        const startSize = el.getBoundingClientRect()[prop];
        const sign = side === 'before' ? -1 : 1;
        document.body.classList.add('rze-resizing', `rze-resizing-${axis}`);
        let last = startSize;
        const move = (ev) => {
            const pos = axis === 'x' ? ev.clientX : ev.clientY;
            last = apply(startSize + sign * (pos - start));
            if (onResize) onResize(last);
        };
        const up = () => {
            handle.removeEventListener('pointermove', move);
            handle.removeEventListener('pointerup', up);
            handle.removeEventListener('pointercancel', up);
            document.body.classList.remove('rze-resizing', `rze-resizing-${axis}`);
            if (key) save(key, last);
        };
        handle.addEventListener('pointermove', move);
        handle.addEventListener('pointerup', up);
        handle.addEventListener('pointercancel', up);
    });
    // keyboard: arrows resize by 20px
    handle.addEventListener('keydown', (e) => {
        const step = { ArrowLeft: 20, ArrowRight: -20, ArrowUp: 20, ArrowDown: -20 }[e.key];
        if (step === undefined) return;
        e.preventDefault();
        const signed = side === 'before' ? step : -step;
        const v = apply(el.getBoundingClientRect()[prop] + signed);
        if (key) save(key, v);
        if (onResize) onResize(v);
    });
    handle.addEventListener('dblclick', () => {
        el.style[prop] = ''; el.style.flex = ''; el.style.maxWidth = ''; el.style.maxHeight = '';
        try { window.localStorage.removeItem(PREFIX + key); } catch { /* storage blocked */ }
        if (onResize) onResize(null);
    });
    return handle;
}
