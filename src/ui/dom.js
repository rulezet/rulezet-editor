/** Tiny DOM helpers and icons (no framework, no icon font). */

export function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, val] of Object.entries(attrs || {})) {
        if (val == null || val === false) continue;
        if (k === 'class') el.className = val;
        else if (k === 'text') el.textContent = val;
        else if (k === 'html') el.innerHTML = val;
        else if (k.startsWith('on') && typeof val === 'function') el.addEventListener(k.slice(2).toLowerCase(), val);
        else if (k === 'style' && typeof val === 'object') Object.assign(el.style, val);
        else el.setAttribute(k, val === true ? '' : String(val));
    }
    for (const c of children.flat()) {
        if (c == null || c === false) continue;
        el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return el;
}

const svg = (body, size = 14) => `<svg width="${size}" height="${size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;

export const ICONS = {
    error: svg('<circle cx="8" cy="8" r="6.5"/><path d="M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4"/>'),
    warning: svg('<path d="M8 1.8l6.5 12H1.5z"/><path d="M8 6.5v3.2M8 11.8v.1"/>'),
    info: svg('<circle cx="8" cy="8" r="6.5"/><path d="M8 7.2v4M8 4.8v.1"/>'),
    ok: svg('<circle cx="8" cy="8" r="6.5"/><path d="M5.2 8.3l2 2 3.8-4"/>'),
    rule: svg('<path d="M3 2.5h7l3 3v8H3z"/><path d="M10 2.5v3h3M5.5 8.5h5M5.5 11h3.5"/>'),
    format: svg('<path d="M2.5 3.5h11M2.5 6.5h7M2.5 9.5h11M2.5 12.5h7"/>'),
    outline: svg('<path d="M2.5 3.5h2M2.5 8h2M2.5 12.5h2M6.5 3.5h7M8.5 8h5M8.5 12.5h5"/>'),
    problems: svg('<path d="M8 1.8l6.5 12H1.5z"/><path d="M8 6.5v3.2M8 11.8v.1"/>'),
    palette: svg('<rect x="1.5" y="3" width="13" height="10" rx="1.5"/><path d="M4 6.5l2 1.5-2 1.5M7.5 10h4"/>'),
    sun: svg('<circle cx="8" cy="8" r="3"/><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1"/>'),
    moon: svg('<path d="M13 9.5A5.5 5.5 0 1 1 6.5 3a4.5 4.5 0 0 0 6.5 6.5z"/>'),
    lock: svg('<rect x="3.5" y="7" width="9" height="7" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>'),
    unlock: svg('<rect x="3.5" y="7" width="9" height="7" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 4.9-.7"/>'),
    search: svg('<circle cx="7" cy="7" r="4.5"/><path d="M10.4 10.4 14 14"/>'),
    wrap: svg('<path d="M2 4h12M2 8h9.5a2.5 2.5 0 0 1 0 5H8M9.5 11 8 13l1.5 2M2 12h3"/>'),
    expand: svg('<path d="M2 6V2h4M10 2h4v4M14 10v4h-4M6 14H2v-4"/>'),
    collapse: svg('<path d="M6 2v4H2M14 6h-4V2M10 14v-4h4M2 10h4v4"/>'),
    cloud: svg('<path d="M4.5 12.5h7.5a3 3 0 0 0 .3-6A4.5 4.5 0 0 0 3.6 7.6 2.5 2.5 0 0 0 4.5 12.5z"/>'),
    copy: svg('<rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M11 5V3.5A1.5 1.5 0 0 0 9.5 2h-6A1.5 1.5 0 0 0 2 3.5v6A1.5 1.5 0 0 0 3.5 11H5"/>'),
    close: svg('<path d="M4 4l8 8M12 4l-8 8"/>'),
    search: svg('<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/>'),
    link: svg('<path d="M6.5 9.5l3-3M7 4.5l1.2-1.2a2.8 2.8 0 0 1 4 4L11 8.5M9 11.5l-1.2 1.2a2.8 2.8 0 0 1-4-4L5 7.5"/>'),
    edit: svg('<path d="M10.5 2.5l3 3L6 13H3v-3z"/>'),
    tools: svg('<path d="M9.5 2.5a3 3 0 0 0 3.9 3.9L8 11.8 4.2 8z"/><path d="M5.5 9.5 2.5 12.5l1 1 3-3"/>'),
    plus: svg('<path d="M8 3v10M3 8h10"/>'),
    undo: svg('<path d="M5.5 4.5 2.5 7.5l3 3"/><path d="M2.5 7.5h7a4 4 0 0 1 0 8H8"/>'),
    redo: svg('<path d="M10.5 4.5l3 3-3 3"/><path d="M13.5 7.5h-7a4 4 0 0 0 0 8H8"/>'),
    play: svg('<path d="M4.5 2.8v10.4L13 8z"/>'),
    tag: svg('<path d="M2 2.5h5.5l6.5 6.5-5 5-6.5-6.5z"/><circle cx="5" cy="5.5" r="1"/>'),
};

export function icon(name, cls = '') {
    return h('span', { class: `rze-icon ${cls}`.trim(), html: ICONS[name] || '' });
}
