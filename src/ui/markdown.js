/**
 * A small, safe Markdown renderer for the editor's own pages (credits, help): builds DOM nodes,
 * never parses HTML, so a text can never inject markup or script.
 *
 *   markdown(text) -> HTMLElement
 *
 * Supported: # ## ### headings, paragraphs, - / * lists (one level), | tables |, > notes,
 * --- rules, ``` code blocks, and inline **bold**, *italic*, `code`, [links](https://…)
 * (http(s) and mailto only; they open in a new tab).
 */
import { h } from './dom.js';

const SAFE_URL = /^(https?:\/\/|mailto:)/i;

function inline(text) {
    const out = [];
    const re = /(\*\*([^*]+)\*\*|\*([^*]+)\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\))/g;
    let last = 0, m;
    while ((m = re.exec(text))) {
        if (m.index > last) out.push(text.slice(last, m.index));
        if (m[2]) out.push(h('strong', { text: m[2] }));
        else if (m[3]) out.push(h('em', { text: m[3] }));
        else if (m[4]) out.push(h('code', { text: m[4] }));
        else if (m[5]) out.push(SAFE_URL.test(m[6])
            ? h('a', { href: m[6], target: '_blank', rel: 'noopener noreferrer', text: m[5] })
            : m[5]);
        last = re.lastIndex;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
}

export function markdown(text) {
    const root = h('div', { class: 'rze-md' });
    const lines = String(text || '').replace(/\r\n/g, '\n').split('\n');
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        if (!line.trim()) { i++; continue; }
        if (line.startsWith('```')) {
            const code = [];
            i++;
            while (i < lines.length && !lines[i].startsWith('```')) code.push(lines[i++]);
            i++;
            root.appendChild(h('pre', { class: 'rze-mono', text: code.join('\n') }));
            continue;
        }
        const head = line.match(/^(#{1,3})\s+(.*)$/);
        if (head) { root.appendChild(h(`h${head[1].length + 2}`, {}, ...inline(head[2]))); i++; continue; }
        if (/^---+\s*$/.test(line)) { root.appendChild(h('hr')); i++; continue; }
        if (/^\s*[-*]\s+/.test(line)) {
            const items = [];
            while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(h('li', {}, ...inline(lines[i++].replace(/^\s*[-*]\s+/, ''))));
            root.appendChild(h('ul', {}, ...items));
            continue;
        }
        if (line.trim().startsWith('|')) {
            const rows = [];
            while (i < lines.length && lines[i].trim().startsWith('|')) rows.push(lines[i++]);
            const cells = (r) => r.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
            const body = rows.filter(r => !cells(r).every(c => /^:?-{2,}:?$/.test(c)));   // drop the |---| line
            const [first, ...rest] = body;
            root.appendChild(h('table', {},
                h('thead', {}, h('tr', {}, ...cells(first).map(c => h('th', {}, ...inline(c))))),
                h('tbody', {}, ...rest.map(r => h('tr', {}, ...cells(r).map(c => h('td', {}, ...inline(c))))))));
            continue;
        }
        if (line.startsWith('>')) {
            const quote = [];
            while (i < lines.length && lines[i].startsWith('>')) quote.push(lines[i++].replace(/^>\s?/, ''));
            root.appendChild(h('blockquote', {}, ...inline(quote.join(' '))));
            continue;
        }
        const para = [];
        while (i < lines.length && lines[i].trim() && !/^(#{1,3}\s|```|---|\s*[-*]\s|\||>)/.test(lines[i])) para.push(lines[i++]);
        root.appendChild(h('p', {}, ...inline(para.join(' '))));
    }
    return root;
}
