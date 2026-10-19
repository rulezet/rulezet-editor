/**
 * Language registry: the only global state of rulezet-editor.
 */
const languages = new Map();

const REQUIRED = ['id', 'name'];

export function registerLanguage(pack) {
    for (const key of REQUIRED) {
        if (!pack || !pack[key]) throw new Error(`rulezet-editor: a language pack needs "${key}"`);
    }
    languages.set(pack.id, pack);
    return pack;
}

export function getLanguage(id) {
    return languages.get(id) || null;
}

export function listLanguages() {
    return [...languages.values()];
}

/** Best pack for a text (pack.detect scores 0..1), or null. */
export function detectLanguage(text, fallback = null) {
    let best = null;
    let bestScore = 0;
    for (const pack of languages.values()) {
        if (typeof pack.detect !== 'function') continue;
        let score = 0;
        try { score = pack.detect(text) || 0; } catch { score = 0; }
        if (score > bestScore) { best = pack; bestScore = score; }
    }
    return bestScore >= 0.5 ? best : (fallback ? getLanguage(fallback) : null);
}

/** Pack for a file name, by extension. */
export function languageForFile(name) {
    const lower = (name || '').toLowerCase();
    return listLanguages().find(p => (p.extensions || []).some(ext => lower.endsWith(ext))) || null;
}
