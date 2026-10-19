/**
 * Host adapter: the editor's only way to reach a backend.
 *
 * Every method is optional. The editor checks `has(name)` and hides the
 * matching feature when a method is missing. Methods never parse rules:
 * they send text and return plain data.
 *
 *   validate(language, text)        -> [{ message, severity: 'error'|'warning', line?, column? }]
 *   searchRules(language, query)    -> [{ name, description?, author?, url?, content? }]
 *   getRule(language, name)         -> { name, description?, author?, url?, content? } | null
 *   loadDraft(key) / saveDraft(key, text)
 */
export class HostAdapter {
    constructor() {
        this.name = 'host';
    }

    has(method) {
        return typeof this[method] === 'function' && this[method] !== HostAdapter.prototype[method];
    }
}

/** Keeps drafts in the browser (localStorage). Safe when storage is blocked. */
export class LocalDraftHost extends HostAdapter {
    constructor(prefix = 'rulezet-editor:draft:') {
        super();
        this.name = 'local';
        this.prefix = prefix;
    }

    async loadDraft(key) {
        try {
            const raw = window.localStorage.getItem(this.prefix + key);
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    }

    async saveDraft(key, text) {
        try {
            if (text == null) window.localStorage.removeItem(this.prefix + key);
            else window.localStorage.setItem(this.prefix + key, JSON.stringify({ text, savedAt: Date.now() }));
        } catch {
            /* storage blocked: drafts are a convenience only */
        }
    }
}
