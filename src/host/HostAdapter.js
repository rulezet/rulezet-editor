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
 *
 *   Tests on samples (rulezet-tester behind the host; see docs/testing.md):
 *   testSets(language)              -> { available, sets: [{ id, name, kind, count, description, labels }] }
 *   startTest(language, text, sets) -> run (every sample pending)
 *   testState(runId)                -> run; poll until status is done | failed
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

/** Base for adapters that talk JSON over HTTP. A 400 answer still carries a body to read. */
export class HttpHost extends LocalDraftHost {
    constructor(options = {}) {
        super(options.draftPrefix);
        this.baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '');
        this.apiKey = options.apiKey || null;
        this.csrfToken = options.csrfToken || null;
        this.fetch = options.fetch || ((...args) => window.fetch(...args));
        this.timeout = options.timeout ?? 8000;
        this.formatMap = options.formatMap || {};      // editor language id -> backend format name
    }

    format(language) {
        return this.formatMap[language] || language;
    }

    _headers(json) {
        const h = { Accept: 'application/json' };
        if (json) h['Content-Type'] = 'application/json';
        if (this.apiKey) h['X-API-KEY'] = this.apiKey;
        if (this.csrfToken) h['X-CSRFToken'] = this.csrfToken;
        return h;
    }

    async _request(path, init = {}, { allow = [400] } = {}) {
        const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timer = ctrl ? setTimeout(() => ctrl.abort(), this.timeout) : null;
        try {
            let res;
            try {
                res = await this.fetch(this.baseUrl + path, { ...init, signal: ctrl ? ctrl.signal : undefined });
            } catch (e) {
                if (e && e.name === 'AbortError') throw new Error(`${this.name} did not answer within ${Math.round(this.timeout / 1000)} s`);
                throw new Error(`${this.name} not reachable: ${e.message || e}`);
            }
            const data = await res.json().catch(() => ({}));
            if (!res.ok && !allow.includes(res.status)) {
                const err = new Error(data.error || data.message || `HTTP ${res.status}`);
                err.status = res.status;
                throw err;
            }
            return data;
        } finally {
            if (timer) clearTimeout(timer);
        }
    }
}
