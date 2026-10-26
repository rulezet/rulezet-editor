/**
 * Host adapter for the editor's own server (server/rulezet_editor, Python).
 * The same adapter works in both modes; only the server side changes:
 *
 *   inside Rulezet   blueprint mounted by Rulezet, answers from its database and compilers
 *   standalone       `rulezet-editor serve`: local compilers, rule lookup on rulezet.org
 *
 *   new EditorServerHost({ baseUrl: '/editor-api', csrfToken })
 *
 *   POST /validate   { format, content }  -> { valid, items }
 *   GET  /rules      ?format=&q=&limit=   -> { results }
 *   GET  /rules/<name>?format=            -> rule | 404
 *   GET  /test/sets?format=               -> { available, sets }      (rulezet-tester)
 *   POST /test/  { format, text, sets }   -> 202 run
 *   GET  /test/<run id>                   -> run
 */
import { HttpHost } from './HostAdapter.js';

export class EditorServerHost extends HttpHost {
    constructor(options = {}) {
        super({ ...options, baseUrl: options.baseUrl ?? '/editor-api' });
        this.name = options.name || 'Rulezet';
    }

    async validate(language, text) {
        const data = await this._request('/validate', {
            method: 'POST',
            headers: this._headers(true),
            body: JSON.stringify({ format: this.format(language), content: text }),
        });
        return Array.isArray(data.items) ? data.items : [];
    }

    async searchRules(language, query, { limit = 10 } = {}) {
        const params = new URLSearchParams({ format: this.format(language), q: query, limit: String(limit) });
        const data = await this._request(`/rules?${params}`, { headers: this._headers(false) });
        return data.results || [];
    }

    async testSets(language) {
        const params = new URLSearchParams({ format: this.format(language) });
        try {
            return await this._request(`/test/sets?${params}`, { headers: this._headers(false) });
        } catch (e) {
            if (e.status === 404) return { available: false, sets: [] };      // server without tests
            throw e;
        }
    }

    async startTest(language, text, sets) {
        return this._request('/test/', {
            method: 'POST',
            headers: this._headers(true),
            body: JSON.stringify({ format: this.format(language), text, sets }),
        }, { allow: [] });
    }

    async testState(runId) {
        return this._request(`/test/${encodeURIComponent(runId)}`, { headers: this._headers(false) }, { allow: [] });
    }

    async getRule(language, name) {
        const params = new URLSearchParams({ format: this.format(language) });
        try {
            return await this._request(`/rules/${encodeURIComponent(name)}?${params}`, { headers: this._headers(false) });
        } catch (e) {
            if (e.status === 404) return null;
            throw e;
        }
    }
}
