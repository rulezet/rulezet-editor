/**
 * Host adapter for a Rulezet instance (https://rulezet.org or self-hosted).
 *
 *   new RulezetHost({ baseUrl: 'https://rulezet.org' })
 *   new RulezetHost({ baseUrl: '' })            // same origin (inside Rulezet)
 *
 * Uses the public API only: no account needed.
 *   POST /api/rule/public/validate     { format, content }
 *   GET  /api/rule/public/searchPage   ?search=&rule_type=&per_page=
 */
import { HttpHost } from './HostAdapter.js';

export class RulezetHost extends HttpHost {
    constructor(options = {}) {
        super(options);
        this.name = options.name || 'Rulezet';
    }

    ruleUrl(uuid) {
        return `${this.baseUrl}/rule/detail_rule/${uuid}`;
    }

    async validate(language, text) {
        const data = await this._request('/api/rule/public/validate', {
            method: 'POST',
            headers: this._headers(true),
            body: JSON.stringify({ format: this.format(language), content: text }),
        });
        if (data.error && !Array.isArray(data.errors)) throw new Error(data.error);
        const toItem = (severity) => (msg) => {
            const m = String(msg).match(/line\s+(\d+)(?:\s*[,:]\s*col(?:umn)?\s*(\d+))?\s*[:,-]?\s*(.*)$/i);
            return m
                ? { severity, message: m[3] || String(msg), line: Number(m[1]), column: m[2] ? Number(m[2]) : null }
                : { severity, message: String(msg) };
        };
        return [...(data.errors || []).map(toItem('error')), ...(data.warnings || []).map(toItem('warning'))];
    }

    async searchRules(language, query, { limit = 10 } = {}) {
        const params = new URLSearchParams({ search: query, rule_type: this.format(language), per_page: String(limit) });
        const data = await this._request(`/api/rule/public/searchPage?${params}`, { headers: this._headers(false) });
        return (data.results || data.rules || []).map(r => ({
            name: r.title,
            uuid: r.uuid,
            description: r.description || '',
            author: r.author || '',
            content: r.content || '',
            url: r.uuid ? this.ruleUrl(r.uuid) : null,
        }));
    }

    async getRule(language, name) {
        const results = await this.searchRules(language, name, { limit: 20 });
        return results.find(r => r.name === name) || null;
    }
}
