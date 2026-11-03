/**
 * Sigma language pack for rulezet-editor (detection rules, YAML). One YAML document (between ---
 * lines) is one rule. Pure data and functions: no network, no DOM, no editor engine import.
 */
import { parse } from './parser.js';
import { lint, DEFAULT_LINT_OPTIONS } from './lint.js';
import { complete, TOP_SNIPPETS } from './completion.js';
import { hover, definition, references, rename } from './navigation.js';
import { actions, setTop, setList, removeTop } from './actions.js';
import { stream } from './highlight.js';
import { TEMPLATES } from './templates.js';
import { TUTORIAL } from './tutorial.js';
import { CREDITS } from './credits.js';
import { entry, yamlValue } from './yaml.js';
import { selections } from './form.js';
import { format } from './format.js';

const SAMPLE = `title: Suspicious Certutil Download
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: experimental
description: Certutil used to download a file from the Internet
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: you
date: ${new Date().toISOString().slice(0, 10)}
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
    condition: all of selection_*
falsepositives:
    - Administrators downloading certificates
level: high
`;

// Fields panel keys that live in the tags (attack.t1059, cve.2024-3094), not in a key of their own
const TAG_KEYS = {
    mitre_attack: { prefix: 'attack.', read: (t) => (/^attack\.t\d{4}(\.\d{3})?$/.test(t) ? t.slice(7).toUpperCase() : null), write: (v) => (/^T\d{4}(\.\d{3})?$/i.test(v) ? `attack.${v.toLowerCase()}` : null) },
    cve: { prefix: 'cve.', read: (t) => (/^cve\.\d{4}-\d{4,}$/.test(t) ? `CVE-${t.slice(4)}` : null), write: (v) => (/^CVE-\d{4}-\d{4,}$/i.test(v) ? `cve.${v.slice(4)}` : null) },
};
TAG_KEYS.attack = TAG_KEYS.mitre_attack;
const LIST_KEYS = ['references', 'falsepositives', 'fields', 'scope'];

const findRule = (model, name) => model.rules.find(r => r.name === name && r.root) || null;

export default {
    id: 'sigma',
    name: 'Sigma',
    version: '0.1.0',
    maturity: 'standard',
    extensions: ['.yml', '.yaml'],
    validateAs: 'sigma',
    sample: SAMPLE,

    detect(text) {
        const t = String(text || '');
        if (/^title\s*:/m.test(t) && /^logsource\s*:/m.test(t) && /^detection\s*:/m.test(t)) return 0.95;
        if (/^detection\s*:/m.test(t) && /^\s+condition\s*:/m.test(t)) return 0.8;
        if (/^logsource\s*:/m.test(t)) return 0.6;
        return 0;
    },

    stream,
    comments: { line: '#' },
    ruleSeparator: '---\n',      // a rule inserted from Rulezet goes in its own YAML document
    indentUnit: '    ',
    snippets: TOP_SNIPPETS,
    tutorial: TUTORIAL,
    templates: TEMPLATES,
    credits: CREDITS,
    actions,
    selections,                // Fields panel: log source, search identifiers and condition as a form

    parse,
    lint(model, options) { return lint(model, { ...DEFAULT_LINT_OPTIONS, ...options }); },
    complete,
    hover,
    definition,
    references,
    rename,
    format,                    // Shift+Alt+F: SigmaHQ layout (4 spaces, keys in spec order)

    /** One entry per rule (YAML document), with its log source, search identifiers and condition. */
    splitRules(model) {
        return model.rules.map(r => {
            const ls = r.logsource;
            const lsText = ls ? [ls.product, ls.category, ls.service].filter(Boolean).map(x => x.value).join(' / ') : '';
            const children = [];
            if (ls) children.push({ name: `logsource${lsText ? ': ' + lsText : ''}`, from: ls.entry.keyFrom, to: ls.entry.keyTo, kind: 'logsource' });
            if (r.detection) {
                for (const s of r.detection.searches) children.push({ name: s.name, from: s.from, to: s.to, kind: 'search identifier' });
                const c = r.detection.conditionEntry;
                if (c) children.push({ name: 'condition', from: c.keyFrom, to: c.to, kind: 'condition' });
            }
            return {
                name: r.name,
                from: r.from,
                to: r.to,
                kind: r.correlation ? `correlation (${(r.correlation.type && r.correlation.type.value) || '?'})`
                    : [r.status && r.status.value, r.level && r.level.value].filter(Boolean).join(' · ') || (r.kind === 'detection' ? 'rule' : `${r.kind} rule`),
                tags: r.tags.map(t => t.value),
                detail: r.description ? r.description.value : '',
                text: model.text.slice(r.from, r.to),
                children,
            };
        });
    },

    /** Key / value metadata of a rule (Fields panel): the top-level keys, list items one by one,
     *  and the ATT&CK techniques / CVEs of the tags as the keys mitre_attack / cve. */
    meta: {
        entries(model, ruleName) {
            const rule = findRule(model, ruleName);
            if (!rule) return null;
            const out = [];
            for (const e of rule.root.entries) {
                if (e.value && e.value.type === 'scalar' && e.value.value != null) out.push({ key: e.key, value: String(e.value.value) });
                else if (e.value && e.value.type === 'seq' && (LIST_KEYS.includes(e.key) || e.key === 'tags')) {
                    for (const it of e.value.items) if (it.type === 'scalar' && it.value != null) out.push({ key: e.key, value: String(it.value) });
                }
            }
            for (const [key, spec] of Object.entries(TAG_KEYS)) {
                if (key === 'attack') continue;
                for (const t of rule.tags) { const v = spec.read(t.value); if (v) out.push({ key, value: v }); }
            }
            return out;
        },
        /** Sets `key`: a top-level value, a list (references…: "a, b"), or the tags of a tag key. */
        set(model, ruleName, key, value) {
            const rule = findRule(model, ruleName);
            if (!rule || !/^[A-Za-z_][\w-]*$/.test(key)) return null;
            const text = model.text;
            const spec = TAG_KEYS[key];
            if (spec) {
                const items = String(value || '').split(/\s*[,;]\s*/).map(v => spec.write(v.trim())).filter(Boolean);
                const kept = rule.tags.map(t => t.value).filter(t => !spec.read(t));
                const all = [...new Set([...kept, ...items])];
                return all.length ? setList(text, rule, 'tags', all) : removeTop(text, rule, 'tags');
            }
            if (key === 'tags') return [];               // Rulezet tags are not Sigma tags: never written into the rule
            if (LIST_KEYS.includes(key)) {
                const items = String(value || '').split(/\s*,\s+/).map(v => v.trim()).filter(Boolean);
                return items.length ? setList(text, rule, key, [...new Set(items)]) : removeTop(text, rule, key);
            }
            const raw = key === 'id' && /^[0-9a-f-]{36}$/i.test(String(value).trim()) ? String(value).trim() : yamlValue(String(value).replace(/\n/g, ' ').trim());
            return setTop(text, rule, key, raw);
        },
        remove(model, ruleName, key) {
            const rule = findRule(model, ruleName);
            if (!rule) return null;
            const spec = TAG_KEYS[key];
            if (spec) {
                const kept = rule.tags.map(t => t.value).filter(t => !spec.read(t));
                if (kept.length === rule.tags.length) return [];
                return kept.length ? setList(model.text, rule, 'tags', kept) : removeTop(model.text, rule, 'tags');
            }
            if (key === 'title') return [];              // a Sigma rule always needs its title
            return removeTop(model.text, rule, key);
        },
        /** A new rule to fill from the Fields panel: valid as it is (Rulezet accepts it). */
        skeleton(name) {
            return `title: ${yamlValue(name)}\nid: {{uuid}}\nstatus: experimental\ndate: {{date}}\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\change_me.exe'\n    condition: selection\nlevel: medium\n`;
        },
        /** The rule's name is its title: any text (256 characters at most). */
        ruleName(title) {
            const t = String(title || '').replace(/\s+/g, ' ').trim();
            return t ? t.slice(0, 256) : null;
        },
        renameRule(model, ruleName, newName) {
            const rule = findRule(model, ruleName);
            if (!rule) return null;
            if (model.rules.some(r => r !== rule && r.title && r.title.value === newName)) return { error: `A rule titled ${newName} already exists` };
            return setTop(model.text, rule, 'title', yamlValue(newName));
        },
    },

    /** Tests on samples (rulezet-tester, driver sigma): a hit is one event; its item names the
     *  search identifiers that matched it, shown in the rule. */
    test: {
        sampleKind: 'events',
        hitLabel(hit) {
            const w = hit.where || {};
            return w.kind === 'event' ? `event #${w.index + 1}${hit.item ? ` (${hit.item})` : ''}` : (hit.item || 'condition');
        },
        locate(model, hit) {
            const rule = model.rules.find(r => r.name === hit.rule || (r.title && r.title.value === hit.rule));
            if (!rule) return null;
            const first = String(hit.item || '').split(',')[0].trim();
            const s = first && rule.detection && rule.detection.searches.find(x => x.name === first);
            return s ? { from: s.from, to: s.to } : { from: rule.from, to: rule.from };
        },
    },

    /** Rules this document links to (related: ids) that are not in it: looked up on the host. */
    dependencies(model) {
        const here = new Set(model.rules.map(r => r.id && r.id.value).filter(Boolean));
        const names = new Set(model.rules.map(r => r.yamlName && r.yamlName.value.trim()).filter(Boolean));
        return model.rules.flatMap(r => [
            ...relatedOf(r).filter(x => !here.has(x.id)).map(x => ({ rule: r.name, name: x.id, from: x.from, to: x.to })),
            ...(r.correlation ? r.correlation.rules.filter(x => !here.has(x.value) && !names.has(x.value)).map(x => ({ rule: r.name, name: x.value, from: x.from, to: x.to })) : []),
        ]);
    },

    /** Foldable ranges: every block (logsource, detection, a search identifier, a list). */
    folding(model) {
        const out = [];
        const text = model.text;
        const walk = (node) => {
            if (!node || node.type !== 'map') return;
            for (const e of node.entries) {
                const v = e.value;
                if (v && (v.type === 'map' || v.type === 'seq') && !v.flow) {
                    const eol = text.indexOf('\n', e.keyFrom);
                    if (eol !== -1 && eol < v.to) out.push({ from: eol, to: v.to });
                    walk(v);
                    if (v.type === 'seq') v.items.forEach(walk);
                }
            }
        };
        for (const r of model.rules) walk(r.root);
        return out;
    },
};

/** The related: entries of a rule: [{ id, type, from, to }] (the id's range). */
export function relatedOf(rule) {
    const e = rule.root && entry(rule.root, 'related');
    if (!e || !e.value || e.value.type !== 'seq') return [];
    return e.value.items.filter(it => it.type === 'map').map(it => {
        const id = entry(it, 'id');
        const type = entry(it, 'type');
        return id && id.value && id.value.type === 'scalar' && id.value.value
            ? { id: String(id.value.value).trim(), type: type && type.value ? String(type.value.value || '') : '', from: id.value.from, to: id.value.to }
            : null;
    }).filter(Boolean);
}

export { entry };
