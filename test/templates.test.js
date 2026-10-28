// Every rule template of the YARA pack, its placeholders filled with their default text, must
// lint clean and compile with the real libyara (yara-python, skipped when it is not installed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import yara from '../src/languages/yara/index.js';
import { TEMPLATES, templateGroups } from '../src/languages/yara/templates.js';

const filled = (tpl) => tpl.snippet
    .replace(/\$\{([^}]*)\}/g, (_, def) => def)
    .replace(/\{\{uuid\}\}/g, '00000000-0000-4000-8000-000000000000')
    .replace(/\{\{date\}\}/g, '2026-10-28');

test('templates: unique ids, a category, a description, grouped', () => {
    assert.ok(TEMPLATES.length >= 20);
    assert.equal(new Set(TEMPLATES.map(t => t.id)).size, TEMPLATES.length);
    for (const t of TEMPLATES) assert.ok(t.label && t.category && t.description && t.snippet, t.id);
    assert.equal(templateGroups().reduce((n, g) => n + g.items.length, 0), TEMPLATES.length);
});

test('templates lint without errors', () => {
    for (const t of TEMPLATES) {
        const errors = yara.lint(yara.parse(filled(t)), { requireMeta: [] }).filter(d => d.severity === 'error');
        assert.deepEqual(errors.map(e => e.message), [], t.id);
    }
});

test('templates compile with libyara', (ctx) => {
    const probe = spawnSync('python3', ['-c', 'import yara'], { encoding: 'utf8' });
    if (probe.status !== 0) { ctx.skip('yara-python is not installed'); return; }
    const script = 'import sys, json, yara\n'
        + 'out = {}\n'
        + 'for k, src in json.load(sys.stdin).items():\n'
        + '    try:\n        yara.compile(source=src, includes=False); out[k] = None\n'
        + '    except yara.Error as e:\n        out[k] = str(e)\n'
        + 'print(json.dumps(out))\n';
    const run = spawnSync('python3', ['-c', script], { input: JSON.stringify(Object.fromEntries(TEMPLATES.map(t => [t.id, filled(t)]))), encoding: 'utf8' });
    const results = JSON.parse(run.stdout);
    const failed = Object.entries(results).filter(([, err]) => err);
    assert.deepEqual(failed, []);
});
