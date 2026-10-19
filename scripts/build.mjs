/**
 * Builds dist/:
 *   rulezet-editor.js        ES module (import { RulezetEditor } from '.../rulezet-editor.js')
 *   rulezet-editor.iife.js   classic <script>: window.RulezetEditorLib
 *   rulezet-editor.css
 * node scripts/build.mjs [--watch]
 */
import * as esbuild from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';

const watch = process.argv.includes('--watch');
const common = { entryPoints: ['src/index.js'], bundle: true, sourcemap: watch, target: ['es2020'], logLevel: 'info', minify: !watch };

const copyCss = {
    name: 'copy-css',
    setup(build) {
        build.onEnd(async () => {
            await mkdir('dist', { recursive: true });
            await copyFile('src/styles/rulezet-editor.css', 'dist/rulezet-editor.css');
        });
    },
};

const configs = [
    { ...common, format: 'esm', outfile: 'dist/rulezet-editor.js', plugins: [copyCss] },
    { ...common, format: 'iife', globalName: 'RulezetEditorLib', outfile: 'dist/rulezet-editor.iife.js' },
];

if (watch) {
    for (const c of configs) await (await esbuild.context(c)).watch();
} else {
    await Promise.all(configs.map(c => esbuild.build(c)));
}
