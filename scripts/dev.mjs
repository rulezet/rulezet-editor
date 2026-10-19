/**
 * Playground server: rebuilds dist/ on change and serves the repository.
 * Requests to /api/ and /rule/ are forwarded to a Rulezet instance, so the
 * playground can validate rules and look up existing ones without CORS.
 *
 *   npm run dev                                   # Rulezet at http://127.0.0.1:7009
 *   RULEZET_URL=https://rulezet.org npm run dev
 *   PORT=5173 npm run dev
 */
import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { spawn } from 'node:child_process';

const PORT = Number(process.env.PORT || 5173);
const RULEZET_URL = (process.env.RULEZET_URL || 'http://127.0.0.1:7009').replace(/\/+$/, '');
const ROOT = process.cwd();
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.map': 'application/json', '.json': 'application/json', '.svg': 'image/svg+xml', '.yar': 'text/plain' };

spawn(process.execPath, ['scripts/build.mjs', '--watch'], { stdio: 'inherit' });

async function proxy(req, res) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    try {
        const upstream = await fetch(RULEZET_URL + req.url, {
            method: req.method,
            headers: { 'content-type': req.headers['content-type'] || 'application/json', accept: 'application/json' },
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks),
        });
        res.writeHead(upstream.status, { 'content-type': upstream.headers.get('content-type') || 'application/json' });
        res.end(Buffer.from(await upstream.arrayBuffer()));
    } catch (e) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: `Rulezet not reachable at ${RULEZET_URL}: ${e.message}` }));
    }
}

http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/rule/')) return proxy(req, res);
    let path = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
    if (path === '/' || path === '\\') path = '/playground/index.html';
    const file = join(ROOT, path);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    try {
        const s = await stat(file);
        const target = s.isDirectory() ? join(file, 'index.html') : file;
        res.writeHead(200, { 'content-type': TYPES[extname(target)] || 'application/octet-stream', 'cache-control': 'no-store' });
        res.end(await readFile(target));
    } catch {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('Not found');
    }
}).listen(PORT, '127.0.0.1', () => {
    console.log(`\n  Playground:  http://127.0.0.1:${PORT}/`);
    console.log(`  Rulezet API: ${RULEZET_URL} (proxied on /api and /rule)\n`);
});
