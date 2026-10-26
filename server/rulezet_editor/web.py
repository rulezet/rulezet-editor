"""
HTTP layer: a Flask blueprint the browser editor talks to (EditorServerHost on the JS side).

    POST /validate          { format, content }   -> { format, valid, items: [...] }
    GET  /rules?format=&q=&limit=                  -> { results: [...] }
    GET  /rules/<name>?format=                     -> rule | 404
    GET  /fields?format=                           -> { fields: [...] }        (Fields panel; [] = none)
    GET  /fields/suggest?format=&field=&q=         -> { results: [{ value, label, detail? }] }
    GET  /fields/browse?format=&field=&path=&page= -> { folders, items, has_more }  (path: a/b, URL-encoded parts)
    GET  /                                         -> { name, formats, features }
    GET  /assets/<file>                            -> dist/ (editor JS and CSS)

    Tests on samples, only with `tests=` (a rulezet-tester TestService), mounted on /test:
    GET  /test/sets?format=                        -> { available, sets: [...] }
    POST /test/         { format, text, sets }     -> 202 run (samples pending)
    GET  /test/<run id>                            -> run (poll until status is done | failed)

Inside Rulezet the blueprint is mounted with a FunctionBackend; standalone, create_app()
mounts it with a LocalBackend + RulezetApiBackend chain.
"""
from pathlib import Path

from flask import Blueprint, Flask, jsonify, request, send_from_directory

from .backends import BackendError, ChainBackend, LocalBackend, RulezetApiBackend

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / 'dist'
MAX_CONTENT = 512 * 1024


def create_blueprint(backend, name='rulezet_editor', max_content=MAX_CONTENT, assets=True,
                     tests=None, test_owner=None):
    """tests: a rulezet_tester.TestService, or None (no Test button). test_owner(): who is asking
    (the host's user id), so a run is only visible to the one who started it."""
    bp = Blueprint(name, __name__)

    def error(message, status):
        return jsonify({'error': message}), status

    @bp.get('/')
    def info():
        return jsonify({
            'name': backend.name,
            'formats': backend.formats(),
            'features': {'validate': True, 'rules': True, 'test': bool(tests and tests.formats()),
                         'fields': backend.fields('') is not None},
        })

    if tests is not None:
        from rulezet_tester.web import create_blueprint as tester_blueprint
        bp.register_blueprint(tester_blueprint(tests, owner=test_owner, name=f'{name}_test'), url_prefix='/test')

    @bp.post('/validate')
    def validate():
        payload = request.get_json(silent=True) or {}
        fmt = str(payload.get('format') or '').strip()
        content = payload.get('content')
        if not fmt:
            return error('No format provided.', 400)
        if not isinstance(content, str):
            return error('No content provided.', 400)
        if len(content) > max_content:
            return error(f'Content too large (max {max_content // 1024} KB).', 413)
        if not content.strip():
            return jsonify({'format': fmt, 'valid': True, 'items': []})
        try:
            result = backend.validate(fmt, content)
        except BackendError as e:
            return error(str(e), 502)
        if result is None:
            return error(f'Unsupported format: {fmt}', 404)
        return jsonify({'format': fmt, **result})

    @bp.get('/rules')
    def search_rules():
        fmt = request.args.get('format', '').strip()
        query = request.args.get('q', '').strip()
        limit = max(1, min(request.args.get('limit', 10, type=int) or 10, 50))
        try:
            results = backend.search_rules(fmt, query, limit)
        except BackendError as e:
            return error(str(e), 502)
        return jsonify({'results': results or [], 'available': results is not None})

    @bp.get('/fields')
    def fields():
        try:
            items = backend.fields(request.args.get('format', '').strip())
        except BackendError as e:
            return error(str(e), 502)
        return jsonify({'fields': items or []})

    @bp.get('/fields/suggest')
    def suggest():
        field = request.args.get('field', '').strip()[:64]
        query = request.args.get('q', '').strip()[:200]
        limit = max(1, min(request.args.get('limit', 10, type=int) or 10, 50))
        try:
            results = backend.suggest(request.args.get('format', '').strip(), field, query, limit)
        except BackendError as e:
            return error(str(e), 502)
        return jsonify({'results': results or []})

    @bp.get('/fields/browse')
    def browse():
        from urllib.parse import unquote
        field = request.args.get('field', '').strip()[:64]
        raw = request.args.get('path', '')
        path = [unquote(p)[:200] for p in raw.split('/') if p][:5]
        page = max(1, min(request.args.get('page', 1, type=int) or 1, 1000))
        try:
            data = backend.browse(request.args.get('format', '').strip(), field, path, page)
        except BackendError as e:
            return error(str(e), 502)
        data = data or {}
        return jsonify({'folders': data.get('folders') or [], 'items': data.get('items') or [],
                        'has_more': bool(data.get('has_more'))})

    @bp.get('/rules/<path:rule_name>')
    def get_rule(rule_name):
        try:
            rule = backend.get_rule(request.args.get('format', '').strip(), rule_name)
        except BackendError as e:
            return error(str(e), 502)
        return jsonify(rule) if rule else error('Rule not found.', 404)

    if assets and DIST.is_dir():
        @bp.get('/assets/<path:filename>')
        def asset(filename):
            return send_from_directory(DIST, filename)

    return bp


def create_app(backend=None, rulezet_url='https://rulezet.org', api_key=None, prefix='/editor-api',
               samples=(), sandbox='bwrap'):
    """Standalone server: editor API + the playground. No database.
    Tests (when rulezet-tester is installed): samples = extra sample folders besides the safe sets
    shipped with rulezet-tester; sandbox = 'bwrap' (default), 'process' (development) or None."""
    if backend is None:
        remote = RulezetApiBackend(rulezet_url, api_key=api_key) if rulezet_url else None
        backend = ChainBackend(LocalBackend(), remote, name=remote.name if remote else 'local')
    tests = None
    if sandbox:
        try:
            from rulezet_tester import FolderSampleStore, Sandbox, TestService
            from rulezet_tester.web import SAMPLES
            tests = TestService(FolderSampleStore(SAMPLES, *samples), Sandbox(mode=sandbox))
        except ImportError:
            tests = None
    app = Flask(__name__, static_folder=None)
    app.register_blueprint(create_blueprint(backend, tests=tests), url_prefix=prefix)
    app.config['EDITOR_TESTS'] = tests
    app.config['EDITOR_BACKEND'] = backend

    @app.get('/')
    def playground():
        return send_from_directory(ROOT / 'playground', 'index.html')

    @app.get('/<any(playground, dist):folder>/<path:filename>')
    def static_files(folder, filename):
        response = send_from_directory(ROOT / folder, filename)
        response.headers['Cache-Control'] = 'no-store'
        return response

    return app
