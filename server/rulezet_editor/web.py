"""
HTTP layer: a Flask blueprint the browser editor talks to (EditorServerHost on the JS side).

    POST /validate          { format, content }   -> { format, valid, items: [...] }
    GET  /rules?format=&q=&limit=                  -> { results: [...] }
    GET  /rules/<name>?format=                     -> rule | 404
    GET  /                                         -> { name, formats, features }
    GET  /assets/<file>                            -> dist/ (editor JS and CSS)

Inside Rulezet the blueprint is mounted with a FunctionBackend; standalone, create_app()
mounts it with a LocalBackend + RulezetApiBackend chain.
"""
from pathlib import Path

from flask import Blueprint, Flask, jsonify, request, send_from_directory

from .backends import BackendError, ChainBackend, LocalBackend, RulezetApiBackend

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / 'dist'
MAX_CONTENT = 512 * 1024


def create_blueprint(backend, name='rulezet_editor', max_content=MAX_CONTENT, assets=True):
    bp = Blueprint(name, __name__)

    def error(message, status):
        return jsonify({'error': message}), status

    @bp.get('/')
    def info():
        return jsonify({
            'name': backend.name,
            'formats': backend.formats(),
            'features': {'validate': True, 'rules': True},
        })

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


def create_app(backend=None, rulezet_url='https://rulezet.org', api_key=None, prefix='/editor-api'):
    """Standalone server: editor API + the playground. No database."""
    if backend is None:
        remote = RulezetApiBackend(rulezet_url, api_key=api_key) if rulezet_url else None
        backend = ChainBackend(LocalBackend(), remote, name=remote.name if remote else 'local')
    app = Flask(__name__, static_folder=None)
    app.register_blueprint(create_blueprint(backend), url_prefix=prefix)
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
