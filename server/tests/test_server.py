import io
import json
import urllib.error

import pytest

from rulezet_editor import (
    BackendError, ChainBackend, FunctionBackend, LocalBackend, RulezetApiBackend,
    create_app, create_blueprint, message_item, validation_result,
)
from flask import Flask

yara = pytest.importorskip('yara')

VALID = 'rule a { strings: $x = "abc" condition: $x }'
BROKEN = 'rule a {\n  condition:\n    $missing\n}'


class FakeResponse(io.BytesIO):
    def __init__(self, status, data):
        super().__init__(json.dumps(data).encode())
        self.status = status


class FakeRulezet(RulezetApiBackend):
    """RulezetApiBackend without network: records requests, replies from a table."""

    def __init__(self, replies):
        super().__init__('https://rulezet.test')
        self.replies = replies
        self.requests = []

    def _open(self, req):
        self.requests.append(req)
        path = req.full_url[len(self.base_url):].split('?')[0]
        reply = self.replies.get(path)
        if isinstance(reply, Exception):
            raise reply
        status, data = reply or (404, {'error': 'not found'})
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, 'err', {}, io.BytesIO(json.dumps(data).encode()))
        return FakeResponse(status, data)


def client(backend):
    app = Flask(__name__)
    app.register_blueprint(create_blueprint(backend), url_prefix='/editor-api')
    return app.test_client()


def test_message_item_places_line_and_column():
    assert message_item('line 3: undefined string "$missing"') == {
        'severity': 'error', 'message': 'undefined string "$missing"', 'line': 3}
    assert message_item('line 2, column 7: oops', 'warning')['column'] == 7
    assert message_item('no position') == {'severity': 'error', 'message': 'no position'}


def test_validation_result_accepts_object_dict_and_list():
    class Result:
        ok = False
        errors = ['line 1: bad']
        warnings = ['slow']
    assert validation_result(Result())['valid'] is False
    assert validation_result({'errors': [], 'warnings': ['w']}) == {
        'valid': True, 'items': [{'severity': 'warning', 'message': 'w'}]}
    assert validation_result([{'message': 'x', 'severity': 'error', 'line': 2}])['items'][0]['line'] == 2
    assert validation_result(None) is None


def test_local_backend_compiles_yara():
    backend = LocalBackend()
    assert 'yara' in backend.formats()
    assert backend.validate('yara', VALID) == {'valid': True, 'items': []}
    result = backend.validate('yara', BROKEN)
    assert result['valid'] is False and result['items'][0]['line'] in (3, 4)
    assert '$missing' in result['items'][0]['message']
    assert backend.validate('sigma', 'title: x') is None


def test_chain_falls_back_to_rulezet_for_formats_not_compiled_here():
    remote = FakeRulezet({'/api/rule/public/validate': (200, {'valid': False, 'errors': ['line 1: bad sigma'], 'warnings': []})})
    chain = ChainBackend(LocalBackend(), remote)
    assert chain.validate('yara', VALID)['valid'] is True
    assert remote.requests == []
    assert chain.validate('sigma', 'x')['items'][0]['message'] == 'bad sigma'
    assert len(remote.requests) == 1


def test_rulezet_api_backend_search_and_get_rule():
    remote = FakeRulezet({'/api/rule/public/searchPage': (200, {'results': [
        {'title': 'Other', 'uuid': 'u1'}, {'title': 'Target', 'uuid': 'u2', 'author': 'me'}]})})
    rules = remote.search_rules('yara', 'Target')
    assert rules[1]['url'] == 'https://rulezet.test/rule/detail_rule/u2'
    assert remote.get_rule('yara', 'Target')['author'] == 'me'
    assert remote.get_rule('yara', 'Nope') is None


def test_rulezet_api_backend_unreachable_raises_backend_error():
    remote = FakeRulezet({'/api/rule/public/validate': urllib.error.URLError('refused')})
    with pytest.raises(BackendError):
        remote.validate('yara', VALID)


def test_function_backend_uses_host_functions_without_network():
    calls = []

    def validate(fmt, content):
        calls.append(fmt)
        return {'errors': ['line 2: from the host'], 'warnings': []}

    db = [{'title': 'Shared_Rule', 'uuid': 'abc', 'description': 'in the database'}]
    backend = FunctionBackend(validate=validate, search_rules=lambda fmt, q, limit: [r for r in db if q in r['title']],
                              name='Rulezet')
    assert backend.validate('yara', VALID)['items'][0]['line'] == 2
    assert calls == ['yara']
    assert backend.get_rule('yara', 'Shared_Rule')['description'] == 'in the database'
    assert backend.get_rule('yara', 'Missing') is None
    assert FunctionBackend().validate('yara', VALID) is None


def test_blueprint_validate():
    c = client(LocalBackend())
    res = c.post('/editor-api/validate', json={'format': 'yara', 'content': BROKEN})
    assert res.status_code == 200 and res.json['valid'] is False
    assert c.post('/editor-api/validate', json={'format': 'yara', 'content': VALID}).json['valid'] is True
    assert c.post('/editor-api/validate', json={'content': VALID}).status_code == 400
    assert c.post('/editor-api/validate', json={'format': 'sigma', 'content': 'x'}).status_code == 404
    assert c.post('/editor-api/validate', data='garbage', content_type='application/json').status_code == 400
    big = 'a' * (512 * 1024 + 1)
    assert c.post('/editor-api/validate', json={'format': 'yara', 'content': big}).status_code == 413


def test_blueprint_rules():
    backend = FunctionBackend(search_rules=lambda fmt, q, limit: [{'title': 'R1', 'uuid': '1'}], name='Rulezet')
    c = client(backend)
    assert c.get('/editor-api/rules?format=yara&q=R').json['results'][0]['name'] == 'R1'
    assert c.get('/editor-api/rules/R1?format=yara').json['uuid'] == '1'
    assert c.get('/editor-api/rules/R2?format=yara').status_code == 404
    assert client(LocalBackend()).get('/editor-api/rules?q=x').json == {'results': [], 'available': False}


def test_blueprint_reports_backend_failure_as_502():
    remote = FakeRulezet({'/api/rule/public/validate': urllib.error.URLError('refused')})
    res = client(remote).post('/editor-api/validate', json={'format': 'sigma', 'content': 'x'})
    assert res.status_code == 502 and 'not reachable' in res.json['error']


def test_standalone_app_serves_playground_and_api():
    c = create_app(rulezet_url=None).test_client()
    assert c.get('/').status_code == 200
    assert c.get('/editor-api/').json['name'] == 'local'
    assert c.post('/editor-api/validate', json={'format': 'yara', 'content': VALID}).json['valid'] is True
