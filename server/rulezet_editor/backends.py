"""
Backends answer the editor's server-side questions: validate a rule, find rules by name.

Every method returns None when the backend cannot answer (unknown format, feature not
available), so backends can be chained. No database here: the host application brings
its own data through FunctionBackend.

    LocalBackend()                       real compilers installed on this machine (yara-python)
    RulezetApiBackend('https://...')     a Rulezet instance through its public API
    FunctionBackend(validate=..., ...)   functions of the host application (Rulezet itself)
    ChainBackend(a, b)                   first backend that answers wins
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .validators import VALIDATORS

_LINE = re.compile(r'line\s+(\d+)(?:\s*[,:]\s*col(?:umn)?\s*(\d+))?\s*[:,-]?\s*(.*)$', re.I)


class BackendError(Exception):
    """The backend exists but failed (network, remote error): shown to the user."""


def message_item(message, severity='error'):
    """'line 3: syntax error' -> { severity, message, line, column }."""
    if isinstance(message, dict):
        item = {'severity': message.get('severity', severity), 'message': str(message.get('message', ''))}
        for key in ('line', 'column'):
            if message.get(key) is not None:
                item[key] = int(message[key])
        return item
    text = str(message)
    m = _LINE.search(text)
    if not m:
        return {'severity': severity, 'message': text}
    item = {'severity': severity, 'message': m.group(3) or text, 'line': int(m.group(1))}
    if m.group(2):
        item['column'] = int(m.group(2))
    return item


def validation_result(value):
    """Accepts what a validator may return: { errors, warnings }, an object with
    ok/errors/warnings (Rulezet's validate_rule_syntax), or a list of items."""
    if value is None:
        return None
    if isinstance(value, list):
        items = [message_item(v) for v in value]
    else:
        get = value.get if isinstance(value, dict) else (lambda k, d=None: getattr(value, k, d))
        items = [message_item(e, 'error') for e in (get('errors') or [])]
        items += [message_item(w, 'warning') for w in (get('warnings') or [])]
    return {'valid': not any(i['severity'] == 'error' for i in items), 'items': items}


def rule_item(value):
    """Rulezet rule (title, ...) or plain dict -> { name, uuid, description, author, content, url }."""
    get = value.get if isinstance(value, dict) else (lambda k, d=None: getattr(value, k, d))
    return {
        'name': get('name') or get('title') or '',
        'uuid': str(get('uuid')) if get('uuid') else None,
        'description': get('description') or '',
        'author': get('author') or '',
        'content': get('content') or get('to_string') or '',
        'url': get('url'),
    }


class Backend:
    name = 'backend'

    def formats(self):
        """Formats this backend can validate."""
        return []

    def validate(self, fmt, content):
        return None

    def search_rules(self, fmt, query, limit=10):
        return None

    def get_rule(self, fmt, name):
        return None


class LocalBackend(Backend):
    """Validation with the compilers available here. No rule lookup: there is no database."""
    name = 'local'

    def formats(self):
        return [fmt for fmt, v in VALIDATORS.items() if v.available()]

    def validate(self, fmt, content):
        validator = VALIDATORS.get(fmt)
        if not validator or not validator.available():
            return None
        return validation_result(validator.validate(content))


class RulezetApiBackend(Backend):
    """A Rulezet instance (rulezet.org or self-hosted) through its public API."""

    def __init__(self, base_url='https://rulezet.org', api_key=None, timeout=8, name='Rulezet'):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.name = name

    def _request(self, path, body=None):
        headers = {'Accept': 'application/json'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if self.api_key:
            headers['X-API-KEY'] = self.api_key
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=headers,
            method='POST' if body is not None else 'GET',
        )
        try:
            with self._open(req) as res:
                return res.status, json.loads(res.read() or b'{}')
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b'{}')
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise BackendError(f'{self.name} not reachable at {self.base_url}: {e}') from e

    def _open(self, req):
        return urllib.request.urlopen(req, timeout=self.timeout)

    def formats(self):
        try:
            status, data = self._request('/api/config/formats')
        except BackendError:
            return []
        if status != 200:
            return []
        items = data if isinstance(data, list) else data.get('formats', [])
        return [f.get('name', f) if isinstance(f, dict) else f for f in items]

    def validate(self, fmt, content):
        status, data = self._request('/api/rule/public/validate', {'format': fmt, 'content': content})
        if status == 404:
            return None
        if status not in (200, 400) or (data.get('error') and 'errors' not in data):
            raise BackendError(data.get('error') or f'{self.name}: HTTP {status}')
        return validation_result(data)

    def search_rules(self, fmt, query, limit=10):
        params = urllib.parse.urlencode({'search': query, 'rule_type': fmt, 'per_page': limit})
        status, data = self._request(f'/api/rule/public/searchPage?{params}')
        if status != 200:
            raise BackendError(data.get('error') or f'{self.name}: HTTP {status}')
        rules = [rule_item(r) for r in data.get('results') or data.get('rules') or []]
        for r in rules:
            if r['uuid'] and not r['url']:
                r['url'] = f'{self.base_url}/rule/detail_rule/{r["uuid"]}'
        return rules

    def get_rule(self, fmt, name):
        rules = self.search_rules(fmt, name, limit=20) or []
        return next((r for r in rules if r['name'] == name), None)


class FunctionBackend(Backend):
    """Functions of the host application. Inside Rulezet:

        FunctionBackend(
            name='Rulezet',
            validate=RuleModel.validate_rule_syntax,           # (fmt, content)
            search_rules=lambda fmt, q, limit: ...,            # rules from the database
            get_rule=lambda fmt, name: ...,
        )
    """

    def __init__(self, validate=None, search_rules=None, get_rule=None, formats=None, name='host'):
        self.name = name
        self._validate = validate
        self._search = search_rules
        self._get = get_rule
        self._formats = formats

    def formats(self):
        return list(self._formats() if callable(self._formats) else self._formats or [])

    def validate(self, fmt, content):
        return validation_result(self._validate(fmt, content)) if self._validate else None

    def search_rules(self, fmt, query, limit=10):
        if not self._search:
            return None
        return [rule_item(r) for r in self._search(fmt, query, limit) or []]

    def get_rule(self, fmt, name):
        if self._get:
            rule = self._get(fmt, name)
            return rule_item(rule) if rule else None
        rules = self.search_rules(fmt, name, limit=20)
        return None if rules is None else next((r for r in rules if r['name'] == name), None)


class ChainBackend(Backend):
    """Asks each backend in turn. For get_rule, a backend that searched and found nothing
    still lets the next one try."""

    def __init__(self, *backends, name=None):
        self.backends = [b for b in backends if b]
        self.name = name or (self.backends[0].name if self.backends else 'backend')

    def formats(self):
        seen = []
        for b in self.backends:
            seen += [f for f in b.formats() if f not in seen]
        return seen

    def _first(self, method, *args):
        for b in self.backends:
            value = getattr(b, method)(*args)
            if value is not None:
                return value
        return None

    def validate(self, fmt, content):
        return self._first('validate', fmt, content)

    def search_rules(self, fmt, query, limit=10):
        return self._first('search_rules', fmt, query, limit)

    def get_rule(self, fmt, name):
        for b in self.backends:
            rule = b.get_rule(fmt, name)
            if rule:
                return rule
        return None
