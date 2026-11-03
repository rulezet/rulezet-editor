"""
Local validators, one per format. Each one is optional: its compiler is imported lazily,
so a missing library only disables that format (the next backend in the chain answers).

A validator returns { errors: [...], warnings: [...] }; messages may start with
'line N:' so the editor can place them.
"""
import importlib
import re


class Validator:
    module = None

    def available(self):
        try:
            importlib.import_module(self.module)
            return True
        except ImportError:
            return False

    def validate(self, content):
        raise NotImplementedError


class YaraValidator(Validator):
    module = 'yara'

    def validate(self, content):
        import yara
        try:
            rules = yara.compile(source=content, includes=False)   # never read a file of this machine
        except yara.SyntaxError as e:
            return {'errors': [str(e)], 'warnings': []}
        except yara.Error as e:
            return {'errors': [str(e)], 'warnings': []}
        return {'errors': [], 'warnings': list(getattr(rules, 'warnings', None) or [])}


_SEPARATOR = re.compile(r'^(?:---|\.\.\.)[ \t]*(?:#.*)?$', re.M)


def split_yaml_documents(content):
    """[(first_line, text)] for each non-empty YAML document of `content` (split on --- lines):
    a Sigma file may hold several rules, a Sigma validator reads one. first_line is 1-based,
    the line of the document's first non-blank line in `content`."""
    out = []
    start = 0
    cuts = [m for m in _SEPARATOR.finditer(content)]
    bounds = []
    for m in cuts:
        bounds.append((start, m.start()))
        start = m.end() + 1
    bounds.append((start, len(content)))
    for a, b in bounds:
        part = content[a:b]
        if not part.strip() or all(not l.strip() or l.lstrip().startswith('#') for l in part.splitlines()):
            continue
        lead = len(part) - len(part.lstrip('\n'))
        out.append((content.count('\n', 0, a + lead) + 1, part.strip('\n') + '\n'))
    return out


class SigmaValidator(Validator):
    """pySigma (optional): each document parsed, then pySigma's own checks — HIGH issues are
    errors (Rulezet refuses them), the others warnings. Messages point at the rule's first line."""
    module = 'sigma'

    def validate(self, content):
        from sigma.collection import SigmaCollection
        from sigma.validation import SigmaValidator as PySigmaValidator
        from sigma.validators.base import SigmaValidationIssueSeverity
        from sigma.validators.core import validators
        errors, warnings = [], []
        for line, text in split_yaml_documents(content):
            try:
                collection = SigmaCollection.from_yaml(text)
                issues = PySigmaValidator(validators=validators.values()).validate_rules(collection)
            except Exception as e:                      # parsing: the rule is refused
                errors.append(f'line {line}: {e}')
                continue
            for issue in issues:
                text_issue = f"line {line}: {issue.description}" + (f" ({_issue_detail(issue)})" if _issue_detail(issue) else '')
                (errors if issue.severity == SigmaValidationIssueSeverity.HIGH else warnings).append(text_issue)
        return {'errors': errors, 'warnings': warnings}


def _issue_detail(issue):
    for attr in ('detection', 'identifier', 'tag', 'fieldname', 'event_id'):
        value = getattr(issue, attr, None)
        if value is not None:
            return f'{attr}: {value}'
    return ''


VALIDATORS = {
    'yara': YaraValidator(),
    'sigma': SigmaValidator(),
}
