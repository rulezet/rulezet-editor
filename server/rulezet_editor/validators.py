"""
Local validators, one per format. Each one is optional: its compiler is imported lazily,
so a missing library only disables that format (the next backend in the chain answers).

A validator returns { errors: [...], warnings: [...] }; messages may start with
'line N:' so the editor can place them.
"""
import importlib


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


VALIDATORS = {
    'yara': YaraValidator(),
}
