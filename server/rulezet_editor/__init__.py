"""
Server side of rulezet-editor. No database.

Standalone:   rulezet-editor serve            (or create_app())
Inside Rulezet (submodule):
    from rulezet_editor import create_blueprint, FunctionBackend
    app.register_blueprint(create_blueprint(FunctionBackend(...)), url_prefix='/editor-api')
"""
from .backends import (
    Backend, BackendError, ChainBackend, FunctionBackend, LocalBackend, RulezetApiBackend,
    message_item, rule_item, validation_result,
)
from .validators import VALIDATORS, Validator

__version__ = '0.1.0'


def create_blueprint(*args, **kwargs):
    from .web import create_blueprint as _create
    return _create(*args, **kwargs)


def create_app(*args, **kwargs):
    from .web import create_app as _create
    return _create(*args, **kwargs)


__all__ = [
    'Backend', 'BackendError', 'ChainBackend', 'FunctionBackend', 'LocalBackend', 'RulezetApiBackend',
    'VALIDATORS', 'Validator', 'create_app', 'create_blueprint', 'message_item', 'rule_item',
    'validation_result',
]
