"""Rebuilds test/fixtures/yara-oracle.json: each case of cases.py with libyara's verdict.

    .venv/bin/python scripts/yara-oracle/build.py
"""
import json
import pathlib
import sys

import yara

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from cases import C  # noqa: E402

out = []
for text in C:
    try:
        yara.compile(source=text)
        error = None
    except yara.Error as e:
        error = str(e)
    out.append({'text': text, 'error': error})
dest = pathlib.Path(__file__).resolve().parents[2] / 'test' / 'fixtures' / 'yara-oracle.json'
dest.write_text(json.dumps(out, indent=1) + '\n')
print(f'{len(out)} cases, YARA {yara.YARA_VERSION} -> {dest}')
