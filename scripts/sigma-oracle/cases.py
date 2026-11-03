"""Cases of the Sigma oracle: rules (valid and broken) whose verdict the lint must reproduce.
build.py adds the pack's own texts (sample, templates, tutorial, skeleton: scripts/sigma-oracle/export.mjs)."""
UUID = '929a690e-bef0-4204-a928-ef5e620d6fcc'


def R(detection='    selection:\n        Image|endswith: \'\\evil.exe\'\n    condition: selection\n',
      head=None, logsource='logsource:\n    category: process_creation\n    product: windows\n', tail='level: medium\n'):
    head = head if head is not None else f'title: Test rule\nid: {UUID}\nstatus: test\ndate: 2026-01-02\n'
    return head + logsource + ('detection:\n' + detection if detection is not None else '') + tail


C = [R()]
H = f'title: Test rule\nid: {UUID}\n'
# header
for h in ['', f'id: {UUID}\n', 'title: \nid: x\n', f'title: T\nid: not-a-uuid\n', f'title: T\nstatus: beta\n', f'title: T\nstatus: stable\n',
          'title: T\ndate: 2024-13-01\n', 'title: T\ndate: 2024/01/02\n', 'title: T\ndate: 24-01-02\n', 'title: T\nmodified: 2024-01-02\n',
          'title: T\ntags: attack.execution\n', 'title: T\ntags:\n    - attack.execution\n    - attack.execution\n', 'title: T\ntags:\n    - Attack.Execution\n',
          'title: T\ntags:\n    - attack.privilege_escalation\n', 'title: T\ntags:\n    - attack.t1059.001\n    - cve.2024-3094\n    - tlp.clear\n    - detection.threat-hunting\n',
          'title: T\ntags:\n    - attack.foo\n', 'title: T\ntags:\n    - foo bar\n', 'title: T\nreferences:\n    - https://a\n    - https://a\n', 'title: T\nreferences: https://a\n',
          'title: T\nfalsepositives:\n    - x\n', 'title: T\nfalsepositives:\n    - Unknown\n    - Unknown\n', 'title: T\nfields:\n    - CommandLine\n',
          f'title: T\nrelated:\n    - id: {UUID}\n      type: derived\n', f'title: T\nrelated:\n    - id: {UUID}\n      type: copy\n', 'title: T\nrelated:\n    - id: x\n      type: derived\n',
          'title: T\ncustom_field: x\n', 'title: T\nauthr: me\n', 'title: ' + 'x' * 300 + '\n', 'title: T\nlevel: severe\n', 'title: T\ndescription: |\n    multi\n    line\n',
          'title: "Quoted: title"\n', "title: 'it''s'\n", 'title: T\nscope:\n    - x\n']:
    C.append(R(head=h, tail=''))
# logsource
for ls in ['', 'logsource:\n    vendor: acme\n', 'logsource:\n    product: windows\n', 'logsource: windows\n', 'logsource:\n    product: windows\n    service: sysmon\n',
           'logsource:\n    product: windows\n    service: security\n', 'logsource:\n    category: proxy\n', 'logsource:\n    definition: x\n    product: linux\n']:
    C.append(R(logsource=ls))
C.append(R(logsource='logsource:\n    product: windows\n    service: sysmon\n', detection='    selection:\n        EventID: 1\n        Image: x\n    condition: selection\n'))
C.append(R(logsource='logsource:\n    product: windows\n    service: sysmon\n', detection="    selection:\n        EventID: '1'\n    condition: selection\n"))
C.append(R(logsource='logsource:\n    product: windows\n    service: security\n', detection='    selection:\n        EventID: 4688\n    condition: selection\n'))
C.append(R(logsource='logsource:\n    product: windows\n    service: security\n', detection='    selection:\n        EventID:\n            - 4624\n            - 4625\n    condition: selection\n'))
# detection
D = [
    None,
    '    selection:\n        Image: x\n',
    '    condition: selection\n',
    '    selection:\n        Image: x\n    condition:\n',
    '    selection:\n        Image: x\n    condition: selection and\n',
    '    selection:\n        Image: x\n    condition: (selection\n',
    '    selection:\n        Image: x\n    condition: selection)\n',
    '    selection:\n        Image: x\n    condition: selectoin\n',
    '    selection:\n        Image: x\n    filter:\n        User: y\n    condition: selection\n',
    '    selection:\n        Image: x\n    filter:\n        User: y\n    condition: selection and not filter\n',
    '    selection_a:\n        Image: x\n    selection_b:\n        User: y\n    condition: 1 of selection_*\n',
    '    selection_a:\n        Image: x\n    selection_b:\n        User: y\n    condition: all of selection_*\n',
    '    selection_a:\n        Image: x\n    selection_b:\n        User: y\n    condition: 2 of selection_*\n',
    '    selection_a:\n        Image: x\n    selection_b:\n        User: y\n    condition: any of selection_*\n',
    '    selection_a:\n        Image: x\n    condition: 1 of nothing_*\n',
    '    selection_a:\n        Image: x\n    condition: selection_*\n',
    '    selection:\n        Image: x\n    condition: 1 of them\n',
    '    selection:\n        Image: x\n    filter:\n        User: y\n    condition: all of them\n',
    '    selection:\n        Image: x\n    condition: them\n',
    '    selection:\n        Image: x\n    condition: selection | count() > 5\n',
    '    selection:\n        Image: x\n    condition:\n        - selection\n',
    '    selection:\n        Image: x\n    timeframe: 5m\n    condition: selection\n',
    '    selection:\n        Image|containz: x\n    condition: selection\n',
    '    selection:\n        Image|contains|all:\n            - a\n            - b\n    condition: selection\n',
    '    selection:\n        Image|endswith|all:\n            - a\n            - b\n    condition: selection\n',
    '    selection:\n        Image|all:\n            - a\n            - b\n    condition: selection\n',
    "    selection:\n        '|all':\n            - a\n            - b\n    condition: selection\n",
    '    selection:\n        Image|base64offset: x\n    condition: selection\n',
    '    selection:\n        Image|base64offset|contains: x\n    condition: selection\n',
    '    selection:\n        CommandLine|windash|contains|all:\n            - -a\n            - -b\n    condition: selection\n',
    '    selection:\n        CommandLine|windash|contains: -a\n    condition: selection\n',
    '    selection:\n        Image|re: \'.*\\.exe\'\n    condition: selection\n',
    '    selection:\n        Image|re|i: \'.*\\.exe\'\n    condition: selection\n',
    '    selection:\n        Image|i|re: \'.*\\.exe\'\n    condition: selection\n',
    '    selection:\n        Image|exists: true\n    condition: selection\n',
    '    selection:\n        Image|exists: maybe\n    condition: selection\n',
    '    selection:\n        Size|gt: 10\n    condition: selection\n',
    '    selection:\n        Size|gt: big\n    condition: selection\n',
    '    selection:\n        DestinationIp|cidr: 10.0.0.0/8\n    condition: selection\n',
    '    selection:\n        DestinationIp|cidr: tenzero\n    condition: selection\n',
    '    selection:\n        Image|contains|contains: x\n    condition: selection\n',
    '    selection:\n        Image|cased: X\n    condition: selection\n',
    '    selection:\n        Image|fieldref: ParentImage\n    condition: selection\n',
    '    selection:\n        Image: "a\\x01b"\n    condition: selection\n',
    '    selection:\n        - Image: x\n        - User: y\n    condition: selection\n',
    '    keywords:\n        - a\n        - b\n    condition: keywords\n',
    '    keywords: foo\n    condition: keywords\n',
    '    selection:\n    condition: selection\n',
    '    selection:\n        Image: \'*\\evil.exe\'\n    condition: selection\n',
    '    selection:\n        Image: \'*evil*\'\n    condition: selection\n',
    '    selection:\n        Image: []\n    condition: selection\n',
    '    selection:\n        Image: [a, b]\n    condition: selection\n',
    '    selection:\n        Image: null\n    condition: selection\n',
    '    selection:\n        EventID: \'4624\'\n    condition: selection\n',
    '    selection:\n        Image: x\n    condition: not selection\n',
    '    selection:\n        Image: x\n    filter_1:\n        User: a\n    filter_2:\n        User: b\n    condition: selection and not 1 of filter_*\n',
    '    selection:\n        Image: x\n    condition: selection and (selection or selection)\n',
    '\tselection:\n        Image: x\n    condition: selection\n',
]
for d in D:
    C.append(R(detection=d))
# documents
C.append(R() + '---\n' + R().replace('Test rule', 'Other rule').replace(UUID, '0f0b2b8a-0f0e-4c63-9a5c-3d6b1c2e4f10'))
C.append('title: Corr\ncorrelation:\n    type: event_count\n    rules:\n        - a\n    timespan: 1h\n    group-by:\n        - User\n    condition:\n        gte: 5\n')
for corr in ['type: evnt_count\n    rules:\n        - a\n    timespan: 1h\n    condition:\n        gte: 5', 'type: event_count\n    rules:\n        - a\n    timespan: 1h',
             'type: event_count\n    rules: []\n    timespan: 1h\n    condition:\n        gte: 5', 'type: event_count\n    rules:\n        - a\n    timespan: 1hour\n    condition:\n        gte: 5',
             'type: value_count\n    rules:\n        - a\n    timespan: 1h\n    condition:\n        gte: 5', 'type: temporal\n    rules:\n        - a\n        - b\n    timespan: 1h',
             'type: event_count\n    rules:\n        - a\n    timespan: 1h\n    condition:\n        more: 5']:
    C.append('title: Corr\ncorrelation:\n    ' + corr + '\n')
C.append('just text')
C.append('- a\n- b\n')
C.append('title: T\n  bad: indentation\n' + R(head=''))
