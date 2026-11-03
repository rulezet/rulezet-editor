/**
 * Sigma vocabulary: keys, value modifiers, log sources, common field names, tag namespaces.
 * Written after the Sigma specification (SigmaHQ/sigma-specification, v2) and pySigma 1.x
 * (the library Rulezet validates with). Pure data.
 */

/** Top-level keys of a detection rule, in the order the specification recommends. */
export const TOP_KEYS = [
    { key: 'title', doc: 'Short capitalised title of what the rule detects (max 256 characters). Required.', required: true },
    { key: 'id', doc: 'Globally unique identifier of the rule: a UUID (version 4 recommended). Keep it when you edit the rule; give a derived rule a new one and link it with `related`.' },
    { key: 'related', doc: 'Rules this one is linked to: a list of `id` + `type` (derived, obsolete, merged, renamed, similar).' },
    { key: 'name', doc: 'A unique human-readable name, used by correlation rules to refer to this rule.' },
    { key: 'taxonomy', doc: 'Field naming taxonomy of the rule (default `sigma`).' },
    { key: 'status', doc: 'Maturity: `stable`, `test`, `experimental`, `deprecated` or `unsupported`.' },
    { key: 'description', doc: 'What the rule detects and why it matters (max 65535 characters).' },
    { key: 'license', doc: 'Licence of the rule (an SPDX identifier, e.g. DRL-1.1, MIT).' },
    { key: 'references', doc: 'Sources: reports, blog posts, documentation (a list of URLs).' },
    { key: 'author', doc: 'Who wrote the rule (names or handles, comma separated).' },
    { key: 'date', doc: 'Creation date, `YYYY-MM-DD`.' },
    { key: 'modified', doc: 'Date of the last change, `YYYY-MM-DD`.' },
    { key: 'tags', doc: 'Namespaced tags: `attack.t1059.001`, `attack.execution`, `cve.2024-3094`, `tlp.clear`, `detection.threat-hunting`…' },
    { key: 'logsource', doc: 'Which logs the rule applies to: `category`, `product`, `service` (and `definition`). Required.', required: true },
    { key: 'detection', doc: 'Search identifiers (selections, filters) and the `condition` that combines them. Required.', required: true },
    { key: 'fields', doc: 'Log fields worth showing to an analyst when the rule fires.' },
    { key: 'falsepositives', doc: 'Known reasons the rule may fire on benign activity (a list).' },
    { key: 'level', doc: 'Criticality: `informational`, `low`, `medium`, `high` or `critical`.' },
    { key: 'scope', doc: 'Where the rule is meant to run (e.g. `server`, `workstation`).' },
];

export const STATUS = {
    stable: 'Tested for months in several environments; ready to alert on.',
    test: 'Reviewed and tested; may still need tuning.',
    experimental: 'New rule: may produce false positives or not work everywhere.',
    deprecated: 'Replaced by another rule (see `related`); kept for reference.',
    unsupported: 'Cannot be used in its current state (special syntax, missing fields).',
};

export const LEVEL = {
    informational: 'Not an alert: enrichment or compliance.',
    low: 'Notable event, rarely an incident on its own.',
    medium: 'Relevant event that should be reviewed manually.',
    high: 'Relevant event that should trigger an internal alert and a quick review.',
    critical: 'Highly relevant event almost certainly malicious: act immediately.',
};

export const RELATED_TYPES = {
    derived: 'This rule is derived from the referenced rule (may be active at the same time).',
    obsolete: 'This rule replaces the referenced rule (the old one is no longer maintained).',
    merged: 'This rule merges the referenced rules.',
    renamed: 'The referenced rule had another id or name.',
    similar: 'A similar rule (e.g. same detection on another log source).',
};

export const LOGSOURCE_KEYS = {
    category: 'Kind of events, whatever the product: `process_creation`, `network_connection`, `dns_query`…',
    product: 'The product or operating system: `windows`, `linux`, `macos`, `aws`, `azure`…',
    service: 'A log of that product: `security`, `sysmon`, `powershell`, `auditd`, `cloudtrail`…',
    definition: 'How the logs must be collected for the rule to work (audit policy, Sysmon configuration…).',
};

export const PRODUCTS = ['windows', 'linux', 'macos', 'aws', 'azure', 'gcp', 'm365', 'okta', 'onelogin', 'github', 'google_workspace', 'cisco', 'fortios', 'paloalto', 'zeek', 'apache', 'nginx', 'kubernetes', 'jvm', 'nodejs', 'python', 'ruby_on_rails', 'spring', 'sql', 'opencanary', 'bitbucket', 'huawei', 'juniper', 'qualys', 'modsecurity', 'velocity', 'django', 'rpc_firewall', 'antivirus'];

export const CATEGORIES = [
    'process_creation', 'process_access', 'process_termination', 'process_tampering', 'image_load', 'driver_load',
    'file_event', 'file_access', 'file_change', 'file_delete', 'file_rename', 'file_executable_detected', 'file_block',
    'registry_event', 'registry_add', 'registry_delete', 'registry_set', 'registry_rename',
    'network_connection', 'dns_query', 'dns', 'firewall', 'proxy', 'webserver',
    'create_remote_thread', 'create_stream_hash', 'raw_access_thread', 'pipe_created', 'wmi_event', 'clipboard_capture',
    'ps_module', 'ps_script', 'ps_classic_start', 'ps_classic_provider_start', 'sysmon_status', 'sysmon_error',
    'antivirus', 'application', 'database',
];

export const SERVICES = [
    'security', 'system', 'application', 'sysmon', 'powershell', 'powershell-classic', 'taskscheduler', 'wmi',
    'windefend', 'firewall-as', 'bits-client', 'dns-server', 'dns-client', 'driver-framework', 'ntlm',
    'codeintegrity-operational', 'appxdeployment-server', 'msexchange-management', 'terminalservices-localsessionmanager',
    'auditd', 'syslog', 'auth', 'sshd', 'sudo', 'cron', 'clamav', 'guacamole', 'vsftpd',
    'cloudtrail', 'activitylogs', 'auditlogs', 'signinlogs', 'riskdetection', 'pim', 'gcp.audit', 'audit', 'threat_management',
    'okta', 'kubernetes', 'apache', 'nginx',
];

/** Common field names per category (completion; Sysmon / Windows names, as the SigmaHQ rules). */
export const FIELDS = {
    process_creation: ['Image', 'CommandLine', 'OriginalFileName', 'ParentImage', 'ParentCommandLine', 'CurrentDirectory', 'User', 'IntegrityLevel', 'Hashes', 'Product', 'Company', 'Description', 'FileVersion', 'LogonId', 'ParentUser', 'ProcessId', 'ParentProcessId'],
    process_access: ['SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace', 'SourceUser', 'TargetUser'],
    image_load: ['Image', 'ImageLoaded', 'OriginalFileName', 'Signed', 'Signature', 'SignatureStatus', 'Hashes', 'Product', 'Company', 'Description'],
    driver_load: ['ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus'],
    file_event: ['Image', 'TargetFilename', 'User', 'CreationUtcTime'],
    file_access: ['Image', 'FileName', 'User'],
    file_change: ['Image', 'TargetFilename', 'PreviousCreationUtcTime', 'CreationUtcTime'],
    file_delete: ['Image', 'TargetFilename', 'User'],
    file_rename: ['Image', 'SourceFilename', 'TargetFilename'],
    registry_event: ['Image', 'TargetObject', 'Details', 'EventType', 'NewName'],
    registry_add: ['Image', 'TargetObject', 'EventType'],
    registry_delete: ['Image', 'TargetObject', 'EventType'],
    registry_set: ['Image', 'TargetObject', 'Details', 'EventType'],
    registry_rename: ['Image', 'TargetObject', 'NewName'],
    network_connection: ['Image', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'SourceIp', 'SourcePort', 'Initiated', 'Protocol', 'User'],
    dns_query: ['Image', 'QueryName', 'QueryResults', 'QueryStatus'],
    create_remote_thread: ['SourceImage', 'TargetImage', 'StartAddress', 'StartModule', 'StartFunction'],
    pipe_created: ['Image', 'PipeName'],
    wmi_event: ['EventType', 'Operation', 'Destination', 'Consumer', 'Filter', 'Query'],
    ps_script: ['ScriptBlockText', 'Path', 'ScriptBlockId'],
    ps_module: ['Payload', 'ContextInfo'],
    ps_classic_start: ['Data', 'HostApplication', 'HostName', 'HostVersion'],
    proxy: ['c-uri', 'c-uri-extension', 'c-uri-query', 'c-uri-stem', 'c-useragent', 'cs-host', 'cs-method', 'cs-referrer', 'cs-cookie', 'r-dns', 'sc-status', 'c-ip', 'dst-ip'],
    webserver: ['cs-method', 'cs-uri-query', 'cs-uri-stem', 'cs-user-agent', 'cs-referer', 'sc-status', 'c-ip'],
    firewall: ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'action', 'protocol'],
    antivirus: ['Signature', 'Filename', 'Image'],
};

/** Fields of a product/service when there is no category (Windows Security / System logs…). */
export const SERVICE_FIELDS = {
    security: ['EventID', 'SubjectUserName', 'SubjectDomainName', 'TargetUserName', 'TargetDomainName', 'LogonType', 'IpAddress', 'WorkstationName', 'ProcessName', 'ServiceName', 'ObjectName', 'AccessMask', 'Status', 'SubStatus', 'TicketEncryptionType', 'ShareName', 'RelativeTargetName'],
    system: ['EventID', 'Provider_Name', 'ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName'],
    sysmon: ['EventID', 'Image', 'CommandLine'],
    powershell: ['EventID', 'ScriptBlockText', 'Payload'],
    auditd: ['type', 'syscall', 'exe', 'comm', 'key', 'a0', 'a1', 'a2', 'a3', 'name', 'nametype', 'uid', 'auid'],
    cloudtrail: ['eventSource', 'eventName', 'errorCode', 'errorMessage', 'userIdentity.type', 'userIdentity.arn', 'requestParameters', 'responseElements', 'sourceIPAddress', 'userAgent', 'awsRegion'],
    auditlogs: ['ActivityDisplayName', 'Category', 'Result', 'TargetResources', 'InitiatedBy'],
    signinlogs: ['ResultType', 'ResultDescription', 'AppDisplayName', 'UserPrincipalName', 'IPAddress', 'Location', 'AuthenticationRequirement'],
    okta: ['eventtype', 'displaymessage', 'outcome.result', 'actor.alternateid'],
};

/** Value modifiers (pySigma's list), with what they do. */
export const MODIFIERS = {
    contains: 'Matches when the value appears anywhere in the field (`*value*`).',
    startswith: 'Matches when the field starts with the value (`value*`).',
    endswith: 'Matches when the field ends with the value (`*value`).',
    all: 'Every value of the list must match (AND), instead of any of them (OR). Use it with `contains`, `startswith` or `endswith`.',
    exists: 'The field exists (`true`) or not (`false`): `Field|exists: true`.',
    cased: 'Case-sensitive match (Sigma matching is case-insensitive by default).',
    neq: 'The field is not equal to the value.',
    re: 'The value is a regular expression (PCRE subset). Flags: `|re|i` (ignore case), `|re|m` (multi-line), `|re|s` (dot matches new lines).',
    i: 'Regular expression flag: ignore case (after `re`).',
    ignorecase: 'Regular expression flag: ignore case (after `re`).',
    m: 'Regular expression flag: ^ and $ match at line breaks (after `re`).',
    multiline: 'Regular expression flag: ^ and $ match at line breaks (after `re`).',
    s: 'Regular expression flag: the dot matches new lines (after `re`).',
    dotall: 'Regular expression flag: the dot matches new lines (after `re`).',
    base64: 'Matches the value encoded in Base64.',
    base64offset: 'Matches the value Base64-encoded at the three possible offsets: use it with `contains`.',
    wide: 'Encodes the value in UTF-16LE before the other transformations (with `base64` / `base64offset`).',
    windash: 'Also matches the command-line flag written with `/`, `–`, `—` or `―` instead of `-`.',
    cidr: 'The value is an IP network in CIDR notation (`10.0.0.0/8`).',
    gt: 'The field is greater than the number.',
    gte: 'The field is greater than or equal to the number.',
    lt: 'The field is less than the number.',
    lte: 'The field is less than or equal to the number.',
    expand: 'The value contains `%placeholder%`s replaced by the processing pipeline.',
    fieldref: 'The value is the name of another field: matches when both fields are equal.',
    minute: 'Compares the minute of a timestamp field.',
    hour: 'Compares the hour of a timestamp field.',
    day: 'Compares the day of a timestamp field.',
    week: 'Compares the week of a timestamp field.',
    month: 'Compares the month of a timestamp field.',
    year: 'Compares the year of a timestamp field.',
};

/** Condition keywords. */
export const CONDITION_KEYWORDS = {
    and: 'Both sides must match.',
    or: 'One side is enough.',
    not: 'The next expression must not match (often `not filter`).',
    of: '`1 of selection_*` (any of the matching identifiers), `all of selection_*` (all of them).',
    them: 'Every search identifier of the rule (`1 of them`, `all of them`). Avoid `all of them` with filters.',
};

/** ATT&CK tactics, as Sigma tags (attack.<name>). */
export const TACTICS = {
    'reconnaissance': 'TA0043', 'resource-development': 'TA0042', 'initial-access': 'TA0001', 'execution': 'TA0002',
    'persistence': 'TA0003', 'privilege-escalation': 'TA0004', 'defense-evasion': 'TA0005', 'credential-access': 'TA0006',
    'discovery': 'TA0007', 'lateral-movement': 'TA0008', 'collection': 'TA0009', 'command-and-control': 'TA0011',
    'exfiltration': 'TA0010', 'impact': 'TA0040',
};

/** Tag namespaces (the part before the first dot). */
export const TAG_NAMESPACES = {
    attack: 'MITRE ATT&CK: a technique (`attack.t1059.001`), a tactic (`attack.execution`), a group (`attack.g0016`) or software (`attack.s0002`).',
    car: 'MITRE Cyber Analytics Repository: `car.2016-04-005`.',
    cve: 'A vulnerability: `cve.2024-3094`.',
    tlp: 'Traffic Light Protocol: `tlp.clear`, `tlp.green`, `tlp.amber`, `tlp.amber-strict`, `tlp.red`.',
    detection: 'Kind of rule: `detection.threat-hunting`, `detection.emerging-threats`, `detection.dfir`.',
    stp: 'Summiting the Pyramid score: `stp.3k`.',
    d3fend: 'MITRE D3FEND: `d3fend.d3-am`.',
};

export const TLP = ['clear', 'green', 'amber', 'amber-strict', 'red'];
export const DETECTION_TAGS = ['threat-hunting', 'emerging-threats', 'dfir'];
