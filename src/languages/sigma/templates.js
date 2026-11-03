/**
 * Rule templates of the Sigma pack ("New rule from template"): complete starting points per log
 * source. Each one is accepted as it is by Rulezet's validation (JSON schema + pySigma, checked by
 * test/sigma-templates.test.js through the oracle fixture) and follows the SigmaHQ conventions:
 *
 *   title       what is detected, capitalised, no "Detects"
 *   status      experimental for a new rule
 *   selection   what to look for; filter_main_* / filter_optional_* what to exclude
 *   condition   selection and not 1 of filter_*
 *   level       how urgent a hit is
 *
 * template: { id, label, category, description, snippet }  (${placeholder}, {{uuid}}, {{date}})
 */
const HEAD = (title, description, tags) => `title: \${${title}}
id: {{uuid}}
status: experimental
description: \${${description}}
references:
    - \${https://example.org/report}
author: \${author}
date: {{date}}
tags:
${tags.map(t => `    - ${t}`).join('\n')}`;

const TAIL = (level, fp = 'Unknown') => `falsepositives:
    - \${${fp}}
level: \${${level}}`;

export const TEMPLATES = [
    // ── Windows ────────────────────────────────────────────────────────────
    {
        id: 'win-process-creation', category: 'Windows', label: 'Suspicious process (command line)',
        description: 'process_creation: a program started with a suspicious command line, its usual parent excluded.',
        snippet: `${HEAD('Suspicious Tool Execution With Encoded Command', 'A tool started with an encoded command, as seen in intrusions', ['attack.execution', 'attack.t1059.001'])}
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\${\\powershell.exe}'
        - OriginalFileName: '\${PowerShell.EXE}'
    selection_cli:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    filter_main_parent:
        ParentImage|endswith: '\${\\legit_updater.exe}'
    condition: all of selection_* and not 1 of filter_main_*
${TAIL('high', 'Administrative scripts')}
`,
    },
    {
        id: 'win-parent-child', category: 'Windows', label: 'Unusual parent → child',
        description: 'process_creation: an Office program (or another parent) starting a shell.',
        snippet: `${HEAD('Office Application Spawning A Shell', 'An Office application starting a command shell, typical of a malicious macro', ['attack.execution', 'attack.t1204.002'])}
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\powerpnt.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\mshta.exe'
    condition: all of selection_*
${TAIL('high')}
`,
    },
    {
        id: 'win-registry-set', category: 'Windows', label: 'Registry persistence (Run key)',
        description: 'registry_set: a value written in a Run key by an unusual program.',
        snippet: `${HEAD('Run Key Set From A Temporary Folder', 'A Run key value pointing to a program in a temporary folder', ['attack.persistence', 'attack.t1547.001'])}
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        Details|contains:
            - '\\AppData\\Local\\Temp\\'
            - '\\Windows\\Temp\\'
    condition: selection
${TAIL('medium', 'Installers that register a first run from a temporary folder')}
`,
    },
    {
        id: 'win-file-event', category: 'Windows', label: 'File dropped in a suspicious place',
        description: 'file_event: a file with a given extension created in a startup or temporary folder.',
        snippet: `${HEAD('Script Dropped In The Startup Folder', 'A script file written in a Startup folder, run at each logon', ['attack.persistence', 'attack.t1547.001'])}
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: '\\Start Menu\\Programs\\Startup\\'
        TargetFilename|endswith:
            - '.vbs'
            - '.js'
            - '.bat'
            - '.ps1'
    condition: selection
${TAIL('medium', 'Legitimate logon scripts')}
`,
    },
    {
        id: 'win-network', category: 'Windows', label: 'Process making a network connection',
        description: 'network_connection: a program that should not talk to the Internet opens a connection.',
        snippet: `${HEAD('Notepad Initiating A Network Connection', 'Notepad opening an outbound connection, often a sign of process injection', ['attack.command-and-control', 'attack.t1071'])}
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\\notepad.exe'
        Initiated: 'true'
    filter_main_local:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not 1 of filter_main_*
${TAIL('high')}
`,
    },
    {
        id: 'win-security-event', category: 'Windows', label: 'Security event log (EventID)',
        description: 'service security: a Windows Security event with its fields (here, a new service account added to a privileged group).',
        snippet: `${HEAD('Member Added To A Privileged Group', 'A user added to the Domain Admins or Enterprise Admins group', ['attack.persistence', 'attack.t1098'])}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4728
            - 4732
            - 4756
        TargetUserName:
            - 'Domain Admins'
            - 'Enterprise Admins'
    condition: selection
${TAIL('high', 'Planned administrative changes')}
`,
    },
    {
        id: 'win-powershell-script', category: 'Windows', label: 'PowerShell script block',
        description: 'ps_script: words seen in a PowerShell script block (Script Block Logging must be on).',
        snippet: `${HEAD('PowerShell Download And Execute', 'A script block that downloads a payload and runs it in memory', ['attack.execution', 'attack.t1059.001'])}
logsource:
    category: ps_script
    product: windows
    definition: 'Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'Invoke-Expression'
    condition: selection
${TAIL('high', 'Software installers written in PowerShell')}
`,
    },
    // ── Linux ──────────────────────────────────────────────────────────────
    {
        id: 'linux-process', category: 'Linux', label: 'Linux command line',
        description: 'process_creation on Linux: a command often used after an intrusion.',
        snippet: `${HEAD('Reverse Shell Through Bash TCP Redirection', 'Bash connecting its input and output to a remote host', ['attack.execution', 'attack.t1059.004'])}
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - '/dev/tcp/'
            - '/dev/udp/'
    condition: selection
${TAIL('high')}
`,
    },
    {
        id: 'linux-auditd', category: 'Linux', label: 'auditd record',
        description: 'service auditd: an execve record of a given program.',
        snippet: `${HEAD('Kernel Module Loaded With Insmod', 'A kernel module loaded by hand, as rootkits do', ['attack.persistence', 'attack.t1547.006'])}
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0:
            - 'insmod'
            - 'modprobe'
    condition: selection
${TAIL('medium', 'Driver installation by administrators')}
`,
    },
    // ── Network / web ──────────────────────────────────────────────────────
    {
        id: 'dns-query', category: 'Network', label: 'DNS query to a domain',
        description: 'dns_query: a host resolving a domain used by a threat (or a whole family of domains).',
        snippet: `${HEAD('DNS Query To A File Sharing Service', 'A host resolving a file sharing domain often used for exfiltration', ['attack.exfiltration', 'attack.t1567.002'])}
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.transfer.sh'
            - '.anonfiles.com'
    condition: selection
${TAIL('medium', 'Legitimate use of these services')}
`,
    },
    {
        id: 'proxy', category: 'Network', label: 'Web proxy request',
        description: 'proxy: an HTTP request with a suspicious user agent or URL.',
        snippet: `${HEAD('Request With A Scripting User Agent', 'An HTTP request made with the default user agent of a scripting tool', ['attack.command-and-control', 'attack.t1071.001'])}
logsource:
    category: proxy
detection:
    selection:
        c-useragent|startswith:
            - 'python-requests/'
            - 'Go-http-client/'
            - 'curl/'
    condition: selection
${TAIL('low', 'Internal scripts and monitoring tools')}
`,
    },
    {
        id: 'webserver', category: 'Network', label: 'Web server attack',
        description: 'webserver: an exploitation attempt seen in the access logs.',
        snippet: `${HEAD('Path Traversal In A Web Request', 'A request trying to read files outside the web root', ['attack.initial-access', 'attack.t1190'])}
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '../../'
            - '..%2f..%2f'
            - '%2e%2e%2f'
    condition: selection
${TAIL('medium', 'Vulnerability scanners run by the security team')}
`,
    },
    // ── Cloud ──────────────────────────────────────────────────────────────
    {
        id: 'aws-cloudtrail', category: 'Cloud', label: 'AWS CloudTrail event',
        description: 'product aws, service cloudtrail: an API call that weakens the logging.',
        snippet: `${HEAD('CloudTrail Logging Stopped', 'Someone stopped or deleted a CloudTrail trail to hide their activity', ['attack.defense-evasion', 'attack.t1562.008'])}
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'cloudtrail.amazonaws.com'
        eventName:
            - 'StopLogging'
            - 'DeleteTrail'
            - 'UpdateTrail'
    condition: selection
${TAIL('high', 'Planned changes of the logging configuration')}
`,
    },
    {
        id: 'keywords', category: 'Generic', label: 'Keywords in any log',
        description: 'A list of keywords searched in the whole event, for logs without known field names.',
        snippet: `${HEAD('Exploit Strings In Application Logs', 'Strings of a known exploit written by the application', ['attack.initial-access', 'attack.t1190'])}
logsource:
    product: \${jvm}
detection:
    keywords:
        - 'jndi:ldap://'
        - 'jndi:rmi://'
    condition: keywords
${TAIL('high')}
`,
    },
];
