/**
 * Rule templates of the YARA pack: complete starting points by kind of threat and file type, for
 * the "New rule from template" command (palette, toolbar menu, empty document). Each one compiles
 * as it is (checked against libyara by test/templates.test.js) and follows the YARA Style Guide
 * (Florian Roth, https://neo23x0.github.io/YARA-Style-Guide):
 *
 *   name       CATEGORY_Platform_Family_Detail  (MAL_, HKTL_, SUSP_, EXPL_, WEBSHELL_, APT_…)
 *   meta       description (what and why), author, date, reference, hash, score (0-100)
 *   strings    $x*  highly specific: one of them is enough
 *              $s*  grouped: several are needed
 *              $a*  pre-selection (file type, framework)
 *              $fp* false-positive filters: when present, the rule must not fire
 *   condition  cheap checks first (magic bytes, filesize), then strings, then modules
 *
 * template: { id, label, category, description, imports?, snippet }
 *   snippet uses ${placeholder} fields (Tab moves between them) and {{uuid}} / {{date}}.
 * A pack may ship any number of templates; the editor groups them by category.
 */

const META = (description, extra = '') => `    meta:
        description = "\${${description}}"
        author = "\${author}"
        date = "{{date}}"
        reference = "\${https://example.org/report}"
        hash = "\${sha256 of a sample}"
        score = \${70}
        id = "{{uuid}}"${extra}`;

export const TEMPLATES = [
    // ── Windows executables ────────────────────────────────────────────────
    {
        id: 'pe-malware', category: 'Windows', label: 'Windows malware (PE)',
        description: 'An executable or DLL: MZ / PE header, a size bound, specific strings ($x) or a group of weaker ones ($s), false positives excluded ($fp).',
        snippet: `rule \${MAL_Win_Family_Detail}
{
${META('Detects the Family malware (what it does, how it was found)')}
    strings:
        $x1 = "\${a string unique to this malware}" ascii wide
        $x2 = { \${4D 5A 90 00} }
        $s1 = "\${a less specific string}" ascii
        $s2 = "\${another one}" ascii wide
        $s3 = "\${a third one}" ascii
        $fp1 = "\${a string of the legitimate software it resembles}"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
        and filesize < \${2}MB
        and ( 1 of ($x*) or 2 of ($s*) )
        and not 1 of ($fp*)
}
`,
    },
    {
        id: 'pe-dll', category: 'Windows', label: 'Windows DLL (pe module: exports, imports)',
        description: 'A DLL recognised by the pe module: what it exports and imports, plus strings.',
        imports: ['pe'],
        snippet: `import "pe"

rule \${MAL_Win_Family_DLL}
{
${META('Detects the Family loader DLL by its exports and imports')}
    strings:
        $s1 = "\${string}" ascii wide
        $s2 = "\${string}" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and filesize < \${5}MB
        and pe.is_dll()
        and pe.exports("\${ExportedFunction}")
        and pe.imports("\${kernel32.dll}", "\${VirtualAlloc}")
        and 1 of ($s*)
}
`,
    },
    {
        id: 'pe-imphash', category: 'Windows', label: 'Windows PE by import hash and rich header',
        description: 'Clusters samples of one build: the import hash (pe.imphash) and the number of sections, no strings.',
        imports: ['pe'],
        snippet: `import "pe"

rule \${MAL_Win_Family_Imphash}
{
${META('Samples of the Family malware built with the same imports')}
    condition:
        uint16(0) == 0x5A4D
        and filesize < \${3}MB
        and pe.imphash() == "\${32 lowercase hex characters of the imphash}"
        and pe.number_of_sections == \${5}
}
`,
    },
    {
        id: 'pe-packed', category: 'Windows', label: 'Packed executable (UPX, high entropy)',
        description: 'Packer traces: section names and a high entropy section (math module).',
        imports: ['pe', 'math'],
        snippet: `import "pe"
import "math"

rule \${SUSP_Win_Packed_UPX}
{
${META('Executable packed with UPX (section names and entropy)')}
    strings:
        $a1 = "UPX0" ascii
        $a2 = "UPX1" ascii
        $a3 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D
        and 2 of ($a*)
        and for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > \${7.0}
        )
}
`,
    },
    {
        id: 'dotnet', category: 'Windows', label: '.NET assembly',
        description: 'A .NET executable: the assembly name, a GUID from the TypeLib, user strings.',
        imports: ['dotnet'],
        snippet: `import "dotnet"

rule \${MAL_Win_NET_Family}
{
${META('Detects the Family .NET malware')}
    strings:
        $x1 = "\${typelib GUID, e.g. 0c2f... }" ascii wide
        $s1 = "\${namespace or class name}" ascii wide
        $s2 = "\${user string}" wide
    condition:
        uint16(0) == 0x5A4D
        and filesize < \${4}MB
        and dotnet.is_dotnet == 1
        and ( $x1 or all of ($s*) )
}
`,
    },
    {
        id: 'shellcode', category: 'Windows', label: 'Shellcode (hex with wildcards and jumps)',
        description: 'Byte patterns with wildcards (??), nibbles (4?), bounded jumps [2-6] and alternatives (a|b): position-independent code, no file header.',
        snippet: `rule \${MAL_Shellcode_Family_Loader}
{
${META('Shellcode stub of the Family loader (API hashing loop)')}
    strings:
        $x1 = { 64 8B ?? 30 00 00 00 [2-6] 8B 4? 0C }
        $x2 = { E8 00 00 00 00 ( 58 | 5D | 5E ) [0-8] 83 ?? ?? }
    condition:
        filesize < \${1}MB and any of them
}
`,
    },
    // ── Linux, macOS, Android ──────────────────────────────────────────────
    {
        id: 'elf', category: 'Linux & other systems', label: 'Linux malware (ELF)',
        description: 'An ELF binary (magic 7F 45 4C 46), with specific and grouped strings.',
        snippet: `rule \${MAL_Lnx_Family_Detail}
{
${META('Detects the Family Linux malware')}
    strings:
        $x1 = "\${unique string}" ascii
        $s1 = "/proc/\${self/exe}" ascii
        $s2 = "\${another string}" ascii
        $s3 = "\${a third string}" ascii
    condition:
        uint32(0) == 0x464C457F
        and filesize < \${5}MB
        and ( $x1 or 2 of ($s*) )
}
`,
    },
    {
        id: 'macho', category: 'Linux & other systems', label: 'macOS malware (Mach-O)',
        description: 'A Mach-O binary (thin 64-bit or universal), with strings.',
        snippet: `rule \${MAL_macOS_Family_Detail}
{
${META('Detects the Family macOS malware')}
    strings:
        $s1 = "\${string}" ascii
        $s2 = "\${string}" ascii
    condition:
        ( uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xBEBAFECA )
        and filesize < \${10}MB
        and all of ($s*)
}
`,
    },
    {
        id: 'android-dex', category: 'Linux & other systems', label: 'Android (DEX)',
        description: 'A Dalvik DEX file ("dex\\n0"): class or method names of the app.',
        snippet: `rule \${MAL_Android_Family_Detail}
{
${META('Detects the Family Android malware (DEX)')}
    strings:
        $s1 = "\${Lcom/example/payload/Main;}" ascii
        $s2 = "\${method or string}" ascii
    condition:
        uint32(0) == 0x0A786564
        and all of ($s*)
}
`,
    },
    // ── Documents ──────────────────────────────────────────────────────────
    {
        id: 'office-macro', category: 'Documents', label: 'Office document with a macro (OLE)',
        description: 'A legacy Office file (doc / xls) whose VBA calls something suspicious when it opens.',
        snippet: `rule \${MAL_Doc_Macro_Downloader}
{
${META('Office document with an auto-open macro that downloads and runs a payload')}
    strings:
        $a1 = "Attribute VB_" ascii
        $s1 = "AutoOpen" ascii nocase
        $s2 = "Document_Open" ascii nocase
        $s3 = "Workbook_Open" ascii nocase
        $x1 = "\${URLDownloadToFileA}" ascii nocase
        $x2 = "\${WScript.Shell}" ascii nocase
    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1
        and $a1 and 1 of ($s*) and 1 of ($x*)
}
`,
    },
    {
        id: 'ooxml-macro', category: 'Documents', label: 'Office Open XML with macros (docm / xlsm)',
        description: 'A zip-based Office file that contains a VBA project.',
        snippet: `rule \${SUSP_Doc_OOXML_VBA_Project}
{
${META('Office Open XML document carrying a VBA project')}
    strings:
        $a1 = "[Content_Types].xml" ascii
        $s1 = "vbaProject.bin" ascii
        $s2 = "\${word/}" ascii
    condition:
        uint32(0) == 0x04034B50
        and $a1 and all of ($s*)
}
`,
    },
    {
        id: 'pdf', category: 'Documents', label: 'Malicious PDF (JavaScript, auto action)',
        description: 'A PDF that runs JavaScript or launches something when it is opened.',
        snippet: `rule \${SUSP_PDF_JavaScript_OpenAction}
{
${META('PDF running JavaScript when it opens')}
    strings:
        $a1 = "%PDF-" ascii
        $s1 = "/OpenAction" ascii
        $s2 = "/AA" ascii
        $x1 = "/JavaScript" ascii
        $x2 = "/JS" ascii
        $x3 = "/Launch" ascii
    condition:
        $a1 at 0
        and 1 of ($s*) and 1 of ($x*)
}
`,
    },
    {
        id: 'rtf', category: 'Documents', label: 'RTF with an embedded object (exploit)',
        description: 'An RTF file carrying an OLE object, as exploits of the equation editor do.',
        snippet: `rule \${EXPL_RTF_Embedded_Object}
{
${META('RTF document with an embedded OLE object (equation editor exploit pattern)')}
    strings:
        $a1 = "{\\\\rt" ascii
        $s1 = "\\\\objdata" ascii nocase
        $s2 = "\\\\objupdate" ascii nocase
        $x1 = "\${4571756174696F6E2E33}" ascii nocase
    condition:
        $a1 at 0
        and $s1 and ( $s2 or $x1 )
}
`,
    },
    {
        id: 'lnk', category: 'Documents', label: 'Windows shortcut (LNK) running a command',
        description: 'A .lnk file whose target is a command line (PowerShell, cmd, mshta…).',
        snippet: `rule \${SUSP_LNK_Command_Execution}
{
${META('Windows shortcut launching a script interpreter')}
    strings:
        $s1 = "powershell" ascii wide nocase
        $s2 = "cmd.exe" ascii wide nocase
        $s3 = "mshta" ascii wide nocase
        $x1 = "\${-enc}" ascii wide nocase
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401
        and filesize < \${100}KB
        and 1 of ($s*) and $x1
}
`,
    },
    // ── Scripts and web ────────────────────────────────────────────────────
    {
        id: 'powershell', category: 'Scripts & web', label: 'PowerShell loader',
        description: 'Encoded commands, download cradles, in-memory execution.',
        snippet: `rule \${MAL_PS1_Loader_Detail}
{
${META('PowerShell script that downloads and runs a payload in memory')}
    strings:
        $s1 = "IEX" ascii nocase
        $s2 = "Invoke-Expression" ascii nocase
        $s3 = "DownloadString" ascii nocase
        $s4 = "FromBase64String" ascii nocase
        $s5 = "-EncodedCommand" ascii nocase
        $x1 = "\${a unique string of this loader}" ascii
    condition:
        filesize < \${200}KB
        and ( $x1 or 3 of ($s*) )
}
`,
    },
    {
        id: 'vbs-js', category: 'Scripts & web', label: 'VBScript / JScript dropper',
        description: 'Windows Script Host scripts that write and run a file.',
        snippet: `rule \${MAL_Script_WSH_Dropper}
{
${META('VBS / JS dropper using Windows Script Host')}
    strings:
        $s1 = "WScript.Shell" ascii nocase
        $s2 = "ActiveXObject" ascii nocase
        $s3 = "CreateObject" ascii nocase
        $s4 = "ADODB.Stream" ascii nocase
        $s5 = ".Run" ascii nocase
    condition:
        filesize < \${300}KB
        and 3 of them
}
`,
    },
    {
        id: 'webshell-php', category: 'Scripts & web', label: 'PHP webshell',
        description: 'Code that runs what an HTTP request sends: eval / assert / system on $_POST, $_GET, $_REQUEST, often obfuscated.',
        snippet: `rule \${WEBSHELL_PHP_Generic_Eval}
{
${META('PHP webshell evaluating request parameters')}
    strings:
        $a1 = "<?php" ascii nocase
        $s1 = /(eval|assert|system|passthru|shell_exec)\\s*\\(\\s*(base64_decode|gzinflate|str_rot13)?\\s*\\(?\\s*\\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $s2 = "base64_decode" ascii
        $fp1 = "\${a legitimate framework marker}" ascii
    condition:
        filesize < \${100}KB
        and $a1
        and ( $s1 or #s2 > \${3} )
        and not $fp1
}
`,
    },
    {
        id: 'webshell-aspx-jsp', category: 'Scripts & web', label: 'ASPX / JSP webshell',
        description: 'Server pages that start a process from a request parameter.',
        snippet: `rule \${WEBSHELL_ASPX_JSP_Process}
{
${META('ASPX or JSP page running commands from a request parameter')}
    strings:
        $s1 = "Process.Start" ascii nocase
        $s2 = "Runtime.getRuntime().exec" ascii
        $s3 = "Request.Form" ascii nocase
        $s4 = "request.getParameter" ascii
    condition:
        filesize < \${200}KB
        and ( ($s1 and $s3) or ($s2 and $s4) )
}
`,
    },
    // ── Families and hunting ───────────────────────────────────────────────
    {
        id: 'ransomware-note', category: 'Families & hunting', label: 'Ransomware (note and extension)',
        description: 'Ransom note sentences and the extension the files get, in the binary or the note itself.',
        snippet: `rule \${MAL_Ransom_Family_Note}
{
${META('Ransom note or encryptor of the Family ransomware')}
    strings:
        $x1 = "\${a sentence of the ransom note}" ascii wide nocase
        $x2 = "\${.extension}" ascii wide
        $s1 = "bitcoin" ascii wide nocase
        $s2 = "decrypt" ascii wide nocase
        $s3 = "\${onion address}" ascii wide
    condition:
        filesize < \${5}MB
        and ( 1 of ($x*) or all of ($s*) )
}
`,
    },
    {
        id: 'c2-config', category: 'Families & hunting', label: 'C2 configuration (URLs, user agent, mutex)',
        description: 'Network indicators kept in a sample: a URL pattern (bounded regex), a user agent, a mutex.',
        snippet: `rule \${MAL_Family_C2_Config}
{
${META('Configuration of the Family implant: C2 path, user agent, mutex')}
    strings:
        $s1 = /https?:\\/\\/[a-z0-9.\\-]{4,64}\\/\${gate}\\.php/ nocase ascii wide
        $s2 = "\${Mozilla/5.0 (compatible; custom agent)}" ascii wide
        $s3 = "\${Global\\\\mutex_name}" ascii wide
    condition:
        filesize < \${3}MB
        and 2 of them
}
`,
    },
    {
        id: 'hacktool', category: 'Families & hunting', label: 'Hack tool (dual use)',
        description: 'Offensive or administration tools (HKTL_): flagged by their own strings, low score when legitimate use is common.',
        snippet: `rule \${HKTL_Win_Tool_Name}
{
${META('Detects the Tool hack tool (used by red teams and attackers)', '\n        tool = "${Tool}"')}
    strings:
        $x1 = "\${the tool's banner or usage line}" ascii wide
        $x2 = "\${a module or command name}" ascii wide
    condition:
        filesize < \${10}MB
        and 1 of them
}
`,
    },
    {
        id: 'cve-exploit', category: 'Families & hunting', label: 'Exploit of a CVE',
        description: 'An exploit file or payload for one vulnerability: the CVE in meta (Rulezet links it), the trigger bytes as strings.',
        snippet: `rule \${EXPL_CVE_YYYY_NNNNN_Detail}
{
${META('Exploit for CVE-YYYY-NNNNN (what it targets)', '\n        cve = "${CVE-YYYY-NNNNN}"')}
    strings:
        $x1 = "\${the trigger}" ascii
        $s1 = "\${payload marker}" ascii
    condition:
        filesize < \${1}MB
        and $x1 and $s1
}
`,
    },
    {
        id: 'hunting', category: 'Families & hunting', label: 'Hunting rule (wide net, low score)',
        description: 'Not a detection: finds files worth a look (SUSP_, low score). Expect false positives; review the hits.',
        snippet: `rule \${SUSP_Hunting_Something_Unusual}
{
${META('Hunting: files combining several unusual traits worth a review', '\n        hunting = true')}
    strings:
        $s1 = "\${unusual string}" ascii wide nocase
        $s2 = "\${another one}" ascii wide nocase
        $s3 = "\${a third}" ascii wide nocase
    condition:
        filesize < \${20}MB
        and 2 of them
}
`,
    },
    {
        id: 'private-helper', category: 'Families & hunting', label: 'Private helper + rule that uses it',
        description: 'A private rule (never reported on its own) describing the file type, reused by the detection rule: one definition, many rules.',
        snippet: `private rule \${IsPE}
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule \${MAL_Win_Family_With_Helper}
{
${META('Detects the Family malware (file type checked by the private rule IsPE)')}
    strings:
        $x1 = "\${unique string}" ascii wide
    condition:
        IsPE and $x1
}
`,
    },
    {
        id: 'hash', category: 'Families & hunting', label: 'Known file by hash (hash module)',
        description: 'Matches exact known files by their hash: precise, but any change to the file escapes it — prefer strings when possible.',
        imports: ['hash'],
        snippet: `import "hash"

rule \${MAL_Known_Sample_Hash}
{
${META('Known sample of the Family malware (exact file)')}
    condition:
        filesize < \${5}MB
        and hash.sha256(0, filesize) == "\${64 lowercase hex characters}"
}
`,
    },
];

/** Templates grouped by category, in their declared order. */
export function templateGroups() {
    const groups = [];
    for (const tpl of TEMPLATES) {
        let g = groups.find(x => x.category === tpl.category);
        if (!g) groups.push(g = { category: tpl.category, items: [] });
        g.items.push(tpl);
    }
    return groups;
}
