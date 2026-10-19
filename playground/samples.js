/** Sample documents for the playground. */
export const SAMPLES = {
    'Several rules': `import "pe"
import "math"

private rule Is_PE
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Suspicious_Downloader : downloader windows
{
    meta:
        author = "you"
        description = "PE that downloads and runs a second stage"
        date = "2026-10-19"
        reference = "https://example.org/report"
    strings:
        $api1 = "URLDownloadToFileA" ascii
        $api2 = "ShellExecuteA" ascii
        $url  = /https?:\\/\\/[a-z0-9.-]{4,64}\\/[a-z0-9_\\/-]{1,64}\\.exe/ nocase
        $ua   = "Mozilla/5.0 (Windows NT 10.0" ascii wide
    condition:
        Is_PE and filesize < 2MB
        and all of ($api*)
        and ($url or $ua)
        and pe.imports("urlmon.dll")
}

rule Packed_Section
{
    meta:
        author = "you"
        description = "High-entropy executable section"
    condition:
        Is_PE and for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE
            and math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.2
        )
}
`,

    'Broken rule (try the quick fixes)': `rule Broken_Example
{
    strings:
        $a = "cmd.exe /c" nocase xor
        $b = { 4D 5A [4-2] 00 GG }
        $c = "powershell -enc"
        $unused = "never used"
    condition:
        $a and $d and elf.type == elf.ET_EXEC and entrypoint > 0
        and Helper_Rule
}

rule Helper_Rule
{
    condition:
        filesize < 1MB
}
`,

    'Messy formatting': `import "pe"
rule messy:tag1 tag2 {
meta:
author="someone" // who wrote it
description =    "format me with Shift+Alt+F"
strings:
$a="abc"   wide ascii
$long_name={4D    5A   90 00}
  $r=/foo[0-9]+bar/is
condition:
$a or
    ($long_name and $r)
}
rule second{condition:true}`,

    'Uses rules from Rulezet': `rule Uses_External
{
    meta:
        author = "you"
        description = "Hover the rule names below: they are looked up on Rulezet"
    condition:
        filesize < 5MB and (FE_Trojan_BADRABBIT_MIMIKATZ or Mimikatz0)
}
`,

    'Empty': '',
};
