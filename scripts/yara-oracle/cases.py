S2 = '$a = "abcd"\n $b = "efgh"'
def R(cond, strings=S2, pre='', head='rule r', meta=''):
    body = (f'meta: {meta}\n' if meta else '') + (f'strings: {strings}\n' if strings else '') + f'condition: {cond}'
    return f'{pre}\n{head} {{ {body} }}'
C = []
# conditions (from the grammar probe)
for c in ['any of them','2 of ($a, $b)','50% of them','filesize of them','1+1 of them','any of them at 0','all of them and $a at 0 and $b in (0..100) and #a in (0..5) > 1',
 '@a[1] > 0 and !a[1] > 0 and @a > 0 and !a > 0 and $b','for any i in (1..#a) : (@a[i] > 0) and $b','for all i in (1,2,3) : (i > 0) and $a and $b','for any of them : ($ at 0)',
 'for 2 of ($a,$b) : (# > 1 and @ > 0 and ! > 0)','$ and $a and $b','# > 0 and $a and $b','with x = 1 : (x == 1) and $a and $b','defined filesize and $a and $b','not defined 1 and $a and $b',
 '"a" contains "b" and $a and $b','"a" matches /b/is and $a and $b','filesize matches /x/ and $a and $b','$a matches /x/ and $b','them','$a*','any of ($a*, $b)','any of ($*)',
 '-1 < 2 and ~1 == 0 and 1 \\ 2 == 0 and 2 ^ 3 | 4 & 5 << 1 >> 1 == 0 and $a and $b','1.5 > 1 and $a and $b','1 and $a and $b','"x" and $a and $b','$a + 1 and $b','filesize + "a" and $a and $b',
 '0x10 == 16 and 0o17 == 15 and $a and $b','1KB == 1024 and 1MB > 0 and $a and $b','uint32be(0) == 0 and int8(0) == 0 and $a and $b','uint32 == 0 and $a and $b','entrypoint == 0 and $a and $b',
 '($a or $b)','(($a) and ($b))','$a and and $b','$a $b','$a and $b or','$a in (0..)','$a in 0..10 and $b','$a at and $b','for any i in (1..3) : i > 0 and $a and $b','for any i in (1..3) (i>0) and $a and $b',
 'all of them : ($)','none of them','any of them in (0..filesize)','#a == 1 and $b','#a[1] == 1 and $b','@a == 1 and $b','!a[1] == 1 and $b','$a[1] and $b','(1..2) and $a and $b',
 '$a and $b and 1 == 1 == 1','$a and $b and 1 < 2 < 3','$a and $b and not not true','$a and $b and - - 1','$a and $b and (1)','$a and $b and ()','all of ($a, $b,)','all of ()','any of $a',
 'any of ($a $b)','any them','of them','$a and $b and 1 of them of them','3 of them','0 of them','$a and $b and "a" == "a" and "a" != 1','$a and $b and 1 contains 2','$a and $b and "a" iequals "A"',
 '$a and $b and filesize in (0..1)','$a and $b and for any x, y in (0..1) : (true)','$a and $b and for i in (0..1) : (true)','$a and $b and for any of ($a) : ($)',
 'any of ($a) and for any s in ("a","b") : (s == "a") and $b','$a and $b and 1.5 == 1','$a and $b and 1.5 & 1 == 0','$a and $b and "a" < "b"','$a and $b and true == true','$a and $b and filesize == true',
 '$a and $b and (1 == 1) == true','$a and $b and -"a" == 1','$a and $b and ~1.5 == 1','$a and $b and uint8("a") == 1','$a and $b and $a at "x"','$a and $b and #a in (0.."x") == 1',
 '$a and $b and @a["x"] == 1','$a and $b and 1 % 2 == 1','$a and $b and 1.5 % 2 == 1','$a and $b and 1 \\ 2.5 > 0','$a and $b and 10 % of them','$a and $b and 101% of them','$a and $b and 0x of them',
 '$a and $b and for any i in (1..3) : ( for any j in (1..i) : (j > 0) )','$a and $b and for any i in (1..3) : (j > 0)','$a and $b and i > 0','$a and $b and not','$a and $b and defined','not $a and not $b',
 '$a and $b and r2','any of (r2, r3*)','$a and $b and #a','$a and $b and @a','$a and $b and !a','$a and $b and #','$a and $b and for any of ($a, $b) : (#)','for all of ($a*) : ($ in (0..10)) and $b',
 '$a and $b and "\\x41" == "A"','$a and $b and "\\q" == "A"','$a and $b and filesize > 1KB*2','$a and $b and 2 of ($a, $b) in (0..10)','$a and $b and any of ($a, $b) at 0','$a and $b and all of them in (0..1) == 1']:
    C.append(R(c))
# modules
PRE = 'import "pe"\nimport "math"\nimport "hash"\nimport "dotnet"\nimport "elf"\nimport "time"\nimport "string"\nimport "console"'
for c in ['math.entropy(0, filesize) > 7','pe.number_of_sections > 0 and pe.sections[0].name == ".text"','pe.imports("k.dll")','pe.imports(/k/, /x/)','pe.version_info["CompanyName"] == "x"',
 'for any s in pe.sections : (s.name == ".text")','for any k, v in pe.version_info : (k == "x")','pe.foo','pe.sections','pe.number_of_sections()','pe.imports','pe.imports("a", 1, 2, 3)','pe.is_dll','pe.is_dll()',
 'pe.sections[0]','pe.sections["x"].name == ""','pe.version_info[0] == "x"','pe.sections[0].foo == 1','math.entropy("a") > 1','math.entropy(1) > 1','math.entropy() > 1','hash.md5(0, filesize) == "x"',
 'hash.md5(0, filesize) == 1','hash.md5("a") == "x"','pe.machine == pe.MACHINE_I386','pe.MACHINE_I386()','pe.number_of_sections == "x"','pe.characteristics & pe.DLL','for any s in pe.sections : (s.foo == 1)',
 'for any i in (0..pe.number_of_sections - 1) : (pe.sections[i].name == ".x")','for any s, t in pe.sections : (true)','for any k in pe.version_info : (true)','dotnet.number_of_guids > 0','elf.type == elf.ET_EXEC',
 'time.now() > 0','string.length("a") == 1','string.to_int("1") == 1','console.log("x")','math.to_number(true) == 1','math.to_number(1 == 1) == 1','pe.exports(1)','pe.exports(/a/)','pe.section_index(".text") >= 0',
 'pe.rich_signature.toolid(1)','pe.signatures[0].issuer contains "x"','pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].size > 0','math.in_range(1.0, 0.0, 2.0)','math.in_range(1, 0, 2)','pe.imports("a", "b") == 1',
 'pe.imports(pe.IMPORT_DELAYED, "a", "b")','math.max(1, "a") == 1','math.mean(0, filesize) > 1.5','not pe.is_dll()','pe.entry_point','pe.sections[0].name','pe.linker_version.major','pe.linker_version']:
    C.append(R(c, strings='', pre=PRE))
C.append(R('pe.number_of_sections > 0', strings=''))                 # not imported
C.append(R('foo.bar > 0', strings=''))                               # unknown module
C.append(R('true', strings='', pre='import "foo"'))
C.append(R('true', strings='', pre='import "pe"\nimport "pe"'))
C.append(R('true', strings='', pre='import "macho"'))
C.append(R('true', strings='', pre='import "magic"'))
C.append(R('true', strings='', pre='import "dex"'))
C.append(R('true', strings='', pre='import pe'))
# strings and modifiers
for s in ['"abc" nocase','"abc" wide ascii','"abc" fullword private','"abc" xor','"abc" xor(1)','"abc" xor(1-255)','"abc" xor(0x01-0xff)','"abc" xor(256)','"abc" xor(5-2)','"abc" xor()','"abc" xor(-1)',
 '"abc" base64','"abc" base64wide','"abc" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")','"abc" base64("abc")','"abc" base64(1)','"abc" nocase xor','"abc" base64 xor','"abc" base64 fullword',
 '"abc" base64 nocase','"abc" base64 wide','"abc" xor wide','"abc" xor fullword','"abc" nocase nocase','"abc" foo','{ 41 42 } nocase','{ 41 42 } wide','{ 41 42 } private','{ 41 42 } xor','/abc/ nocase wide ascii fullword private',
 '/abc/ xor','/abc/ base64','"abc" base64 base64wide','"ab"','""','"a"','"\\x4"','"\\q"','"\\n\\t\\r\\\\\\""','"\\x41\\x42"','"abc','{ 41 42 43 }','{ 4 }','{ 41 4 }','{ }','{ 41 ?? 43 }','{ 4? ?3 43 }',
 '{ 41 [2] 43 }','{ [2] 41 }','{ 41 [2] }','{ 41 [2-1] 43 }','{ 41 [-] 43 }','{ 41 [2-] 43 }','{ 41 [0] 43 }','{ 41 [0-0] 43 }','{ 41 ( 42 | 43 ) 44 }','{ 41 ( 42 | 43 44 }','{ 41 42 | 43 }','{ 41 ( 42 | [1-] 43 ) 44 }',
 '{ 41 ( 42 | [1-2] 43 ) 44 }','{ 41 ~42 43 }','{ 41 ~4? 43 }','{ 41 ~?? 43 }','{ 41 G2 43 }','{ 41 42 // c\n 43 }','{ 41 /* c */ 42 }','{ ?? 41 }','{ 41 ?? }','{ 41 ( 42 ) 43 }','{ 41 () 43 }','{ 41 ( 42 | ) 43 }',
 '{ 41 [1-300] 43 }','{ 41 [1-70000] 43 }','{ 41 [9999999999] 43 }','{ 41 [1-2] [3] 43 }','{ 41 42 43 } nocase','{ ( 41 | 42 ) 43 }','{ 41 ( 42 ( 43 | 44 ) | 45 ) 46 }','{ ~41 42 }','{ 41 ~ 42 }',
 '/abc/is','/abc/x','/(?:a)/','/a\\1/','/a{2,1}/','/[z-a]/','/a{40000}/','/a*?b+/','/a(b/','/a[/','/a/','/a\\x4/','/\\babc\\b/','/a$*/','/ab/s nocase']:
    C.append(R('$a', strings=f'$a = {s}'))
# rule level
C += [
 'rule r { condition: true }\nrule r { condition: true }',
 'rule r : t1 t2 { condition: true }','rule r : t1 t1 { condition: true }','rule r : { condition: true }','rule r : 1x { condition: true }',
 'private rule r { condition: true }','global rule r { condition: true }','private global rule r { condition: true }','global private rule r { condition: true }','private private rule r { condition: true }',
 'rule condition { condition: true }','rule all { condition: true }','rule with { condition: true }','rule pe { condition: true }','rule _x { condition: true }','rule 1x { condition: true }',
 'rule ' + 'a'*128 + ' { condition: true }','rule ' + 'a'*129 + ' { condition: true }',
 'rule r { meta: a = "x" b = 1 c = true d = -1 e = false condition: true }','rule r { meta: a = x condition: true }','rule r { meta: a = "x" a = "y" condition: true }','rule r { meta: a = 1.5 condition: true }',
 'rule r { meta: a = "\\q" condition: true }','rule r { meta: condition: true }','rule r { strings: condition: true }','rule r { condition: }','rule r { }','rule r { condition: true',
 'rule r { strings: $a = "abcd" $a = "efgh" condition: $a }','rule r { strings: $a = "abcd" condition: true }','rule r { strings: $ = "abcd" condition: true }','rule r { strings: $ = "abcd" $ = "efgh" condition: all of them }',
 'rule r { strings: $a = "abcd" condition: $b }','rule r { strings: $a = "abcd" $ab = "efgh" condition: $a* }','rule r { strings: $a1 = "abcd" condition: $a* }','rule r { strings: $a1 = "abcd" condition: any of ($b*) }',
 'rule r { strings: $a1 = "abcd" condition: any of ($a*) }','rule r { condition: them }','rule r { condition: any of them }','rule r { strings: $a* = "abcd" condition: $a }',
 'rule a { condition: true }\nrule b { condition: a }','rule b { condition: a }\nrule a { condition: true }','rule a { condition: a }','rule a { condition: true }\nrule b { condition: any of (a, c) }',
 'rule a1 { condition: true }\nrule a2 { condition: true }\nrule b { condition: any of (a*) }','rule b { condition: any of (z*) }',
 'rule r { condition: true } garbage','import "pe" rule r { condition: pe.is_dll() }','include "x.yar"','rule r { condition: true }}','rule r { meta: description = "x" condition: true }',
 'rule r { condition: entrypoint == 0 }','rule r { strings: $a = "ab" condition: $a and 1 }','rule r\n{\n strings:\n  $a = "abcd" wide nocase\n condition:\n  $a\n}',
 'rule r { strings: $a = "abcd" private condition: $a }','rule r { strings: $a = { 41 } condition: $a }','rule r { condition: filesize > 10MB }','rule r { condition: 10 KB }','rule r { condition: 1.0.0 }',
]
