/**
 * YARA modules: members used for completion, hover and lint.
 *
 * Node kinds:
 *   f(sig, doc)            function           pe.imports("kernel32.dll")
 *   v(type, doc)           value              pe.number_of_sections
 *   c(doc)                 integer constant   pe.MACHINE_I386
 *   s({...}, doc)          structure          pe.version_info  (dict)  /  x.y
 *   a({...}, doc)          array of struct    pe.sections[i].name
 *   av(type, doc)          array of values    math.?  (indexable)
 */

const f = (sig, doc) => ({ kind: 'function', sig, doc });
const v = (type, doc) => ({ kind: 'value', type, doc });
const c = (doc) => ({ kind: 'constant', type: 'integer', doc });
const s = (fields, doc) => ({ kind: 'struct', fields, doc });
const a = (fields, doc) => ({ kind: 'array', fields, doc });
const av = (type, doc) => ({ kind: 'array', type, doc });
const d = (type, doc) => ({ kind: 'dict', type, doc });

const consts = (names, prefix = '') => Object.fromEntries(names.map(n => [n, c(`${prefix}${n}`)]));

const PE = {
    is_pe: v('integer', '1 if the file is a PE.'),
    is_32bit: f('is_32bit()', 'True if the file is a 32-bit PE.'),
    is_64bit: f('is_64bit()', 'True if the file is a 64-bit PE.'),
    is_dll: f('is_dll()', 'True if the file is a DLL.'),
    machine: v('integer', 'Machine type (pe.MACHINE_*).'),
    subsystem: v('integer', 'Subsystem (pe.SUBSYSTEM_*).'),
    characteristics: v('integer', 'File characteristics bitmask (pe.EXECUTABLE_IMAGE, pe.DLL, ...).'),
    dll_characteristics: v('integer', 'DLL characteristics bitmask.'),
    timestamp: v('integer', 'Compile timestamp from the file header (epoch).'),
    entry_point: v('integer', 'Entry point as a file offset (raw).'),
    entry_point_raw: v('integer', 'Entry point RVA as written in the header.'),
    image_base: v('integer', 'Image base.'),
    number_of_sections: v('integer', 'Number of sections.'),
    number_of_imports: v('integer', 'Number of imported DLLs.'),
    number_of_imported_functions: v('integer', 'Number of imported functions.'),
    number_of_exports: v('integer', 'Number of exported functions.'),
    number_of_resources: v('integer', 'Number of resources.'),
    number_of_signatures: v('integer', 'Number of Authenticode signatures.'),
    number_of_rich_entries: v('integer', 'Number of Rich header entries.'),
    size_of_code: v('integer', 'SizeOfCode.'),
    size_of_image: v('integer', 'SizeOfImage.'),
    size_of_headers: v('integer', 'SizeOfHeaders.'),
    size_of_optional_header: v('integer', 'SizeOfOptionalHeader.'),
    checksum: v('integer', 'Checksum from the optional header.'),
    linker_version: s({ major: v('integer', ''), minor: v('integer', '') }, 'Linker version.'),
    os_version: s({ major: v('integer', ''), minor: v('integer', '') }, 'Operating system version.'),
    subsystem_version: s({ major: v('integer', ''), minor: v('integer', '') }, 'Subsystem version.'),
    dll_name: v('string', 'Name of the DLL from the export directory.'),
    export_timestamp: v('integer', 'Timestamp of the export directory.'),
    pdb_path: v('string', 'PDB path from the debug directory.'),
    imphash: f('imphash()', 'MD5 import hash, as a lowercase hex string.'),
    imports: f('imports(dll [, function | ordinal | /regex/])', 'Number of matching imports; true if the DLL / function is imported. Case-insensitive DLL name.'),
    exports: f('exports(function_name | ordinal | /regex/)', 'True if the PE exports the function.'),
    exports_index: f('exports_index(function_name | ordinal | /regex/)', 'Index of the export, or undefined.'),
    import_rva: f('import_rva(dll, function)', 'RVA of an imported function.'),
    section_index: f('section_index(name | address)', 'Index of the section with that name, or containing that address.'),
    is_signed: v('integer', '1 if at least one signature is valid.'),
    calculate_checksum: f('calculate_checksum()', 'Checksum computed over the file.'),
    rva_to_offset: f('rva_to_offset(rva)', 'File offset of an RVA.'),
    locale: f('locale(id)', 'True if a resource uses this locale.'),
    language: f('language(id)', 'True if a resource uses this language.'),
    overlay: s({ offset: v('integer', 'Overlay file offset (0 if none).'), size: v('integer', 'Overlay size.') }, 'Data appended after the last section.'),
    rich_signature: s({
        offset: v('integer', ''), length: v('integer', ''), key: v('integer', ''),
        raw_data: v('string', ''), clear_data: v('string', ''),
        version: f('version(version [, toolid])', 'Number of entries with this version.'),
        toolid: f('toolid(toolid [, version])', 'Number of entries with this tool id.'),
    }, 'Rich header.'),
    version_info: d('string', 'Version information dictionary: pe.version_info["CompanyName"].'),
    sections: a({
        name: v('string', 'Section name.'), full_name: v('string', ''),
        characteristics: v('integer', 'pe.SECTION_* flags.'),
        virtual_address: v('integer', ''), virtual_size: v('integer', ''),
        raw_data_offset: v('integer', ''), raw_data_size: v('integer', ''),
        number_of_relocations: v('integer', ''), number_of_line_numbers: v('integer', ''),
    }, 'Sections: pe.sections[i].name'),
    data_directories: a({ virtual_address: v('integer', ''), size: v('integer', '') }, 'Data directories, index pe.IMAGE_DIRECTORY_ENTRY_*.'),
    resources: a({
        type: v('integer', ''), id: v('integer', ''), language: v('integer', ''),
        type_string: v('string', ''), name_string: v('string', ''), language_string: v('string', ''),
        offset: v('integer', ''), length: v('integer', ''),
    }, 'Resources.'),
    signatures: a({
        issuer: v('string', ''), subject: v('string', ''), version: v('integer', ''),
        algorithm: v('string', ''), serial: v('string', ''), thumbprint: v('string', ''),
        not_before: v('integer', ''), not_after: v('integer', ''),
        verified: v('integer', ''), valid_on: f('valid_on(timestamp)', 'True if the certificate is valid at that time.'),
    }, 'Authenticode signatures.'),
    import_details: a({
        library_name: v('string', ''), number_of_functions: v('integer', ''),
        functions: a({ name: v('string', ''), ordinal: v('integer', ''), rva: v('integer', '') }, ''),
    }, 'Imports per DLL.'),
    export_details: a({ name: v('string', ''), ordinal: v('integer', ''), rva: v('integer', ''), offset: v('integer', ''), forward_name: v('string', '') }, 'Exports.'),
    ...consts(['MACHINE_UNKNOWN', 'MACHINE_I386', 'MACHINE_AMD64', 'MACHINE_ARM', 'MACHINE_ARM64', 'MACHINE_IA64', 'MACHINE_ARMNT', 'MACHINE_THUMB', 'MACHINE_POWERPC'], 'Machine: '),
    ...consts(['SUBSYSTEM_UNKNOWN', 'SUBSYSTEM_NATIVE', 'SUBSYSTEM_WINDOWS_GUI', 'SUBSYSTEM_WINDOWS_CUI', 'SUBSYSTEM_OS2_CUI', 'SUBSYSTEM_POSIX_CUI', 'SUBSYSTEM_EFI_APPLICATION', 'SUBSYSTEM_XBOX'], 'Subsystem: '),
    ...consts(['RELOCS_STRIPPED', 'EXECUTABLE_IMAGE', 'LINE_NUMS_STRIPPED', 'LOCAL_SYMS_STRIPPED', 'LARGE_ADDRESS_AWARE', 'MACHINE_32BIT', 'DEBUG_STRIPPED', 'SYSTEM', 'DLL'], 'Characteristic: '),
    ...consts(['SECTION_CNT_CODE', 'SECTION_CNT_INITIALIZED_DATA', 'SECTION_CNT_UNINITIALIZED_DATA', 'SECTION_MEM_EXECUTE', 'SECTION_MEM_READ', 'SECTION_MEM_WRITE', 'SECTION_MEM_SHARED', 'SECTION_MEM_DISCARDABLE'], 'Section flag: '),
    ...consts(['IMAGE_DIRECTORY_ENTRY_EXPORT', 'IMAGE_DIRECTORY_ENTRY_IMPORT', 'IMAGE_DIRECTORY_ENTRY_RESOURCE', 'IMAGE_DIRECTORY_ENTRY_SECURITY', 'IMAGE_DIRECTORY_ENTRY_BASERELOC', 'IMAGE_DIRECTORY_ENTRY_DEBUG', 'IMAGE_DIRECTORY_ENTRY_TLS', 'IMAGE_DIRECTORY_ENTRY_IAT', 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'], 'Data directory index: '),
    ...consts(['DYNAMIC_BASE', 'NX_COMPAT', 'NO_SEH', 'GUARD_CF', 'HIGH_ENTROPY_VA', 'FORCE_INTEGRITY', 'APPCONTAINER'], 'DLL characteristic: '),
};

const ELF = {
    type: v('integer', 'elf.ET_* file type.'),
    machine: v('integer', 'elf.EM_* machine.'),
    entry_point: v('integer', 'Entry point as a file offset.'),
    number_of_sections: v('integer', ''),
    number_of_segments: v('integer', ''),
    sh_offset: v('integer', ''), sh_entry_size: v('integer', ''),
    ph_offset: v('integer', ''), ph_entry_size: v('integer', ''),
    sections: a({ type: v('integer', ''), flags: v('integer', ''), name: v('string', ''), address: v('integer', ''), size: v('integer', ''), offset: v('integer', '') }, 'Sections.'),
    segments: a({ type: v('integer', ''), flags: v('integer', ''), offset: v('integer', ''), virtual_address: v('integer', ''), physical_address: v('integer', ''), file_size: v('integer', ''), memory_size: v('integer', ''), alignment: v('integer', '') }, 'Segments.'),
    dynamic_section_entries: v('integer', ''),
    dynamic: a({ type: v('integer', ''), val: v('integer', '') }, ''),
    symtab_entries: v('integer', ''),
    symtab: a({ name: v('string', ''), value: v('integer', ''), size: v('integer', ''), type: v('integer', ''), bind: v('integer', ''), shndx: v('integer', '') }, 'Symbol table.'),
    dynsym_entries: v('integer', ''),
    dynsym: a({ name: v('string', ''), value: v('integer', ''), size: v('integer', ''), type: v('integer', ''), bind: v('integer', ''), shndx: v('integer', '') }, 'Dynamic symbols.'),
    telfhash: f('telfhash()', 'Trend Micro ELF hash.'),
    import_md5: f('import_md5()', 'MD5 of the imported symbols.'),
    ...consts(['ET_NONE', 'ET_REL', 'ET_EXEC', 'ET_DYN', 'ET_CORE'], 'Type: '),
    ...consts(['EM_NONE', 'EM_386', 'EM_X86_64', 'EM_ARM', 'EM_AARCH64', 'EM_MIPS', 'EM_PPC', 'EM_PPC64', 'EM_SPARC'], 'Machine: '),
    ...consts(['SHT_NULL', 'SHT_PROGBITS', 'SHT_SYMTAB', 'SHT_STRTAB', 'SHT_DYNAMIC', 'SHT_NOBITS', 'SHT_DYNSYM'], 'Section type: '),
    ...consts(['PT_NULL', 'PT_LOAD', 'PT_DYNAMIC', 'PT_INTERP', 'PT_NOTE', 'PT_PHDR', 'PT_TLS', 'PT_GNU_STACK'], 'Segment type: '),
};

const MATH = {
    entropy: f('entropy(offset, size) | entropy(string)', 'Shannon entropy (0 to 8).'),
    mean: f('mean(offset, size) | mean(string)', 'Mean of the bytes.'),
    deviation: f('deviation(offset, size, mean) | deviation(string, mean)', 'Mean deviation.'),
    serial_correlation: f('serial_correlation(offset, size) | serial_correlation(string)', 'Serial correlation coefficient.'),
    monte_carlo_pi: f('monte_carlo_pi(offset, size) | monte_carlo_pi(string)', 'Monte Carlo pi error.'),
    in_range: f('in_range(test, lower, upper)', 'True if lower <= test <= upper.'),
    count: f('count(byte [, offset, size])', 'Number of occurrences of a byte.'),
    percentage: f('percentage(byte [, offset, size])', 'Share of a byte (0.0 to 1.0).'),
    mode: f('mode([offset, size])', 'Most frequent byte.'),
    min: f('min(a, b)', 'Minimum of two integers.'),
    max: f('max(a, b)', 'Maximum of two integers.'),
    to_number: f('to_number(bool)', '1 for true, 0 for false.'),
    abs: f('abs(int)', 'Absolute value.'),
    to_string: f('to_string(int [, base])', 'Integer to string.'),
};

const HASH = {
    md5: f('md5(offset, size) | md5(string)', 'MD5 as a lowercase hex string.'),
    sha1: f('sha1(offset, size) | sha1(string)', 'SHA-1 as a lowercase hex string.'),
    sha256: f('sha256(offset, size) | sha256(string)', 'SHA-256 as a lowercase hex string.'),
    checksum32: f('checksum32(offset, size) | checksum32(string)', '32-bit checksum.'),
    crc32: f('crc32(offset, size) | crc32(string)', 'CRC32.'),
};

const DOTNET = {
    is_dotnet: v('integer', '1 if the file is a .NET assembly.'),
    version: v('string', 'Runtime version string.'),
    module_name: v('string', ''),
    guids: av('string', 'GUIDs.'), number_of_guids: v('integer', ''),
    streams: a({ name: v('string', ''), offset: v('integer', ''), size: v('integer', '') }, ''), number_of_streams: v('integer', ''),
    resources: a({ name: v('string', ''), offset: v('integer', ''), length: v('integer', '') }, ''), number_of_resources: v('integer', ''),
    assembly: s({ name: v('string', ''), culture: v('string', ''), version: s({ major: v('integer', ''), minor: v('integer', ''), build_number: v('integer', ''), revision_number: v('integer', '') }, '') }, ''),
    assembly_refs: a({ name: v('string', ''), public_key_or_token: v('string', ''), version: s({ major: v('integer', ''), minor: v('integer', ''), build_number: v('integer', ''), revision_number: v('integer', '') }, '') }, ''),
    number_of_assembly_refs: v('integer', ''),
    user_strings: av('string', 'User strings.'), number_of_user_strings: v('integer', ''),
    typelib: v('string', ''),
    classes: a({ fullname: v('string', ''), name: v('string', ''), namespace: v('string', ''), visibility: v('string', ''), type: v('string', '') }, ''),
    number_of_classes: v('integer', ''),
};

const TIME = { now: f('now()', 'Current time (epoch seconds).') };

const CONSOLE = {
    log: f('log(value) | log(message, value)', 'Print a value while scanning; always true.'),
    hex: f('hex(int) | hex(message, int)', 'Print an integer in hex; always true.'),
};

const STRING = {
    to_int: f('to_int(string [, base])', 'Parse an integer.'),
    length: f('length(string)', 'Length in bytes.'),
};

const MAGIC = {
    type: f('type()', 'libmagic description of the file.'),
    mime_type: f('mime_type()', 'MIME type of the file.'),
};

const MACHO = {
    magic: v('integer', ''), cputype: v('integer', ''), cpusubtype: v('integer', ''),
    filetype: v('integer', ''), ncmds: v('integer', ''), flags: v('integer', ''),
    entry_point: v('integer', ''), number_of_segments: v('integer', ''),
    segments: a({ segname: v('string', ''), vmaddr: v('integer', ''), vmsize: v('integer', ''), fileoff: v('integer', ''), fsize: v('integer', '') }, ''),
    file_index_for_arch: f('file_index_for_arch(cputype [, cpusubtype])', ''),
    entry_point_for_arch: f('entry_point_for_arch(cputype [, cpusubtype])', ''),
};

const LNK = {
    is_lnk: v('integer', '1 if the file is a Windows shortcut.'),
    creation_time: v('integer', ''), access_time: v('integer', ''), write_time: v('integer', ''),
    file_size: v('integer', ''), name_string: v('string', ''), relative_path: v('string', ''),
    working_dir: v('string', ''), command_line_arguments: v('string', ''), icon_location: v('string', ''),
    machine_id: v('string', ''),
};

export const MODULES = {
    pe: { doc: 'Windows PE files.', fields: PE },
    elf: { doc: 'ELF files.', fields: ELF },
    math: { doc: 'Mathematical functions over the file or a string.', fields: MATH },
    hash: { doc: 'Hashes of file ranges or strings.', fields: HASH },
    dotnet: { doc: '.NET assemblies.', fields: DOTNET },
    time: { doc: 'Current time.', fields: TIME },
    console: { doc: 'Debug output while scanning.', fields: CONSOLE },
    string: { doc: 'String helpers.', fields: STRING },
    magic: { doc: 'libmagic file type (not available on Windows builds).', fields: MAGIC },
    macho: { doc: 'Mach-O files.', fields: MACHO },
    lnk: { doc: 'Windows shortcut files.', fields: LNK },
    cuckoo: { doc: 'Cuckoo sandbox report (deprecated).', fields: {} },
    dex: { doc: 'Android DEX files.', fields: {} },
};

/**
 * Walk a member path like ["pe", "sections", "name"] (indexes removed).
 * Returns the node or null; for a module root returns {kind:'module', fields}.
 */
export function resolvePath(path) {
    const mod = MODULES[path[0]];
    if (!mod) return null;
    let node = { kind: 'module', fields: mod.fields, doc: mod.doc };
    for (const part of path.slice(1)) {
        const fields = node.fields;
        if (!fields || !fields[part]) return null;
        node = fields[part];
    }
    return node;
}

/** Fields under a node, for completion after a dot. */
export function childrenOf(node) {
    if (!node) return {};
    if (node.kind === 'module' || node.kind === 'struct' || node.kind === 'array') return node.fields || {};
    return {};
}
