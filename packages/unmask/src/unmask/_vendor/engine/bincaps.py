"""Binary capability inference from import/symbol tables.

Pure-Python, zero-dependency parsers for the three native formats (ELF, PE,
Mach-O) that extract the imported symbol names and the linked libraries, then map
those APIs to judgment-free capability atoms (network, exec, dynamic-load, crypto,
filesystem, registry, persistence, privilege). Imported APIs indicate a capability
is PRESENT, not that it is used, so the observations are emitted at modest
confidence and say so.

Why hand-rolled rather than a library: this code runs on potentially hostile
binaries, so it avoids a large native parser's attack surface, stays dependency-
free, and bounds every read. Anything it cannot parse cleanly degrades to no
capability atoms (the strings / entropy / structure triage still applies). It
never executes the target.
"""

from __future__ import annotations

import struct

from .model import Observation

_MAX_SYMBOLS = 8000     # cap symbols parsed per artifact
_MAX_NAME = 256         # cap a single symbol/lib name length
_MAX_LIST = 4000        # cap total names collected

# Imported-API -> capability atom. Ordered: more specific patterns win. Substrings
# are matched against the normalized symbol (leading underscores and "@version"
# suffix stripped, lowercased). Atoms are mechanical; the lens assigns meaning.
_CAP_MAP = [
    (("virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
      "ptrace", "task_for_pid"), "EXEC.INJECT", "process-injection primitive"),
    (("system", "popen", "shellexecute", "winexec"), "EXEC.SHELL",
     "spawns a shell or runs a command line"),
    (("execve", "execvp", "execl", "execlp", "posix_spawn", "createprocessa",
      "createprocessw"), "EXEC.PROC", "creates or replaces a process"),
    (("dlopen", "dlsym", "loadlibrarya", "loadlibraryw", "getprocaddress"),
     "LOAD.DYNAMIC", "loads a library or resolves symbols at runtime"),
    (("socket", "connect", "gethostbyname", "getaddrinfo", "wsasocket", "wsastartup",
      "internetopen", "internetconnect", "httpsendrequest", "urldownloadtofile",
      "winhttpopen", "curl_easy_init", "inet_addr", "inet_pton", "recvfrom", "sendto"),
     "NETW.SOCKET", "opens network sockets or connections"),
    (("regsetvalue", "regcreatekey", "regopenkey", "regqueryvalue", "regdeletekey"),
     "SYSI.REGISTRY", "reads or writes the Windows registry"),
    (("createservicea", "createservicew", "startservice", "openscmanager"),
     "PRST.SERVICE", "installs or controls a service"),
    (("setuid", "seteuid", "adjusttokenprivileges", "openprocesstoken",
      "lookupprivilegevalue"), "PRIV.ELEVATE", "changes process privilege or token"),
    (("cryptacquirecontext", "cryptencrypt", "bcryptencrypt", "evp_encrypt",
      "evp_decrypt", "ssl_connect", "ssl_new", "ssl_write"), "XFRM.ENCRYPT",
     "cryptographic primitive"),
    (("writefile", "createfilea", "createfilew", "fwrite", "unlink", "deletefilea",
      "deletefilew"), "FSYS.WRITE", "writes or deletes files"),
    (("readfile", "fread", "opendir", "readdir", "findfirstfilea", "fopen"),
     "FSYS.READ", "reads files or directories"),
]


def _norm(name: str) -> str:
    name = name.split("@", 1)[0].lstrip("_")
    return name.lower()


def classify_symbol(name: str):
    """Map an imported symbol name to (atom, description), or None."""
    n = _norm(name)
    if not n:
        return None
    for needles, atom, desc in _CAP_MAP:
        if any(s in n for s in needles):
            return (atom, desc)
    return None


def _cstr(data: bytes, off: int, cap: int = _MAX_NAME) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + cap)
    if end == -1:
        end = min(off + cap, len(data))
    return data[off:end].decode("ascii", "replace")


# --------------------------------------------------------------------------- ELF
def _parse_elf(data: bytes):
    if data[:4] != b"\x7fELF":
        return [], []
    is64 = data[4] == 2
    en = "<" if data[5] == 1 else ">"
    try:
        if is64:
            e_shoff = struct.unpack_from(en + "Q", data, 0x28)[0]
            shentsize, shnum = struct.unpack_from(en + "HH", data, 0x3a)
        else:
            e_shoff = struct.unpack_from(en + "I", data, 0x20)[0]
            shentsize, shnum = struct.unpack_from(en + "HH", data, 0x2e)
    except struct.error:
        return [], []
    if not e_shoff or shnum == 0 or shnum > 4000:
        return [], []

    # collect (type, offset, size, link, entsize) per section
    secs = []
    for i in range(shnum):
        base = e_shoff + i * shentsize
        try:
            if is64:
                sh_type = struct.unpack_from(en + "I", data, base + 4)[0]
                sh_offset, sh_size = struct.unpack_from(en + "QQ", data, base + 24)
                sh_link = struct.unpack_from(en + "I", data, base + 40)[0]
                sh_entsize = struct.unpack_from(en + "Q", data, base + 56)[0]
            else:
                sh_type = struct.unpack_from(en + "I", data, base + 4)[0]
                sh_offset, sh_size = struct.unpack_from(en + "II", data, base + 16)
                sh_link = struct.unpack_from(en + "I", data, base + 24)[0]
                sh_entsize = struct.unpack_from(en + "I", data, base + 36)[0]
        except struct.error:
            return secs and _elf_finish(data, is64, en, secs) or ([], [])
        secs.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    return _elf_finish(data, is64, en, secs)


def _elf_finish(data, is64, en, secs):
    imports, libs = [], []
    sym_entsize = 24 if is64 else 16
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in secs:
        if sh_type == 11 and 0 <= sh_link < len(secs):  # SHT_DYNSYM -> .dynstr via sh_link
            stroff = secs[sh_link][1]
            esize = sh_entsize or sym_entsize
            n = min(sh_size // esize, _MAX_SYMBOLS) if esize else 0
            for k in range(n):
                base = sh_offset + k * esize
                try:
                    if is64:
                        st_name = struct.unpack_from(en + "I", data, base)[0]
                        st_shndx = struct.unpack_from(en + "H", data, base + 6)[0]
                    else:
                        st_name = struct.unpack_from(en + "I", data, base)[0]
                        st_shndx = struct.unpack_from(en + "H", data, base + 14)[0]
                except struct.error:
                    break
                if st_shndx == 0 and st_name:  # SHN_UNDEF + named == imported
                    nm = _cstr(data, stroff + st_name)
                    if nm and len(imports) < _MAX_LIST:
                        imports.append(nm)
        elif sh_type == 6 and 0 <= sh_link < len(secs):  # SHT_DYNAMIC -> DT_NEEDED libs
            stroff = secs[sh_link][1]
            esize = 16 if is64 else 8
            n = min((sh_size // esize) if esize else 0, 2000)
            for k in range(n):
                base = sh_offset + k * esize
                try:
                    d_tag, d_val = struct.unpack_from(en + ("QQ" if is64 else "II"), data, base)
                except struct.error:
                    break
                if d_tag == 0:  # DT_NULL terminates
                    break
                if d_tag == 1:  # DT_NEEDED
                    nm = _cstr(data, stroff + d_val)
                    if nm and len(libs) < 200:
                        libs.append(nm)
    return imports, libs


# ---------------------------------------------------------------------------- PE
def _parse_pe(data: bytes):
    if data[:2] != b"MZ":
        return [], []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return [], []
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", data, coff + 2)[0]
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is_plus = magic == 0x20b
        ddir = opt + (112 if is_plus else 96)
        import_rva = struct.unpack_from("<I", data, ddir + 8)[0]  # data dir index 1
        if not import_rva:
            return [], []
        sec_off = opt + size_opt
        sections = []
        for i in range(min(nsec, 96)):
            b = sec_off + i * 40
            va, = struct.unpack_from("<I", data, b + 12)
            vsize, = struct.unpack_from("<I", data, b + 8)
            rawptr, = struct.unpack_from("<I", data, b + 20)
            rawsize, = struct.unpack_from("<I", data, b + 16)
            sections.append((va, max(vsize, rawsize), rawptr))
    except struct.error:
        return [], []

    def rva2off(rva):
        for va, size, rawptr in sections:
            if va <= rva < va + size:
                return rawptr + (rva - va)
        return None

    imports, libs = [], []
    thunk_sz = 8 if is_plus else 4
    ord_flag = (1 << 63) if is_plus else (1 << 31)
    desc_off = rva2off(import_rva)
    if desc_off is None:
        return [], []
    for d in range(200):  # import descriptors, terminated by all-zero
        b = desc_off + d * 20
        try:
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, b)
        except struct.error:
            break
        if not (oft or name_rva or ft):
            break
        dll = _cstr(data, rva2off(name_rva) or -1)
        if dll and len(libs) < 200:
            libs.append(dll)
        toff = rva2off(oft or ft)
        if toff is None:
            continue
        for t in range(2000):
            try:
                thunk = struct.unpack_from("<Q" if is_plus else "<I", data, toff + t * thunk_sz)[0]
            except struct.error:
                break
            if not thunk:
                break
            if thunk & ord_flag:
                continue  # imported by ordinal, no name
            noff = rva2off(thunk & 0x7fffffff)
            if noff is None:
                continue
            nm = _cstr(data, noff + 2)  # skip the 2-byte Hint
            if nm and len(imports) < _MAX_LIST:
                imports.append(nm)
    return imports, libs


# ------------------------------------------------------------------------ Mach-O
_MACHO_THIN = {b"\xcf\xfa\xed\xfe": (True, "<"), b"\xce\xfa\xed\xfe": (False, "<"),
               b"\xfe\xed\xfa\xcf": (True, ">"), b"\xfe\xed\xfa\xce": (False, ">")}


def _parse_macho(data: bytes):
    magic = data[:4]
    # fat binary: jump to the first architecture slice
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        en = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        try:
            nfat = struct.unpack_from(en + "I", data, 4)[0]
            if nfat:
                off = struct.unpack_from(en + "I", data, 8 + 8)[0]  # fat_arch[0].offset
                return _parse_macho(data[off:off + _max_slice(data, off)])
        except struct.error:
            return [], []
        return [], []
    if magic not in _MACHO_THIN:
        return [], []
    is64, en = _MACHO_THIN[magic]
    try:
        ncmds = struct.unpack_from(en + "I", data, 16)[0]
    except struct.error:
        return [], []
    p = 32 if is64 else 28
    imports, libs = [], []
    for _ in range(min(ncmds, 4000)):
        try:
            cmd, cmdsize = struct.unpack_from(en + "II", data, p)
        except struct.error:
            break
        if cmdsize < 8:
            break
        if cmd in (0xc, 0x8000001f, 0x80000018):  # LC_LOAD_DYLIB / REEXPORT / WEAK
            try:
                name_ofs = struct.unpack_from(en + "I", data, p + 8)[0]
            except struct.error:
                name_ofs = 0
            nm = _cstr(data, p + name_ofs) if name_ofs else ""
            if nm and len(libs) < 200:
                libs.append(nm.rsplit("/", 1)[-1])
        elif cmd == 0x2:  # LC_SYMTAB
            try:
                symoff, nsyms, stroff, _ = struct.unpack_from(en + "IIII", data, p + 8)
            except struct.error:
                symoff = nsyms = stroff = 0
            nlist_sz = 16 if is64 else 12
            for k in range(min(nsyms, _MAX_SYMBOLS)):
                b = symoff + k * nlist_sz
                try:
                    n_strx = struct.unpack_from(en + "I", data, b)[0]
                    n_type = struct.unpack_from(en + "B", data, b + 4)[0]
                except struct.error:
                    break
                # undefined (N_UNDF) external (N_EXT) == imported
                if (n_type & 0x0e) == 0 and (n_type & 0x01) and n_strx:
                    nm = _cstr(data, stroff + n_strx)
                    if nm and len(imports) < _MAX_LIST:
                        imports.append(nm)
        p += cmdsize
    return imports, libs


def _max_slice(data, off):
    return max(0, len(data) - off)


# --------------------------------------------------------------------------- API
def analyze(data: bytes, relpath: str):
    """Return (imports, libraries, observations). Detects the native format,
    extracts imported symbols + libraries, and emits one capability observation
    per inferred atom. Returns ([], [], []) for anything it cannot parse."""
    try:
        if data[:4] == b"\x7fELF":
            imports, libs = _parse_elf(data)
        elif data[:2] == b"MZ":
            imports, libs = _parse_pe(data)
        elif data[:4] in _MACHO_THIN or data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            imports, libs = _parse_macho(data)
        else:
            return [], [], []
    except Exception:
        return [], [], []

    # group imported symbols by inferred capability atom
    by_atom = {}
    for sym in imports:
        hit = classify_symbol(sym)
        if hit:
            by_atom.setdefault(hit, []).append(sym)

    obs = []
    for (atom, desc), syms in sorted(by_atom.items()):
        examples = ", ".join(sorted(set(syms))[:6])
        obs.append(Observation(
            atom=atom, method="binary-imports", confidence=0.55, path=relpath,
            rule_id="binary.imports",
            summary=f"imports {len(syms)} symbol(s) ({examples}): {desc} "
                    "(capability present, not proven used)"))
    return imports, libs, obs
