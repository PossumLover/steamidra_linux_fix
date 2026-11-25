#!/usr/bin/env python3
"""Patch the depotkit that steamidra links (sizing on Linux, safety on Windows).

depotkit is compiled into steamidra_plugin.dll. Two bugs in that code become
an invalid write inside the plugin image when an owns-download decrypts
manifests (Valheim with a selected Steam DLC walks every lua depot):

* BCryptSetProperty writes through the chaining-mode buffer. The call sites
  passed a string literal, which lives in the plugin .rdata.
* Manifest section lengths were applied with pointer arithmetic before checking
  that the section fits in the file.
"""

from __future__ import annotations

import sys
from pathlib import Path

MARKER = "steamidra: writable bcrypt chain mode"


def patch_crypto(text: str) -> str:
    old = """    const wchar_t *chain = useCbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
    if (BCryptSetProperty(slot, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(chain)),
                          static_cast<ULONG>((wcslen(chain) + 1) * sizeof(wchar_t)), 0)"""
    new = f"""    // {MARKER}
    wchar_t chainBuf[32] = {{}};
    const wchar_t *chainLit = useCbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
    wcsncpy(chainBuf, chainLit, 31);
    chainBuf[31] = L'\\0';
    if (BCryptSetProperty(slot, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(chainBuf),
                          static_cast<ULONG>((wcslen(chainBuf) + 1) * sizeof(wchar_t)), 0)"""
    if old not in text:
        if MARKER in text:
            return text
        raise SystemExit("depot_crypto.cpp: BCryptSetProperty pattern missing")
    return text.replace(old, new, 1)


HELPER = f"""
// {MARKER}
// BCryptSetProperty writes into pbInput. A string literal is in the plugin
// image (.rdata) because this file is linked into steamidra_plugin.dll.
inline void setBcryptChainMode(BCRYPT_ALG_HANDLE alg, const wchar_t *literal)
{{
    wchar_t mode[32] = {{}};
    if (!alg || !literal)
        return;
    wcsncpy(mode, literal, 31);
    mode[31] = L'\\0';
    const ULONG bytes = static_cast<ULONG>((wcslen(mode) + 1) * sizeof(wchar_t));
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(mode), bytes, 0);
}}

"""


def patch_session(text: str) -> str:
    text2 = text
    for mode in ("BCRYPT_CHAIN_MODE_ECB", "BCRYPT_CHAIN_MODE_CBC"):
        old = (
            "    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, "
            f"reinterpret_cast<PUCHAR>(const_cast<wchar_t *>({mode})),\n"
            f"                      sizeof({mode}), 0);"
        )
        new = f"    setBcryptChainMode(alg, {mode});"
        if old not in text2:
            if "setBcryptChainMode" in text2:
                continue
            raise SystemExit(f"session.cpp: missing {mode} BCryptSetProperty")
        text2 = text2.replace(old, new)
    if "setBcryptChainMode" in text and HELPER.strip() in text:
        return text2
    anchor = "WinsockInit gWinsock;\n"
    if "inline void setBcryptChainMode" not in text2:
        if anchor not in text2:
            raise SystemExit("session.cpp: WinsockInit anchor missing")
        text2 = text2.replace(anchor, anchor + HELPER, 1)
    return text2


MANIFEST_OLD = """        if (magic == kProtoPayloadMagic) {
            const uint32_t len = c.u32();
            Cursor sub{c.p, c.p + len};
            c.p += len;
            parsePayload(m, sub);
        } else if (magic == kProtoMetadataMagic) {
            const uint32_t len = c.u32();
            Cursor sub{c.p, c.p + len};
            c.p += len;
            parseMetadata(m, sub);
        } else if (magic == kProtoSignatureMagic) {
            const uint32_t len = c.u32();
            c.skip(len);
        } else {"""

MANIFEST_NEW = """        if (magic == kProtoPayloadMagic || magic == kProtoMetadataMagic
            || magic == kProtoSignatureMagic) {
            const uint32_t len = c.u32();
            // Reject a length that runs past the file before any pointer add.
            // A wrapped length used to build a cursor into unrelated mapped
            // pages (including this DLL) and the decrypt path then wrote there.
            if (static_cast<size_t>(len) > c.left())
                throw std::runtime_error("manifest section truncated");
            if (magic == kProtoSignatureMagic) {
                c.skip(len);
            } else {
                Cursor sub{c.p, c.p + len};
                c.p += len;
                if (magic == kProtoPayloadMagic)
                    parsePayload(m, sub);
                else
                    parseMetadata(m, sub);
            }
        } else {"""


def patch_manifest(text: str) -> str:
    if "manifest section truncated" in text:
        return text
    if MANIFEST_OLD not in text:
        raise SystemExit("manifest.cpp: section parser pattern missing")
    return text.replace(MANIFEST_OLD, MANIFEST_NEW, 1)


FILE_LIST_PAYLOAD_MARKER = "steamidra: distinguish missing and empty file lists"
FILE_LIST_MANIFEST_HEADER_OLD = """    std::vector<FileInfo> files;
};"""
FILE_LIST_MANIFEST_HEADER_NEW = f"""    std::vector<FileInfo> files;
    // {FILE_LIST_PAYLOAD_MARKER}
    bool hasFileList = false;
}};"""
FILE_LIST_BINARY_OLD = """            parseBinaryManifest(m, c);
            // trailing marker"""
FILE_LIST_BINARY_NEW = """            parseBinaryManifest(m, c);
            m.hasFileList = true;
            // trailing marker"""
FILE_LIST_PAYLOAD_OLD = """                if (magic == kProtoPayloadMagic)
                    parsePayload(m, sub);
                else
                    parseMetadata(m, sub);"""
FILE_LIST_PAYLOAD_NEW = f"""                // {FILE_LIST_PAYLOAD_MARKER}
                if (magic == kProtoPayloadMagic) {{
                    parsePayload(m, sub);
                    m.hasFileList = true;
                }} else {{
                    parseMetadata(m, sub);
                }}"""


def patch_file_list_manifest_header(text: str) -> str:
    if FILE_LIST_PAYLOAD_MARKER in text:
        return text
    if FILE_LIST_MANIFEST_HEADER_OLD not in text:
        raise SystemExit("manifest.hpp: file list field pattern missing")
    return text.replace(FILE_LIST_MANIFEST_HEADER_OLD, FILE_LIST_MANIFEST_HEADER_NEW, 1)


def patch_file_list_manifest(text: str) -> str:
    if FILE_LIST_PAYLOAD_MARKER in text:
        return text
    if FILE_LIST_BINARY_OLD not in text or FILE_LIST_PAYLOAD_OLD not in text:
        raise SystemExit("manifest.cpp: file list section pattern missing")
    text = text.replace(FILE_LIST_BINARY_OLD, FILE_LIST_BINARY_NEW, 1)
    return text.replace(FILE_LIST_PAYLOAD_OLD, FILE_LIST_PAYLOAD_NEW, 1)


ENGINE_MARKER = "steamidra: size files to the manifest"
ENGINE_OLD = """    if (fileSize > 0) {
        slot.stream.seekp(static_cast<std::streamoff>(fileSize > 0 ? fileSize - 1 : 0));
        char zero = 0;
        slot.stream.write(&zero, 1);
        slot.stream.flush();
    }
#endif"""
ENGINE_NEW = """    // steamidra: size files to the manifest. Writing one byte at size-1 only ever
    // grows a file; one that shrank between builds kept its old tail, and the verify
    // could never fix it (wrong size -> re-download chunks -> still too long).
    // Enshrouded: enshrouded_000.dat 1'511'514'112 bytes, expected 1'060'708'352.
    // Unreal paks keep their index at the end, so Far Far West read empty files.
    // The Windows branch already truncates with SetEndOfFile.
    {
        std::error_code resizeEc;
        std::filesystem::resize_file(path, fileSize, resizeEc);
        if (resizeEc) {
            err = "cannot size " + path + ": " + resizeEc.message();
            return false;
        }
    }
#endif"""


def patch_engine(text: str) -> str:
    if ENGINE_MARKER in text:
        return text
    if ENGINE_OLD not in text:
        raise SystemExit("engine.cpp: openFileSlot sizing pattern missing")
    return text.replace(ENGINE_OLD, ENGINE_NEW, 1)


EMPTY_ENTRIES_MARKER = "steamidra: materialize empty manifest entries"
EMPTY_ENTRIES_OLD = r"""                if (f.flags & kFileFlagDirectory)
                    continue;
                ++totalFiles;
                seenBytes += f.size;
                std::string path = std::string(req->install_dir);
#if defined(_WIN32)
                if (!path.empty() && path.back() != '\\' && path.back() != '/')
                    path.push_back('\\');
#else
                if (!path.empty() && path.back() != '/')
                    path.push_back('/');
#endif
                path += f.filename;"""
EMPTY_ENTRIES_NEW = r"""                std::string path = std::string(req->install_dir);
#if defined(_WIN32)
                if (!path.empty() && path.back() != '\\' && path.back() != '/')
                    path.push_back('\\');
#else
                if (!path.empty() && path.back() != '/')
                    path.push_back('/');
#endif
                path += f.filename;""" + f"""
                // {EMPTY_ENTRIES_MARKER}
                if (f.flags & kFileFlagDirectory) {{
                    std::error_code ec;
                    std::filesystem::create_directories(std::filesystem::path(path), ec);
                    continue;
                }}
                ++totalFiles;
                seenBytes += f.size;
#if !defined(_WIN32)
                if (f.size == 0) {{
                    std::error_code ec;
                    const auto size = std::filesystem::file_size(path, ec);
                    if (size != 0 || ec) {{
                        bool ready = false;
                        if (!ec) {{
                            std::filesystem::resize_file(path, 0, ec);
                            ready = !ec;
                        }} else if (ec == std::errc::no_such_file_or_directory && ensureParentDir(path)) {{
                            std::ofstream emptyFile(path, std::ios::binary | std::ios::trunc);
                            emptyFile.close();
                            ready = static_cast<bool>(emptyFile);
                        }}
                        if (!ready) {{
                            const std::string detail = "cannot create or truncate " + path;
                            emit(onProgress, user,
                                 depotkit_progress{{completeBytes, seenBytes, 0, filesDone, totalFiles,
                                                   static_cast<uint32_t>(di),
                                                   static_cast<uint32_t>(req->depot_count),
                                                   DEPOTKIT_PHASE_ERROR, detail.c_str()}});
                            return DEPOTKIT_ERR_IO;
                        }}
                    }}
                    ++filesDone;
                    continue;
                }}
#endif"""


def patch_empty_entries(text: str) -> str:
    if EMPTY_ENTRIES_MARKER in text:
        return text
    if EMPTY_ENTRIES_OLD not in text:
        raise SystemExit("engine.cpp: manifest planning path pattern missing")
    return text.replace(EMPTY_ENTRIES_OLD, EMPTY_ENTRIES_NEW, 1)


CLOSE_SLOT_MARKER = "steamidra: check buffered writes at close"
CLOSE_SLOT_OLD = """void closeFileSlot(FileSlot &slot)
{
#if defined(_WIN32)
    if (slot.handle != INVALID_HANDLE_VALUE) {
        CloseHandle(slot.handle);
        slot.handle = INVALID_HANDLE_VALUE;
    }
#else
    if (slot.stream.is_open())
        slot.stream.close();
#endif
    slot.ready.store(false);
}"""
CLOSE_SLOT_NEW = f"""bool closeFileSlot(FileSlot &slot)
{{
    bool ok = true;
#if defined(_WIN32)
    if (slot.handle != INVALID_HANDLE_VALUE) {{
        CloseHandle(slot.handle);
        slot.handle = INVALID_HANDLE_VALUE;
    }}
#else
    // {CLOSE_SLOT_MARKER}
    if (slot.stream.is_open()) {{
        slot.stream.flush();
        ok = static_cast<bool>(slot.stream);
        slot.stream.close();
        ok = ok && static_cast<bool>(slot.stream);
    }}
#endif
    slot.ready.store(false);
    return ok;
}}"""

FINALIZE_SLOTS_OLD = """    {
        std::lock_guard lock(filesMu);
        for (auto &kv : fileSlots)
            closeFileSlot(*kv.second);
        fileSlots.clear();
    }"""
FINALIZE_SLOTS_NEW = """    bool closeFailed = false;
    {
        std::lock_guard lock(filesMu);
        for (auto &kv : fileSlots) {
            if (!closeFileSlot(*kv.second) && !failed.load() && !closeFailed) {
                closeFailed = true;
                failMsg = "cannot flush or close " + kv.first;
            }
        }
        fileSlots.clear();
    }"""

FINALIZE_RESULT_OLD = """    if (failed.load()) {
        emit(onProgress, user,
             depotkit_progress{bytesDone.load(), totalBytes, rate, filesDoneAtomic.load(), totalFiles, 0,
                               static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_ERROR,
                               failMsg.c_str()});
        return DEPOTKIT_ERR_NETWORK;
    }"""
FINALIZE_RESULT_NEW = FINALIZE_RESULT_OLD.replace(
    "if (failed.load())", "if (failed.load() || closeFailed)"
).replace(
    "return DEPOTKIT_ERR_NETWORK;", "return closeFailed ? DEPOTKIT_ERR_IO : DEPOTKIT_ERR_NETWORK;"
)


def patch_close_slot(text: str) -> str:
    if CLOSE_SLOT_MARKER in text:
        return text
    if CLOSE_SLOT_OLD not in text:
        raise SystemExit("engine.cpp: closeFileSlot pattern missing")
    if FINALIZE_SLOTS_OLD not in text:
        raise SystemExit("engine.cpp: file slot cleanup pattern missing")
    if FINALIZE_RESULT_OLD not in text:
        raise SystemExit("engine.cpp: download error result pattern missing")
    text = text.replace(CLOSE_SLOT_OLD, CLOSE_SLOT_NEW, 1)
    text = text.replace(FINALIZE_SLOTS_OLD, FINALIZE_SLOTS_NEW, 1)
    return text.replace(FINALIZE_RESULT_OLD, FINALIZE_RESULT_NEW, 1)


FILE_LIST_MARKER = "steamidra: expose shipped manifest entries"
FILE_LIST_HEADER_OLD = """                                                             uint32_t *out_flags);

#ifdef __cplusplus"""
FILE_LIST_HEADER_NEW = f"""                                                             uint32_t *out_flags);

/* {FILE_LIST_MARKER}. Path and SHA-1 are borrowed for the callback only. */
enum {{ DEPOTKIT_FILE_DIRECTORY = 0x40 }};
typedef void (*depotkit_file_fn)(const char *path, uint64_t size, const uint8_t *sha1,
                                 uint32_t flags, void *user);
DEPOTKIT_API depotkit_result depotkit_manifest_list_files(const char *manifest_path,
                                                          const char *key_hex,
                                                          depotkit_file_fn on_file,
                                                          void *user,
                                                          uint64_t *out_manifest_id,
                                                          uint32_t *out_depot_id);

#ifdef __cplusplus"""
FILE_LIST_API_OLD = """depotkit_result depotkit_manifest_platform_hint(const char *manifest_path, const char *key_hex,
                                                uint32_t *out_flags)
{
    if (!manifest_path || !out_flags)
        return DEPOTKIT_ERR_INVALID_ARG;
    *out_flags = 0;
    try {
        auto man = depotkit::loadManifestFile(manifest_path);
        if (key_hex && *key_hex) {
            auto key = depotkit::fromHex(key_hex);
            if (key.size() != 32)
                return DEPOTKIT_ERR_CRYPTO;
            depotkit::decryptManifestFilenames(man, key.data());
        }
        uint32_t win = 0, lin = 0, mac = 0;"""
FILE_LIST_API_NEW = f"""// {FILE_LIST_MARKER}
static depotkit_result loadManifestWithNames(const char *manifest_path, const char *key_hex,
                                              depotkit::Manifest &man)
{{
    man = depotkit::loadManifestFile(manifest_path);
    if (key_hex && *key_hex) {{
        auto key = depotkit::fromHex(key_hex);
        if (key.size() != 32 || !depotkit::decryptManifestFilenames(man, key.data()))
            return DEPOTKIT_ERR_CRYPTO;
    }}
    return DEPOTKIT_OK;
}}

depotkit_result depotkit_manifest_list_files(const char *manifest_path, const char *key_hex,
                                             depotkit_file_fn on_file, void *user,
                                             uint64_t *out_manifest_id,
                                             uint32_t *out_depot_id)
{{
    if (!manifest_path || !on_file)
        return DEPOTKIT_ERR_INVALID_ARG;
    try {{
        depotkit::Manifest man;
        const auto rc = loadManifestWithNames(manifest_path, key_hex, man);
        if (rc != DEPOTKIT_OK)
            return rc;
        if (!man.hasFileList)
            return DEPOTKIT_ERR_MANIFEST;
        if (man.filenamesEncrypted)
            return DEPOTKIT_ERR_CRYPTO;
        static_assert(DEPOTKIT_FILE_DIRECTORY == depotkit::kFileFlagDirectory);
        for (auto &f : man.files) {{
            if (f.filename.find('\\0') != std::string::npos)
                return DEPOTKIT_ERR_MANIFEST;
            // Report the name exactly as runDownload() joins it onto the install path.
            // decryptManifestFilenames() already turns '\\' into '/' for encrypted names;
            // a plaintext name that still has one is written verbatim on Linux, so the
            // caller must not map it onto a different, '/'-separated path.
            on_file(f.filename.c_str(), f.size,
                    f.contentHash.size() == 20 ? f.contentHash.data() : nullptr, f.flags, user);
        }}
        if (out_manifest_id)
            *out_manifest_id = man.manifestId;
        if (out_depot_id)
            *out_depot_id = man.depotId;
        return DEPOTKIT_OK;
    }} catch (...) {{
        return DEPOTKIT_ERR_MANIFEST;
    }}
}}

depotkit_result depotkit_manifest_platform_hint(const char *manifest_path, const char *key_hex,
                                                uint32_t *out_flags)
{{
    if (!manifest_path || !out_flags)
        return DEPOTKIT_ERR_INVALID_ARG;
    *out_flags = 0;
    try {{
        depotkit::Manifest man;
        const auto rc = loadManifestWithNames(manifest_path, key_hex, man);
        if (rc != DEPOTKIT_OK)
            return rc;
        uint32_t win = 0, lin = 0, mac = 0;"""


def patch_file_list_header(text: str) -> str:
    if FILE_LIST_MARKER in text:
        return text
    if FILE_LIST_HEADER_OLD not in text:
        raise SystemExit("depotkit.h: platform hint declaration pattern missing")
    return text.replace(FILE_LIST_HEADER_OLD, FILE_LIST_HEADER_NEW, 1)


def patch_file_list_api(text: str) -> str:
    if FILE_LIST_MARKER in text:
        return text
    if FILE_LIST_API_OLD not in text:
        raise SystemExit("api.cpp: platform hint loader pattern missing")
    return text.replace(FILE_LIST_API_OLD, FILE_LIST_API_NEW, 1)


def write_if_changed(path: Path, text: str) -> None:
    if path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: harden_depotkit.py DEPOTKIT_SRC")
    root = Path(sys.argv[1])
    crypto = root / "src" / "crypto" / "depot_crypto.cpp"
    session = root / "src" / "steam" / "session.cpp"
    manifest = root / "src" / "manifest" / "manifest.cpp"
    manifest_header = manifest.with_suffix(".hpp")
    engine = root / "src" / "engine" / "engine.cpp"
    header = root / "include" / "depotkit.h"
    api = root / "src" / "api.cpp"
    for p in (crypto, session, manifest, manifest_header, engine, header, api):
        if not p.is_file():
            raise SystemExit(f"missing {p}")
    write_if_changed(crypto, patch_crypto(crypto.read_text(encoding="utf-8")))
    write_if_changed(session, patch_session(session.read_text(encoding="utf-8")))
    manifest_text = patch_manifest(manifest.read_text(encoding="utf-8"))
    write_if_changed(manifest, patch_file_list_manifest(manifest_text))
    write_if_changed(manifest_header,
                     patch_file_list_manifest_header(manifest_header.read_text(encoding="utf-8")))
    engine_text = patch_engine(engine.read_text(encoding="utf-8"))
    engine_text = patch_empty_entries(engine_text)
    write_if_changed(engine, patch_close_slot(engine_text))
    write_if_changed(header, patch_file_list_header(header.read_text(encoding="utf-8")))
    write_if_changed(api, patch_file_list_api(api.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
