"""Dependency-free, bounded static APK parsing. Run only in the offline sandbox."""
# Source: https://github.com/zhcalvin/DeRea@7d4917b4e3c0acbbd1e1b384afb72024ecfbb860
# License: Apache-2.0 (see LICENSE and THIRD_PARTY_NOTICES.md)
import os
import stat

MAX_APK_BYTES = 64 * 1024 * 1024


def admit_apk_bytes(filename) -> bytes:
    """Windows/POSIX-safe host admission ported from packages/apk-inspector/src/index.ts:54-73.

    Rejects symlinks, Windows reparse points, non-regular files, sizes outside 22 B .. 64 MiB,
    and files mutated during bounded single-FD snapshot read. Raises ValueError on failure.
    """
    full = os.path.abspath(os.fspath(filename))
    try:
        st_link = os.lstat(full)
    except OSError as exc:
        raise ValueError(f"APK input does not exist or cannot be stat'd: {full}") from exc

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    is_reparse = bool(getattr(st_link, "st_file_attributes", 0) & reparse_flag)
    if stat.S_ISLNK(st_link.st_mode) or is_reparse or not stat.S_ISREG(st_link.st_mode):
        raise ValueError("APK input must be a non-symlink regular file")
    if st_link.st_size < 22 or st_link.st_size > MAX_APK_BYTES:
        raise ValueError("APK byte size must be between 22 bytes and 64 MiB")

    open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(full, open_flags)
    except OSError as exc:
        raise ValueError(f"Failed to open APK input safely: {exc}") from exc

    with os.fdopen(fd, "rb") as fh:
        before = os.fstat(fh.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != st_link.st_size:
            raise ValueError("APK changed during admission")
        if st_link.st_ino and before.st_ino and (before.st_dev != st_link.st_dev or before.st_ino != st_link.st_ino):
            raise ValueError("APK inode changed during admission")
        data = fh.read(before.st_size + 1)
        after = os.fstat(fh.fileno())
        if len(data) != before.st_size or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("APK changed while its bounded snapshot was read")
    return data

import hashlib
import json
import re
import stat
import struct
import sys
import zipfile
import zlib
from pathlib import PurePosixPath
from xml.etree import ElementTree


class InvalidApk(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidApk(message)


def u16(data, offset):
    require(0 <= offset <= len(data) - 2, "Truncated 16-bit field")
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    require(0 <= offset <= len(data) - 4, "Truncated 32-bit field")
    return struct.unpack_from('<I', data, offset)[0]


def string_pool(data, start, header, size):
    require(header >= 28, "Invalid Android string-pool header")
    count, styles, flags, strings_start, styles_start = struct.unpack_from('<5I', data, start + 8)
    require(count <= 20000 and styles <= 20000, "Android string-pool count exceeds limits")
    require(header + (count + styles) * 4 <= size and strings_start >= header + (count + styles) * 4, "Invalid Android string-pool offsets")
    stop = start + (styles_start if styles_start else size)
    require(start + strings_start <= stop <= start + size, "Invalid Android string-pool bounds")

    def length8(at):
        require(at < stop, "Truncated Android UTF-8 string length")
        first = data[at]
        if first & 0x80:
            require(at + 1 < stop, "Truncated Android UTF-8 string length")
            return ((first & 0x7f) << 8) | data[at + 1], at + 2
        return first, at + 1

    def length16(at):
        require(at + 2 <= stop, "Truncated Android UTF-16 string length")
        first = u16(data, at)
        if first & 0x8000:
            require(at + 4 <= stop, "Truncated Android UTF-16 string length")
            return ((first & 0x7fff) << 16) | u16(data, at + 2), at + 4
        return first, at + 2

    result = []
    for index in range(count):
        at = start + strings_start + u32(data, start + header + index * 4)
        require(start + strings_start <= at < stop, "Android string offset escapes its pool")
        if flags & 0x100:
            chars, at = length8(at)
            length, at = length8(at)
            require(chars <= 8192 and length <= 32768 and at + length < stop and data[at + length] == 0, "Invalid Android UTF-8 string bounds")
            value = data[at:at + length].decode('utf-8', 'strict')
            require(len(value.encode('utf-16-le')) // 2 == chars, "Android UTF-8 string length mismatch")
        else:
            length, at = length16(at)
            require(length <= 8192 and at + length * 2 + 2 <= stop and u16(data, at + length * 2) == 0, "Invalid Android UTF-16 string bounds")
            value = data[at:at + length * 2].decode('utf-16-le', 'strict')
        result.append(value)
    return result


def binary_manifest(data):
    require(len(data) >= 8 and u16(data, 0) == 3 and u16(data, 2) == 8 and u32(data, 4) == len(data), "Invalid Android binary XML document header")
    strings, stack, root, at, nodes = None, [], None, 8, 0

    def string(index):
        require(strings is not None and index < len(strings), "Android XML string reference is out of bounds")
        return strings[index]

    while at < len(data):
        require(at + 8 <= len(data), "Truncated Android XML chunk")
        kind, header, size = struct.unpack_from('<HHI', data, at)
        require(size >= header >= 8 and at + size <= len(data) and size % 4 == 0, "Invalid Android XML chunk bounds")
        if kind == 1:
            require(strings is None and not stack and root is None, "Duplicate or misplaced Android XML string pool")
            strings = string_pool(data, at, header, size)
        elif kind == 0x180:
            require(strings is not None and header == 8 and (size - header) % 4 == 0, "Invalid Android resource map")
        elif kind in (0x100, 0x101):
            require(strings is not None and header == 16 and size == 24, "Invalid Android XML namespace chunk")
            for offset in (16, 20):
                value = u32(data, at + offset)
                if value != 0xffffffff:
                    string(value)
        elif kind == 0x102:
            require(strings is not None and header == 16 and size >= 36, "Invalid Android XML start element")
            namespace, name = u32(data, at + 16), string(u32(data, at + 20))
            if namespace != 0xffffffff:
                string(namespace)
            attr_start, attr_size, count = struct.unpack_from('<3H', data, at + 24)
            require(attr_start >= 20 and attr_size >= 20 and count <= 256 and 16 + attr_start + count * attr_size <= size, "Invalid Android XML attributes")
            attrs = {}
            for index in range(count):
                attr = at + 16 + attr_start + index * attr_size
                ns, key, raw = struct.unpack_from('<3I', data, attr)
                key = string(key)
                if ns != 0xffffffff:
                    key = '{' + string(ns) + '}' + key
                require(key not in attrs and u16(data, attr + 12) == 8 and data[attr + 14] == 0, "Invalid or duplicate Android XML attribute")
                value_type, value_data = data[attr + 15], u32(data, attr + 16)
                if value_type == 3:
                    value = string(value_data)
                elif value_type == 0x12:
                    value = value_data != 0
                elif value_type in (0x10, 0x11):
                    value = value_data
                elif value_type in (1, 2):
                    value = '@0x%08x' % value_data
                else:
                    value = None
                if raw != 0xffffffff:
                    raw_value = string(raw)
                    if value_type not in (0x12, 0x10, 0x11):
                        value = raw_value
                attrs[key] = value
            node = {'name': name, 'attrs': attrs, 'children': []}
            if stack:
                stack[-1]['children'].append(node)
            else:
                require(root is None, "Multiple Android XML root elements")
                root = node
            stack.append(node)
            nodes += 1
            require(len(stack) <= 64 and nodes <= 10000, "Android XML structural limits exceeded")
        elif kind == 0x103:
            require(header == 16 and size == 24 and stack and stack[-1]['name'] == string(u32(data, at + 20)), "Mismatched Android XML end element")
            stack.pop()
        elif kind == 0x104:
            require(header == 16 and size == 28 and stack, "Invalid Android XML text chunk")
            string(u32(data, at + 16))
        else:
            raise InvalidApk("Unsupported Android XML chunk type")
        at += size
    require(root is not None and not stack and root['name'] == 'manifest', "Incomplete Android manifest")
    return root


ANDROID = '{http://schemas.android.com/apk/res/android}'


def parse_manifest(data):
    if data.startswith(b'\x03\x00'):
        root, fmt = binary_manifest(data), 'android-binary-xml'
    else:
        require(b'<!' not in data and len(data) <= 2 * 1024 * 1024, "XML declarations with entities or DTD are unsupported")
        element = ElementTree.fromstring(data)
        nodes = 0

        def convert(item, depth=0):
            nonlocal nodes
            nodes += 1
            require(depth <= 64 and nodes <= 10000 and len(item.attrib) <= 256, "Manifest XML structural limits exceeded")
            return {'name': item.tag, 'attrs': dict(item.attrib), 'children': [convert(child, depth + 1) for child in item]}
        root, fmt = convert(element), 'text-xml'
        require(root['name'] == 'manifest', "Manifest root must be manifest")

    def attr(node, name):
        return node['attrs'].get(ANDROID + name)

    def boolean(value):
        if value in (True, 'true', '1'):
            return True
        if value in (False, 'false', '0'):
            return False
        return value

    def sdk(value):
        if isinstance(value, str) and value.isdecimal():
            return int(value)
        return value

    sdk_nodes = [node for node in root['children'] if node['name'] == 'uses-sdk']
    apps = [node for node in root['children'] if node['name'] == 'application']
    require(len(sdk_nodes) <= 1 and len(apps) == 1, "Manifest must contain one application and at most one uses-sdk")
    min_sdk = sdk(attr(sdk_nodes[0], 'minSdkVersion')) if sdk_nodes else None
    target_sdk = sdk(attr(sdk_nodes[0], 'targetSdkVersion')) if sdk_nodes else None
    effective_target = target_sdk if target_sdk is not None else (min_sdk if min_sdk is not None else 1)
    permissions = [attr(node, 'name') for node in root['children'] if node['name'] in ('uses-permission', 'uses-permission-sdk-23')]
    require(len(permissions) <= 512, "Permission inventory exceeds limits")
    application = apps[0]
    settings = {key: boolean(attr(application, key)) for key in ('debuggable', 'allowBackup', 'usesCleartextTraffic', 'extractNativeLibs', 'networkSecurityConfig')}
    components = []
    for node in application['children']:
        if node['name'] not in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            continue
        exported = boolean(attr(node, 'exported'))
        filters = sum(child['name'] == 'intent-filter' for child in node['children'])
        effective = exported if isinstance(exported, bool) else 'unknown'
        if exported is None and isinstance(effective_target, int):
            if node['name'] == 'provider':
                effective = effective_target <= 16
            elif effective_target <= 30:
                effective = filters > 0
            elif filters == 0:
                effective = False
        components.append({'type': node['name'], 'name': attr(node, 'name'), 'exported': exported,
                           'exportedAttributePresent': ANDROID + 'exported' in node['attrs'],
                           'intentFilterCount': filters, 'permission': attr(node, 'permission'), 'effectiveExported': effective})
    require(len(components) <= 512, "Component inventory exceeds limits")
    return {'format': fmt, 'package': root['attrs'].get('package'), 'versionName': attr(root, 'versionName'),
            'versionCode': sdk(attr(root, 'versionCode')), 'minSdkVersion': min_sdk, 'targetSdkVersion': target_sdk,
            'permissions': sorted({value for value in permissions if isinstance(value, str)}),
            'application': settings, 'components': components}


def dex_metadata(data, name):
    require(len(data) >= 112 and re.fullmatch(b'dex\n0(?:3[5-9]|40)\x00', data[:8]), "Unsupported or malformed standard DEX header")
    require(u32(data, 32) == len(data) and u32(data, 36) == 112 and u32(data, 40) == 0x12345678, "Invalid DEX size, header, or endianness")
    require(u32(data, 8) == zlib.adler32(data[12:]) & 0xffffffff, "DEX Adler-32 header integrity mismatch")
    require(data[12:32] == hashlib.sha1(data[32:]).digest(), "DEX SHA-1 header integrity mismatch")
    data_size, data_offset = u32(data, 104), u32(data, 108)
    require(data_offset % 4 == 0 and (data_size == 0 and data_offset == 0 or data_offset >= 112 and data_offset + data_size == len(data)), "Invalid DEX data-section bounds")
    counts = {}
    tables = {}
    for label, field, width in [('strings', 56, 4), ('types', 64, 4), ('prototypes', 72, 12), ('fields', 80, 8), ('methods', 88, 8), ('classes', 96, 32)]:
        count, offset = u32(data, field), u32(data, field + 4)
        require(count <= 500000 and (count == 0 and offset == 0 or count > 0 and offset >= 112 and offset % 4 == 0 and offset + count * width <= len(data)), "Invalid DEX %s table bounds" % label)
        counts[label], tables[label] = count, offset
    ranges = sorted((tables[label], tables[label] + counts[label] * width) for label, width in [('strings', 4), ('types', 4), ('prototypes', 12), ('fields', 8), ('methods', 8), ('classes', 32)] if counts[label])
    require(all(previous[1] <= following[0] for previous, following in zip(ranges, ranges[1:])), "Overlapping DEX identifier tables")
    map_offset = u32(data, 52)
    require(map_offset >= data_offset and map_offset <= len(data) - 4 and map_offset % 4 == 0, "Invalid DEX map offset")
    map_count = u32(data, map_offset)
    require(map_count <= 256 and map_offset + 4 + map_count * 12 <= len(data), "Invalid DEX map bounds")
    require(counts['classes'] <= 50000, "DEX class count exceeds inspection limits")
    class_names = []
    for index in range(counts['classes']):
        definition = tables['classes'] + index * 32
        class_index = u32(data, definition)
        require(class_index < counts['types'], "DEX class type index is out of bounds")
        string_index = u32(data, tables['types'] + class_index * 4)
        require(string_index < counts['strings'], "DEX class string index is out of bounds")
        string_offset = u32(data, tables['strings'] + string_index * 4)
        require(data_offset <= string_offset < len(data), "DEX class string offset escapes data section")
        at, length = string_offset, 0
        for shift in range(0, 35, 7):
            require(at < len(data), "Truncated DEX class string length")
            byte = data[at]
            at += 1
            length |= (byte & 0x7f) << shift
            if byte < 0x80:
                break
        else:
            raise InvalidApk("Invalid DEX ULEB128 class string length")
        require(length <= 4096, "DEX class descriptor exceeds limits")
        end = data.find(b'\0', at, min(len(data), at + 16385))
        require(end >= at, "Unterminated DEX class descriptor")
        descriptor = data[at:end].decode('utf-8', 'surrogatepass')
        utf16 = descriptor.encode('utf-16-le', 'surrogatepass')
        descriptor = utf16.decode('utf-16-le', 'strict')
        require(len(utf16) // 2 == length and re.fullmatch(r'L[^\x00-\x20.;\[\]]+;', descriptor) and
                all(part for part in descriptor[1:-1].split('/')), "Invalid DEX class descriptor")
        if len(class_names) < 128:
            class_names.append(descriptor[1:-1].replace('/', '.'))
    return {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'version': data[4:7].decode('ascii'),
            'counts': counts, 'classNames': class_names, 'classNamesTruncated': counts['classes'] > 128,
            'headerIntegrity': {'adler32': True, 'sha1': True}}


def web_metadata(data, name, digest):
    kind = 'javascript' if name.lower().endswith(('.js', '.mjs', '.cjs')) else 'html'
    try:
        text = data.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        return {'path': name, 'bytes': len(data), 'sha256': digest, 'kind': kind, 'lines': 0, 'longestLine': 0, 'sourceVisibility': 'unknown'}
    lines = text.splitlines()
    longest = max((len(line) for line in lines), default=0)
    nonempty = [line for line in lines if line.strip()]
    indented = sum(bool(re.match(r'\s{2,}\S', line)) for line in nonempty)
    readable = (len(nonempty) >= 10 and indented >= 5 and len(text) / max(1, len(nonempty)) < 200 and
                bool(re.search(r'\bfunction\b|\bconst\b|\breturn\b|\bvar\b|\blet\b', text)))
    visibility = 'readable-source-like' if readable else ('compact-or-generated' if longest > 500 else 'unknown')
    return {'path': name, 'bytes': len(data), 'sha256': digest, 'kind': kind, 'lines': len(lines),
            'longestLine': longest, 'sourceVisibility': visibility}


def inspect(filename):
    archive_bytes = admit_apk_bytes(filename)
    report = {'schemaVersion': '1', 'analysisKind': 'apk-static-inspection', 'synthetic': False,
              'modelCalled': False, 'elfEvaluationSupported': False,
              'input': {'name': 'input.apk', 'sha256': hashlib.sha256(archive_bytes).hexdigest(), 'bytes': len(archive_bytes)},
              'archive': {}, 'manifest': None, 'dex': [], 'nativeLibraries': [], 'findings': [], 'warnings': [],
              'web': {'javascriptCount': 0, 'htmlCount': 0, 'javascriptBytes': 0, 'htmlBytes': 0, 'assets': [], 'inventoryTruncated': False},
              'limitations': [
                  'Static APK metadata and source-visibility observations do not measure functional reconstruction or protection effectiveness.',
                  'No app, DEX bytecode, JavaScript, native library, installation, or Android runtime behavior was executed.',
                  'No model was called; no security score, reconstruction attempt, or functional-equivalence result is produced.',
                  'APK signature blocks and certificate validity are not verified; DEX header checks are not APK signature validation.',
                  'Manifest resource references are not resolved; exported defaults are reported only where the SDK and declarations permit inference.',
                  'JavaScript source visibility is a bounded formatting heuristic, not proof that all application logic or secrets are exposed.',
                  'Only standard DEX versions 035 through 040 and bounded XML/ZIP structures are supported; arbitrary DEX strings are not emitted.',
                  'APK input is outside the Linux/amd64 ELF JSONL functional benchmark contract.',
              ]}
    from io import BytesIO
    with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 4096, "APK ZIP entry count exceeds limits")
        seen, file_paths, total, compressed, file_count, inventory = set(), set(), 0, 0, 0, []
        for entry in entries:
            name = entry.filename
            require(name == entry.orig_filename and name and len(name.encode('utf-8')) <= 1024 and not any(ord(char) < 32 or ord(char) == 127 for char in name), "Unsafe ZIP filename")
            require('\\' not in name and '\x00' not in name and not name.startswith('/') and ':' not in name, "Unsafe ZIP path")
            parts = name.rstrip('/').split('/')
            require(parts and all(part not in ('', '.', '..') for part in parts) and not PurePosixPath(name).is_absolute(), "ZIP path traversal or ambiguous path")
            normalized = '/'.join(parts)
            require(normalized not in seen, "Duplicate ZIP path")
            require(not any('/'.join(parts[:index]) in file_paths for index in range(1, len(parts))), "ZIP file/directory path collision")
            require(entry.is_dir() or not any(prior.startswith(normalized + '/') for prior in seen), "ZIP file/directory path collision")
            seen.add(normalized)
            mode = entry.external_attr >> 16
            require(not stat.S_ISLNK(mode) and (stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)), "ZIP links or special files are forbidden")
            require(not entry.flag_bits & 1 and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "Encrypted or unsupported ZIP compression")
            require(entry.file_size <= 16 * 1024 * 1024 and entry.compress_size <= 64 * 1024 * 1024, "ZIP member size exceeds limits")
            require(entry.file_size <= max(1, entry.compress_size) * 200, "ZIP expansion ratio exceeds limits")
            total += entry.file_size
            compressed += entry.compress_size
            require(total <= 128 * 1024 * 1024, "ZIP expanded total exceeds limits")
            if entry.is_dir():
                require(entry.file_size == 0, "ZIP directory contains file payload")
                continue
            file_count += 1
            file_paths.add(normalized)
            selected = name == 'AndroidManifest.xml' or name.lower().endswith(('.dex', '.js', '.mjs', '.cjs', '.html', '.htm', '.so'))
            digest, retained, actual = hashlib.sha256(), [], 0
            with archive.open(entry, 'r') as member:
                while True:
                    chunk = member.read(65536)
                    if not chunk:
                        break
                    actual += len(chunk)
                    require(actual <= entry.file_size and actual <= 16 * 1024 * 1024, "ZIP member expanded beyond its declared limit")
                    digest.update(chunk)
                    if selected:
                        retained.append(chunk)
            require(actual == entry.file_size, "ZIP member size mismatch")
            digest = digest.hexdigest()
            if len(inventory) < 512:
                inventory.append({'path': name, 'bytes': actual, 'compressedBytes': entry.compress_size, 'sha256': digest})
            data = b''.join(retained)
            if name == 'AndroidManifest.xml':
                require(actual <= 2 * 1024 * 1024, "Manifest exceeds inspection limit")
                report['manifest'] = parse_manifest(data)
            elif name.lower().endswith('.dex'):
                require(len(report['dex']) < 32, "DEX file count exceeds inspection limits")
                report['dex'].append(dex_metadata(data, name))
            elif name.lower().endswith(('.js', '.mjs', '.cjs', '.html', '.htm')):
                web = web_metadata(data, name, digest)
                kind = web['kind']
                report['web'][kind + 'Count'] += 1
                report['web'][kind + 'Bytes'] += actual
                if len(report['web']['assets']) < 256:
                    report['web']['assets'].append(web)
                else:
                    report['web']['inventoryTruncated'] = True
            elif name.lower().endswith('.so'):
                require(len(data) >= 20 and data[:4] == b'\x7fELF' and data[4] in (1, 2) and data[5] in (1, 2) and data[6] == 1, "Malformed native ELF library header")
                elf_size = 52 if data[4] == 1 else 64
                endian = 'little' if data[5] == 1 else 'big'
                require(len(data) >= elf_size and int.from_bytes(data[40:42] if data[4] == 1 else data[52:54], endian) == elf_size,
                        "Truncated or inconsistent native ELF header size")
                require(len(report['nativeLibraries']) < 256, "Native library count exceeds inspection limits")
                report['nativeLibraries'].append({'path': name, 'abi': parts[1] if len(parts) == 3 and parts[0] == 'lib' else None,
                                                  'elfClass': 32 if data[4] == 1 else 64, 'endianness': 'little' if data[5] == 1 else 'big',
                                                  'machine': int.from_bytes(data[18:20], 'little' if data[5] == 1 else 'big'), 'bytes': actual})
        require(report['manifest'] is not None, "APK has no AndroidManifest.xml")
        report['archive'] = {'entryCount': len(entries), 'fileCount': file_count, 'totalUncompressedBytes': total,
                             'totalCompressedBytes': compressed, 'files': inventory, 'inventoryTruncated': file_count > 512}
    readable = [asset for asset in report['web']['assets'] if asset['kind'] == 'javascript' and asset['sourceVisibility'] == 'readable-source-like']
    if readable:
        report['findings'].append({'code': 'APK_READABLE_JAVASCRIPT', 'title': 'Readable JavaScript assets are packaged in the APK',
                                   'evidence': ['%s: %d bytes, %d lines, SHA-256 %s' % (item['path'], item['bytes'], item['lines'], item['sha256']) for item in readable[:16]],
                                   'interpretation': 'These actual APK members contain multiline, indented JavaScript with readable language structure. This exposes packaged source-like logic to static inspection; it does not establish full reconstruction or reveal runtime-only behavior.'})
    if not report['dex']:
        report['warnings'].append('No DEX member was found; no claim about executable app completeness is made.')
    return report


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, "Expected exactly one staged APK input")
        print(json.dumps({'ok': True, 'report': inspect(sys.argv[1])}, ensure_ascii=True, separators=(',', ':')))
    except (InvalidApk, ValueError, IndexError, KeyError, struct.error, zipfile.BadZipFile, zipfile.LargeZipFile,
            zlib.error, NotImplementedError, ElementTree.ParseError, UnicodeError, OSError, EOFError, RuntimeError) as error:
        # Never echo target strings, XML content, or exception text that may contain secrets.
        message = str(error) if isinstance(error, InvalidApk) else 'Malformed or unsupported APK structure'
        print(json.dumps({'ok': False, 'error': {'code': 'APK_INVALID', 'message': message}}))
        sys.exit(2)


def admit_and_inspect_apk(filename) -> dict:
    try:
        rep = inspect(filename)
    except InvalidApk as exc:
        raise ValueError(str(exc)) from exc
    except (
        UnicodeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
        struct.error,
        ElementTree.ParseError,
        EOFError,
        NotImplementedError,
        IndexError,
        KeyError,
        RuntimeError,
        OSError,
    ) as exc:
        raise ValueError("Malformed or unsupported APK structure") from exc
    except ValueError as exc:
        if str(exc).startswith(("APK ", "Failed to open APK input safely:")):
            raise
        raise ValueError("Malformed or unsupported APK structure") from exc
    app_cfg = (rep.get("manifest") or {}).get("application") or {}
    for item in rep.get("findings", []):
        item.setdefault("severity", "medium")
    if app_cfg.get("debuggable") is True:
        rep["findings"].append(
            {
                "code": "APK_DEBUGGABLE",
                "severity": "high",
                "title": "Android application manifest has android:debuggable=true",
                "evidence": ["AndroidManifest.xml application@debuggable=true"],
            }
        )
    if app_cfg.get("usesCleartextTraffic") is True:
        rep["findings"].append(
            {
                "code": "APK_CLEARTEXT_TRAFFIC",
                "severity": "medium",
                "title": "Android application manifest permits cleartext HTTP traffic",
                "evidence": ["AndroidManifest.xml application@usesCleartextTraffic=true"],
            }
        )
    return rep
