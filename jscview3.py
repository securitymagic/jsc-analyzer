import sys
import re
import base64
import json
import math
import struct

def read_u32_le(b):
    return struct.unpack("<I", b)[0]

# Common V8 or Bytenode magic values
KNOWN_MAGIC_BYTES = {
    "bytenode": b'\x28\x06\xDE\xC0',        # Bytenode-specific
    "v8_zero": b'\x00\x00\x00\x00',         # Sometimes used as filler
    "v8_old": b'\x73\x01\x00\x00',          # Older V8 versions (Node 8.x)
    "v8_v9":  b'\x73\x02\x00\x00',          # Node 9.x
    "v8_v10": b'\x73\x03\x00\x00',          # Node 10.x
    "v8_v11": b'\x73\x04\x00\x00',          # Node 11.x
    "v8_v12": b'\x73\x05\x00\x00',          # Node 12.x
    "v8_v13": b'\x73\x06\x00\x00',          # Node 13.x
    "v8_v14": b'\x73\x07\x00\x00',          # Node 14.x
    "v8_v15": b'\x73\x08\x00\x00',          # Node 15.x
    "v8_v16": b'\x73\x09\x00\x00',          # Node 16.x
    "v8_v17": b'\x73\x0A\x00\x00',          # Node 17.x
    "v8_v18": b'\x73\x0B\x00\x00',          # Node 18.x
    "v8_v20": b'\x73\x0D\x00\x00',          # Node 20.x
    "custom_like": b'\x73\x06\xDE\xC0',     # Custom / mutated variant
}
# Extended V8 opcode table (partial)
V8_OPCODES = {
    0x01: "Wide",
    0x02: "ExtraWide",
    0x03: "DebugBreak",
    0x04: "StackCheck",
    0x05: "Throw",
    0x06: "ReThrow",
    0x07: "Return",
    0x08: "Jump",
    0x09: "JumpIfTrue",
    0x0a: "JumpIfFalse",
    0x20: "LdaZero",
    0x21: "LdaSmi",
    0x22: "LdaUndefined",
    0x23: "LdaNull",
    0x24: "LdaTheHole",
    0x25: "LdaTrue",
    0x26: "LdaFalse",
    0x2f: "Add",
    0x30: "Sub",
    0x31: "Mul",
    0x32: "Div",
    0x33: "Mod",
    0x34: "Exp",
    0x35: "BitwiseOr",
    0x36: "BitwiseXor",
    0x37: "BitwiseAnd",
    0x38: "ShiftLeft",
    0x39: "ShiftRight",
    0x3a: "ShiftRightLogical",
    0x5e: "CallProperty1",
    0x97: "CallRuntime"
}

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def extract_ascii_strings(buf, min_len=4):
    return [s.decode('utf-8', errors='ignore') for s in re.findall(rb'[\x20-\x7e]{%d,}' % min_len, buf)]

def extract_utf16le_strings(buf, min_len=4):
    pattern = re.compile((rb'(?:[\x20-\x7e]\x00){%d,}' % min_len))
    matches = pattern.findall(buf)
    return [m.decode('utf-16le', errors='ignore') for m in matches]

def recursive_base64_decode(s, depth=3):
    try:
        for _ in range(depth):
            s = base64.b64decode(s)
        return s.decode('utf-8', errors='ignore')
    except:
        return None

def extract_base64(buf):
    strings = re.findall(rb'[A-Za-z0-9+/]{20,}={0,2}', buf)
    decoded = []
    for s in strings:
        try:
            base = s.decode()
            layer1 = base64.b64decode(base)
            try:
                layer1_decoded = layer1.decode('utf-8', errors='ignore')
                decoded.append((base, layer1_decoded))
            except:
                pass
            layer2 = recursive_base64_decode(base)
            if layer2 and (base, layer2) not in decoded:
                decoded.append((base, layer2))
        except Exception:
            continue
    return decoded

def extract_json_strings(strings):
    found = []
    for s in strings:
        try:
            if s.startswith("{") or s.startswith("["):
                obj = json.loads(s)
                found.append(obj)
        except:
            continue
    return found

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def detect_dangerous_patterns(strings):
    keywords = ['eval', 'Function', 'fromCharCode', 'atob', 'unescape', 'child_process', 'require', 'spawn', 'exec', 'net', 'fs', 'crypto']
    found = set()
    for s in strings:
        for k in keywords:
            if k in s:
                found.add((k, s))
    return found

def detect_encoded_js(buf):
    hex_escapes = re.findall(rb'(\\x[0-9a-fA-F]{2}){4,}', buf)
    uni_escapes = re.findall(rb'(\\u[0-9a-fA-F]{4}){4,}', buf)
    return hex_escapes, uni_escapes

def hex_dump(buf, start=0, count=256):
    for i in range(start, min(start + count, len(buf)), 16):
        chunk = buf[i:i+16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{i:08x}  {hex_bytes:<47}  {printable}")

def disassemble_opcodes(buf, max_instructions=64):
    print("\n[+] V8 Disassembly (best-effort):")
    i = 0
    count = 0
    while i < len(buf) and count < max_instructions:
        opcode = buf[i]
        mnemonic = V8_OPCODES.get(opcode, f"Unknown_0x{opcode:02x}")
        if mnemonic.startswith("Unknown") or mnemonic == "Illegal":
            i += 1
            continue
        print(f"  0x{i:04x}: {mnemonic} (0x{opcode:02x})")
        i += 1
        count += 1

def find_v8_magic_offset(buf):
    patterns = list(KNOWN_MAGIC_BYTES.values())
    for pattern in patterns:
        idx = buf.find(pattern)
        if idx != -1:
            return idx
    return -1

def xor_bruteforce_v8(buf):
    print("\n[?] Trying XOR brute-force for V8 magic...")
    for key in range(1, 256):
        xored = bytes(b ^ key for b in buf)
        offset = find_v8_magic_offset(xored)
        if offset != -1:
            print(f"[+] XOR key 0x{key:02x} revealed V8 bytecode at offset 0x{offset:x}")
            return True
    print("[-] No XOR key revealed a valid V8 header.")
    return False

def analyze_jsc(path):
    raw = read_file(path)

    print(f"[+] Analyzing: {path}")
    print(f"[+] File size: {len(raw)} bytes")
    magic = raw[:4]
    print(f"[+] Magic: {magic.hex()}")

    for name, val in KNOWN_MAGIC_BYTES.items():
        if magic == val:
            print(f"[*] Known magic match: {name}")

    ascii_strings = extract_ascii_strings(raw)
    utf16_strings = extract_utf16le_strings(raw)
    all_strings = ascii_strings + utf16_strings

    print(f"\n[+] ASCII strings: {len(ascii_strings)}")
    print(f"[+] UTF-16LE strings: {len(utf16_strings)}")

    with open("strings.txt", "w", encoding='utf-8') as out:
        for s in sorted(set(all_strings)):
            out.write(s + "\n")
    print("[+] Saved all strings to strings.txt")

    b64_hits = extract_base64(raw)
    if b64_hits:
        print("\n[+] Base64 blobs:")
        for b64, decoded in b64_hits:
            print(f"    [b64] {b64[:40]}...")
            print(f"    [decoded] {decoded[:80]}...\n")

    hex_esc, uni_esc = detect_encoded_js(raw)
    if hex_esc:
        print(f"[+] Found {len(hex_esc)} hex escape JS patterns")
    if uni_esc:
        print(f"[+] Found {len(uni_esc)} unicode escape JS patterns")

    json_hits = extract_json_strings(all_strings)
    if json_hits:
        print("\n[+] Parsed JSON blobs:")
        for j in json_hits:
            print(f"    {json.dumps(j, indent=2)}")

    dangerous = detect_dangerous_patterns(all_strings)
    if dangerous:
        print("\n[!] Dangerous patterns found:")
        for k, s in dangerous:
            print(f"    Keyword: {k} in: {s[:80]}")

    offset = find_v8_magic_offset(raw)
    if offset != -1:
        print(f"\n[+] Found embedded V8 bytecode at offset: 0x{offset:x}")
        embedded = raw[offset:]
        disassemble_opcodes(embedded)
    else:
        print("\n[!] No direct V8 magic found.")
        xor_bruteforce_v8(raw)

    ent = shannon_entropy(list(raw))
    print(f"\n[+] File entropy: {ent:.4f}")

    source_hash = raw[8:12]
    flag_hash = raw[12:16]
    source_len = read_u32_le(source_hash)
    magic = raw[:4].hex()
    v8_tag = "unknown (run `v8.cachedDataVersionTag()` in node to compare)"

    print("[+] JSC Metadata:")
    print(f"    File: {path}")
    print(f"    Size: {len(raw)} bytes")
    print(f"    Magic: {magic}")
    print(f"    Source length (from header): {source_len}")
    print(f"    Source hash: {source_hash.hex()}")
    print(f"    Flag hash: {flag_hash.hex()}")
    print(f"    V8 tag (est.): {v8_tag}")

    print("\n[+] Hexdump preview:")
    hex_dump(raw)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_jsc.py index.jsc")
        sys.exit(1)
    analyze_jsc(sys.argv[1])