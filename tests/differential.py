#!/usr/bin/env python3
"""Offline differential and Wycheproof checks for the shared AES-dust library.

Install tests/requirements.txt, build with BUILD_SHARED_LIBS=ON, then run:
  python tests/differential.py --library /absolute/path/to/libaes128.so
Windows example: --library build/shared/bin/Release/aes128.dll

Expected values come from independent libraries or pinned upstream fixtures.
Assertions intentionally use explicit checks, so python -O retains all tests.
"""

import argparse
import ctypes
import json
from pathlib import Path
import random
import sys

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV


MODES = ("ccm", "eax", "gcm", "gcm_siv")
LENGTHS = (0, 1, 2, 7, 14, 15, 16, 17, 30, 31, 32, 33,
           47, 48, 49, 64, 65, 127, 128, 129, 255, 256, 257, 1000)
GUARD = 16
SENTINEL = 0xA5


def require(condition, context):
    if not condition:
        raise RuntimeError(context)


class Buffer:
    """Surround every buffer, including read-only arguments, with canaries."""

    def __init__(self, data):
        self.size = len(data)
        self.storage = (ctypes.c_ubyte * (self.size + 2 * GUARD))()
        ctypes.memset(self.storage, SENTINEL, len(self.storage))
        self.pointer = ctypes.c_void_p(ctypes.addressof(self.storage) + GUARD)
        if data:
            ctypes.memmove(self.pointer, data, self.size)
        self.before = bytes(self.storage)

    def data(self):
        return ctypes.string_at(self.pointer, self.size)

    def check(self, context, unchanged=False):
        after = bytes(self.storage)
        require(after[:GUARD] == self.before[:GUARD] and
                after[GUARD + self.size:] == self.before[GUARD + self.size:],
                context + ": buffer canary changed")
        if unchanged:
            require(after == self.before, context + ": input buffer changed")


def parameters_valid(mode, key, nonce, tag_len, size):
    if len(key) != 16:
        return False
    if mode == "ccm":
        return (7 <= len(nonce) <= 13 and tag_len in range(4, 17, 2) and
                size < (1 << (8 * (15 - len(nonce)))))
    if mode == "gcm":
        return len(nonce) > 0 and tag_len == 16
    if mode == "gcm_siv":
        return len(nonce) == 12 and tag_len == 16
    return tag_len == 16


class Library:
    def __init__(self, path):
        self.library = ctypes.CDLL(str(Path(path).resolve()))
        pointer, length = ctypes.c_void_p, ctypes.c_uint32
        common = [pointer, length, pointer, length, pointer, length,
                  pointer, length, pointer, pointer]
        self.functions = {}
        for mode in MODES:
            for encrypt in (False, True):
                name = "aes128_" + mode + ("_encrypt" if encrypt else "_decrypt")
                function = getattr(self.library, name)
                if mode == "ccm":
                    function.argtypes = (common + [length] if encrypt else
                                         common[:-1] + [length, pointer])
                else:
                    function.argtypes = common
                function.restype = ctypes.c_int
                self.functions[mode, encrypt] = function

    def call(self, mode, encrypt, key, nonce, aad, data, tag=b"", tag_len=16,
             inplace=False, context=""):
        for value in (key, nonce, aad, data):
            require(len(value) <= 0xFFFFFFFF, context + ": exceeds uint32_t API")
        inputs = [Buffer(value) for value in (key, nonce, aad)]
        message = Buffer(data)
        output = message if inplace else Buffer(bytes([SENTINEL]) * len(data))
        tag_buffer = Buffer(bytes([SENTINEL]) * tag_len if encrypt else tag)
        kp, np, ap = [value.pointer for value in inputs]
        if mode == "gcm":
            args = [kp, len(key), np, len(nonce), message.pointer, len(data),
                    ap, len(aad)]
        else:
            args = [kp, len(key), np, len(nonce), ap, len(aad),
                    message.pointer, len(data)]
        if encrypt:
            args += [output.pointer, tag_buffer.pointer]
            if mode == "ccm":
                args.append(tag_len)
        else:
            args.append(tag_buffer.pointer)
            if mode == "ccm":
                args.append(len(tag))
            args.append(output.pointer)
        rc = self.functions[mode, encrypt](*args)
        for index, value in enumerate(inputs):
            value.check(context + f" argument {index}", unchanged=True)
        message.check(context + " message", unchanged=not inplace)
        output.check(context + " output")
        tag_buffer.check(context + " tag", unchanged=not encrypt)
        if rc != 0:
            valid = parameters_valid(mode, key, nonce,
                                     tag_len if encrypt else len(tag), len(data))
            if encrypt or mode == "gcm" or not valid:
                expected = data if inplace else bytes([SENTINEL]) * len(data)
            else:
                expected = bytes(len(data))
            require(output.data() == expected, context + ": failure output contract")
            if encrypt:
                require(tag_buffer.data() == bytes([SENTINEL]) * tag_len,
                        context + ": failure changed output tag")
        return rc, output.data(), tag_buffer.data()


def reference(mode, key, nonce, aad, message, tag_len):
    if mode == "gcm_siv":
        combined = AESGCMSIV(key).encrypt(nonce, message, aad)
        return combined[:-16], combined[-16:]
    if mode == "eax":
        # Use the EAX construction over separate CMAC/CTR primitives. This
        # also covers empty nonces, which PyCryptodome's EAX API disallows.
        def omac(domain, payload):
            digest = CMAC.new(key, ciphermod=AES)
            digest.update(bytes(15) + bytes([domain]) + payload)
            return digest.digest()
        nonce_tag = omac(0, nonce)
        cipher = AES.new(key, AES.MODE_CTR, nonce=b"",
                         initial_value=int.from_bytes(nonce_tag, "big"))
        ciphertext = cipher.encrypt(message)
        tag = bytes(a ^ b ^ c for a, b, c in
                    zip(nonce_tag, omac(1, aad), omac(2, ciphertext)))
        return ciphertext, tag
    cipher = AES.new(key, AES.MODE_CCM if mode == "ccm" else AES.MODE_GCM,
                     nonce=nonce, mac_len=tag_len)
    cipher.update(aad)
    return cipher.encrypt_and_digest(message)


def check_valid(library, mode, key, nonce, aad, message, ciphertext, tag, context,
                negative=False):
    for inplace in (False, True):
        label = context + (" in-place" if inplace else " disjoint")
        rc, actual, generated = library.call(mode, True, key, nonce, aad, message,
                                             tag_len=len(tag), inplace=inplace,
                                             context=label + " encrypt")
        require(rc == 0 and actual == ciphertext and generated == tag,
                label + ": encryption differs from independent expectation")
        rc, actual, _ = library.call(mode, False, key, nonce, aad, ciphertext,
                                     tag=tag, inplace=inplace,
                                     context=label + " decrypt")
        require(rc == 0 and actual == message,
                label + ": decryption differs from independent expectation")
    if negative:
        # Every tag byte must participate in authentication, including interior
        # bytes. Reuse the independently generated ciphertext/tag, not C output.
        for index in range(len(tag)):
            changed = bytearray(tag)
            changed[index] ^= 1 << (index % 8)
            for inplace in (False, True):
                rc, _, _ = library.call(mode, False, key, nonce, aad, ciphertext,
                                         tag=bytes(changed), inplace=inplace,
                                         context=f"{context} tag byte {index}")
                require(rc == -1, f"{context}: accepted changed tag byte {index}")


def differential(library, count, seed):
    generator = random.Random(seed)
    for mode in MODES:
        for index in range(count):
            key = generator.randbytes(16)
            message = generator.randbytes(generator.choice(LENGTHS))
            aad = generator.randbytes(generator.choice(LENGTHS))
            if mode == "ccm":
                nonce_len = 7 + index % 7
                tag_len = 4 + 2 * ((index // 7) % 7)
                if index < 5:
                    aad = generator.randbytes((65278, 65279, 65280, 65535, 65536)[index])
            else:
                nonce_len = (12 if mode == "gcm_siv" else
                             generator.randint(0 if mode == "eax" else 1, 128))
                tag_len = 16
            nonce = generator.randbytes(nonce_len)
            ciphertext, tag = reference(mode, key, nonce, aad, message, tag_len)
            check_valid(library, mode, key, nonce, aad, message, ciphertext, tag,
                        f"{mode} seed={seed} case={index}", negative=index < 8)
        print(f"Differential {mode}: {count} independent cases passed")


def wycheproof(library):
    directory = Path(__file__).resolve().parent / "wycheproof"
    for mode in MODES:
        path = directory / ("aes_" + mode + "_test.json")
        document = json.loads(path.read_text(encoding="utf-8"))
        valid_count = invalid_count = 0
        for group in document["testGroups"]:
            for case in group["tests"]:
                key, nonce, aad, message, ciphertext, tag = [
                    bytes.fromhex(case[field]) for field in
                    ("key", "iv", "aad", "msg", "ct", "tag")
                ]
                context = f"Wycheproof {mode} tcId={case['tcId']} {case['comment']}"
                if case["result"] in ("valid", "acceptable"):
                    require(parameters_valid(mode, key, nonce, len(tag), len(message)),
                            context + ": selected valid case outside API contract")
                    check_valid(library, mode, key, nonce, aad, message,
                                ciphertext, tag, context)
                    valid_count += 1
                else:
                    for inplace in (False, True):
                        rc, _, _ = library.call(mode, False, key, nonce, aad,
                                                 ciphertext, tag=tag,
                                                 inplace=inplace, context=context)
                        require(rc == -1, context + ": invalid vector accepted")
                        if not parameters_valid(mode, key, nonce, len(tag), len(ciphertext)):
                            rc, _, _ = library.call(mode, True, key, nonce, aad,
                                                     message, tag_len=len(tag),
                                                     inplace=inplace, context=context)
                            require(rc == -1, context + ": invalid parameters accepted")
                    invalid_count += 1
        require(valid_count + invalid_count == document["numberOfTests"],
                f"{path.name}: fixture count mismatch")
        print(f"Wycheproof {mode}: {valid_count} valid, {invalid_count} invalid passed; "
              f"{document['provenance']['excludedTests']} upstream cases excluded "
              "for unsupported key/tag sizes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, help="path to shared AES-dust library")
    parser.add_argument("--cases-per-mode", type=int, default=350)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=731)
    arguments = parser.parse_args()
    require(arguments.cases_per_mode > 0, "--cases-per-mode must be positive")
    library = Library(arguments.library)
    differential(library, arguments.cases_per_mode, arguments.seed)
    wycheproof(library)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
