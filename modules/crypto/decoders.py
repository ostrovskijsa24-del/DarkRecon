from __future__ import annotations

import base64
import codecs
import re
import urllib.parse


MORSE_STANDARD_EN = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    ".-.-.-": ".",
    "--..--": ",",
    "..--..": "?",
    "-.-.--": "!",
    "---...": ":",
    "-.-.-.": ";",
    "-...-": "=",
    ".-.-.": "+",
    "-....-": "-",
    "..--.-": "_",
    ".-..-.": '"',
    ".----.": "'",
    "-..-.": "/",
    "-.--.": "(",
    "-.--.-": ")",
    "...-..-": "$",
    ".-...": "&",
    ".--.-.": "@",
}

MORSE_EN = {
    **MORSE_STANDARD_EN,
    "-.--.": "{",
    "-.--.-": "}",
    "-.--..": "{",
    "-.--.--": "}",
}


def decode_base64(data: str) -> bytes:
    stripped = re.sub(r"\s+", "", data)
    padding = "=" * (-len(stripped) % 4)
    return base64.b64decode(stripped + padding, validate=False)


def decode_base32(data: str) -> bytes:
    stripped = re.sub(r"\s+", "", data).upper()
    padding = "=" * (-len(stripped) % 8)
    return base64.b32decode(stripped + padding, casefold=True)


def decode_base85(data: str) -> bytes:
    return base64.b85decode(data.strip())


def decode_hex(data: str) -> bytes:
    stripped = re.sub(r"[\s:,-]+", "", data)
    return bytes.fromhex(stripped)


def decode_binary(data: str) -> bytes:
    stripped = re.sub(r"\s+", "", data)
    if len(stripped) % 8 != 0:
        raise ValueError("binary data length must be divisible by 8")
    return bytes(int(stripped[index : index + 8], 2) for index in range(0, len(stripped), 8))


def decode_url(data: str) -> str:
    return urllib.parse.unquote(data)


def decode_morse(data: str, language: str = "en") -> str:
    if language.lower() != "en":
        raise ValueError("only English Morse is supported")
    words = re.split(r"\s*/\s*|\s*\|\s*", data.strip())
    decoded_words = []
    for word in words:
        letters = [token for token in word.split() if token]
        decoded_words.append("".join(MORSE_EN.get(token, "?") for token in letters))
    return " ".join(decoded_words)


def decode_ascii_numbers(data: str) -> str:
    numbers = [int(item) for item in re.findall(r"\d{1,3}", data)]
    if any(number < 0 or number > 255 for number in numbers):
        raise ValueError("ASCII numbers must be in range 0..255")
    return "".join(chr(number) for number in numbers)


def decode_unicode_escapes(data: str) -> str:
    return codecs.decode(data, "unicode_escape")


DECODERS = {
    "base64": decode_base64,
    "base32": decode_base32,
    "base85": decode_base85,
    "hex": decode_hex,
    "binary": decode_binary,
    "url": decode_url,
    "morse": decode_morse,
    "ascii_numbers": decode_ascii_numbers,
    "unicode_escapes": decode_unicode_escapes,
}


def decode_by_type(data: str, encoding_type: str) -> str | bytes:
    """Call a decoder by encoding type name."""
    decoder = DECODERS.get(encoding_type.lower())
    if decoder is None:
        raise ValueError(f"unknown encoding type: {encoding_type}")
    return decoder(data)
