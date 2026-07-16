import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import unquote

import jwt


@dataclass
class DecodeAttempt:
    method: str
    success: bool
    decoded_value: str = ""
    error: str = ""


@dataclass
class CookieAnalysis:
    name: str
    raw_value: str
    detected_type: str = ""
    decode_attempts: List[DecodeAttempt] = field(default_factory=list)
    json_data: Optional[Dict] = None
    jwt_data: Optional[Dict] = None
    flags_found: List[str] = field(default_factory=list)
    suspicious_patterns: List[str] = field(default_factory=list)


class CookieAnalyzer:
    SUSPICIOUS_PATTERNS = [
        (r"\b(admin|root|administrator|superuser)\b", "Привилегированная учетная запись"),
        (r"\b(password|passwd|pwd|secret)\b", "Пароль или секрет"),
        (r"\b(token|session|auth|bearer)\b", "Токен аутентификации"),
        (r"\b(user|username|login)\b", "Идентификатор пользователя"),
        (r"\b(key|private|api_key)\b", "Секретный ключ"),
        (r"\b(is_admin|role|permission|privilege)\b", "Параметр авторизации"),
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email-адрес"),
    ]

    def __init__(self, flag_prefix: str = ""):
        r"""
        flag_prefix — строка-префикс флага (например "grodno", "HTB", "picoCTF").
        Автоматически формирует regex вида: <prefix>\{[^}]+\}
        Если передана строка с "{" или "\{" — используется как raw regex.
        Если пустая — поиск флагов не выполняется.
        """
        self.flag_prefix = flag_prefix.strip()
        self.FLAG_PATTERN = self._build_flag_pattern(self.flag_prefix)

    @staticmethod
    def _build_flag_pattern(prefix: str) -> Optional[re.Pattern]:
        if not prefix:
            return None
        # Если пользователь ввёл полный regex (содержит { или \{) — используем как есть
        if "{" in prefix or r"\{" in prefix:
            try:
                return re.compile(prefix)
            except re.error:
                return None
        # Иначе формируем стандартный regex: prefix\{[^}]+\}
        try:
            return re.compile(rf"{re.escape(prefix)}\{{[^}}]+\}}")
        except re.error:
            return None

    def analyze_cookie(self, name: str, value: str) -> CookieAnalysis:
        analysis = CookieAnalysis(name=name, raw_value=value)

        if not value:
            analysis.detected_type = "empty"
            return analysis

        if self._is_jwt(value):
            analysis.detected_type = "JWT"
            analysis.jwt_data = self._decode_jwt(value)
            if analysis.jwt_data and "error" not in analysis.jwt_data and self.FLAG_PATTERN:
                analysis.flags_found.extend(
                    self.FLAG_PATTERN.findall(json.dumps(analysis.jwt_data))
                )
            return analysis

        attempts = [
            ("Hex", self._try_hex),
            ("Base64", self._try_base64),
            ("Base32", self._try_base32),
            ("URL-encoded", self._try_url_encoding),
        ]

        for method_name, decoder in attempts:
            result = decoder(value)
            analysis.decode_attempts.append(result)
            if result.success:
                analysis.detected_type = method_name
                decoded = result.decoded_value
                if self.FLAG_PATTERN:
                    analysis.flags_found.extend(self.FLAG_PATTERN.findall(decoded))
                analysis.suspicious_patterns.extend(self._check_suspicious(decoded))
                if self._is_json(decoded):
                    try:
                        analysis.json_data = json.loads(decoded)
                    except json.JSONDecodeError:
                        pass
                break

        if not analysis.detected_type:
            analysis.detected_type = "unknown/plain"
            if self.FLAG_PATTERN:
                analysis.flags_found.extend(self.FLAG_PATTERN.findall(value))
            analysis.suspicious_patterns.extend(self._check_suspicious(value))

        return analysis

    def _is_jwt(self, value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 3:
            return False
        try:
            for part in parts[:2]:
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += "=" * padding
                base64.urlsafe_b64decode(part)
            return True
        except Exception:
            return False

    def _decode_jwt(self, value: str) -> Optional[Dict]:
        try:
            header = jwt.get_unverified_header(value)
            payload = jwt.decode(value, options={"verify_signature": False})
            return {"header": header, "payload": payload}
        except Exception as e:
            return {"error": str(e)}

    def _is_printable(self, text: str, threshold: float = 0.8) -> bool:
        if not text:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return (printable / len(text)) >= threshold

    def _try_base64(self, value: str) -> DecodeAttempt:
        try:
            if not re.match(r'^[A-Za-z0-9+/=\s]+$', value):
                return DecodeAttempt(method="Base64", success=False, error="Invalid charset")
            clean = value.replace(" ", "").replace("\n", "")
            padding = 4 - len(clean) % 4
            if padding != 4:
                clean += "=" * padding
            decoded_bytes = base64.b64decode(clean, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded and self._is_printable(decoded, threshold=0.85):
                return DecodeAttempt(method="Base64", success=True, decoded_value=decoded)
            return DecodeAttempt(method="Base64", success=False, error="Non-printable result")
        except (binascii.Error, ValueError) as e:
            return DecodeAttempt(method="Base64", success=False, error=str(e))

    def _try_base32(self, value: str) -> DecodeAttempt:
        try:
            if not re.match(r'^[A-Z2-7=\s]+$', value.upper()):
                return DecodeAttempt(method="Base32", success=False, error="Invalid charset")
            value_upper = value.upper().replace(" ", "")
            padding = 8 - len(value_upper) % 8
            if padding != 8:
                value_upper += "=" * padding
            decoded = base64.b32decode(value_upper).decode("utf-8", errors="ignore")
            if decoded and self._is_printable(decoded):
                return DecodeAttempt(method="Base32", success=True, decoded_value=decoded)
        except (binascii.Error, ValueError):
            pass
        return DecodeAttempt(method="Base32", success=False, error="Invalid Base32")

    def _try_hex(self, value: str) -> DecodeAttempt:
        try:
            if re.match(r'^[0-9a-fA-F\s]+$', value) and len(value.replace(" ", "")) % 2 == 0:
                decoded = bytes.fromhex(value.replace(" ", "")).decode("utf-8", errors="ignore")
                if decoded and self._is_printable(decoded):
                    return DecodeAttempt(method="Hex", success=True, decoded_value=decoded)
        except ValueError:
            pass
        return DecodeAttempt(method="Hex", success=False, error="Invalid Hex")

    def _try_url_encoding(self, value: str) -> DecodeAttempt:
        try:
            if "%" in value:
                decoded = unquote(value)
                if decoded != value:
                    return DecodeAttempt(method="URL-encoded", success=True, decoded_value=decoded)
        except Exception:
            pass
        return DecodeAttempt(method="URL-encoded", success=False, error="Not URL-encoded")

    def _is_json(self, value: str) -> bool:
        v = value.strip()
        return (v.startswith("{") and v.endswith("}")) or (v.startswith("[") and v.endswith("]"))

    def _check_suspicious(self, value: str) -> List[str]:
        found = []
        for pattern, description in self.SUSPICIOUS_PATTERNS:
            for match in re.finditer(pattern, value, re.IGNORECASE):
                found.append(f"{description}: {match.group(0)}")
        return found

    def analyze_batch(self, cookies: List[Dict[str, str]]) -> List[CookieAnalysis]:
        return [self.analyze_cookie(c.get("name", "?"), c.get("value", "")) for c in cookies]