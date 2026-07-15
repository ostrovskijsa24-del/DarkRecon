import base64
import hashlib
import hmac
import json
import re
import warnings
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path

import jwt
from jwt.exceptions import InvalidSignatureError


@dataclass
class JWTAnalysis:
    raw_token: str
    header: Optional[Dict] = None
    payload: Optional[Dict] = None
    signature: str = ""
    algorithm: str = ""
    is_valid: bool = False
    secret_found: str = ""
    errors: List[str] = field(default_factory=list)


class JWTTool:
    DEFAULT_SECRET_WORDLIST = [
        "secret", "password", "123456", "12345678", "1234567890", "qwerty",
        "abc123", "password123", "admin", "letmein", "welcome", "monkey",
        "master", "dragon", "login", "princess", "football", "shadow",
        "sunshine", "trustno1", "iloveyou", "batman", "access", "hello",
        "charlie", "donald", "key", "supersecret", "jwt_secret", "secret_key",
    ]

    def __init__(self, wordlist_path: Optional[str] = None):
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                self.secrets = [line.strip() for line in f if line.strip()]
        else:
            self.secrets = self.DEFAULT_SECRET_WORDLIST.copy()

    def decode_token(self, token: str) -> JWTAnalysis:
        analysis = JWTAnalysis(raw_token=token)
        try:
            analysis.header = jwt.get_unverified_header(token)
            analysis.payload = jwt.decode(token, options={"verify_signature": False})
            analysis.algorithm = analysis.header.get("alg", "unknown")
            
            parts = token.split(".")
            if len(parts) == 3:
                analysis.signature = parts[2]
        except Exception as e:
            analysis.errors.append(f"Decode error: {e}")
        return analysis

    def create_none_token(self, payload: Dict) -> str:
        header = {"alg": "none", "typ": "JWT"}
        header_b64 = self._b64encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._b64encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{header_b64}.{payload_b64}."

    def create_hs256_token(self, payload: Dict, secret: str) -> str:
        return jwt.encode(payload, secret, algorithm="HS256")

    def brute_force_secret(self, token: str) -> Optional[str]:
        # Подавляем warnings о коротких ключах во время брутфорса
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            warnings.filterwarnings("ignore", message=".*InsecureKeyLengthWarning.*")
            
            for secret in self.secrets:
                try:
                    jwt.decode(token, secret, algorithms=["HS256"])
                    return secret
                except InvalidSignatureError:
                    continue
                except Exception:
                    continue
        return None

    def modify_payload(self, token: str, modifications: Dict) -> JWTAnalysis:
        analysis = self.decode_token(token)
        if analysis.payload:
            new_payload = analysis.payload.copy()
            new_payload.update(modifications)
            analysis.payload = new_payload
        return analysis

    def _b64encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")