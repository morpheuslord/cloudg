"""Fake credentials for the privacy detector tests.

None of these is a real credential. Each value is assembled from pieces at
import time so that no complete key-shaped string appears in the source:
secret scanners (GitHub secret scanning, Codacy) read the source text, while
the detectors under test see exactly the same strings as before.
"""

from __future__ import annotations


def _join(*parts: str) -> str:
    return "".join(parts)


# AWS's documented example key ids and secret, in their access-key and
# temporary-key forms, plus a unique-id (AROA) that is not a key
AWS_KEY_ID = _join("AKIA", "IOSFODNN7", "EXAMPLE")
AWS_TEMP_KEY_ID = _join("ASIA", "IOSFODNN7", "EXAMPLE")
AWS_ROLE_UNIQUE_ID = _join("AROA", "J2UCCR6DPC", "EXAMPLE")
AWS_SECRET = _join("wJalrXUtnFEMI", "/K7MDENG/", "bPxRfiCYEXAMPLEKEY")

_BEGIN, _END = "-----BEGIN ", "-----END "
RSA_PRIVATE_KEY = _join(
    _BEGIN, "RSA PRIVATE KEY-----\n",
    "MIIEowIBAAKCAQEA1x8b0aB3cdEfGh\nabcDEF123==\n",
    _END, "RSA PRIVATE KEY-----",
)  # fmt: skip
OPENSSH_PRIVATE_KEY = _join(
    _BEGIN, "OPENSSH PRIVATE KEY-----\n", "b3BlbnNzaA==\n", _END, "OPENSSH PRIVATE KEY-----"
)
JWT = _join(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".",
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ", ".",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
)  # fmt: skip
SLACK_TOKEN = _join("xox", "b-", "1234567890-abcdefghij")
SAS_SIGNATURE = _join("AbCdEf0123456789", "%2BxyzQQ")
SAS_URL = _join("https://acct.blob.core.windows.net/c?sv=2020&", "sig=", SAS_SIGNATURE)
