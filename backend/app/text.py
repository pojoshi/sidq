import hashlib
import math
import re
import unicodedata

DIM = 256
_HIDDEN = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_AR_MARKS = re.compile("[ً-ٰـ]")
_AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
_AR_LETTERS = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ة": "ه", "ى": "ي"})
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ι": "i", "υ": "u", "κ": "k", "ν": "v", "τ": "t",
})
MAX_CHARS = 6000


def clean(raw: str) -> str:
    t = unicodedata.normalize("NFKC", raw or "")
    t = _HIDDEN.sub("", t).translate(_AR_DIGITS)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:MAX_CHARS]


_NUM = re.compile(r"\d[\d\s-]{3,}\d")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def mask(text: str) -> str:
    return _EMAIL.sub("••••@••••", _NUM.sub("••••", clean(text)))


def normalise_for_match(text: str) -> str:
    t = _AR_MARKS.sub("", clean(text)).translate(_AR_LETTERS).translate(_CONFUSABLES).lower()
    return re.sub(r"\d+", "0", t)


def _features(text: str):
    for w in re.findall(r"[\w.\-]+", normalise_for_match(text)):
        yield "w:" + w
        padded = f"#{w}#"
        for i in range(len(padded) - 2):
            yield "c:" + padded[i:i + 3]


def embed(text: str) -> list[float]:
    vec = [0.0] * DIM
    for f in _features(text):
        h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "big")
        vec[h % DIM] += 1.0 if (h >> 63) & 1 else -1.0
    n = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / n for v in vec]


_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b")
_SHORTENER = re.compile(r"\b(bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|wa\.me)/(\S+)")
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co", "wa.me"}
OFFICIAL = {"operatorx.example"}
OFFICIAL_SENDERS = {"operatorx", "operatorx_support", "+97317000000"}


def indicators(masked_text: str, sender: str | None) -> list[str]:
    low = masked_text.lower()
    out = {d for d in _DOMAIN.findall(low) if d not in OFFICIAL and d not in SHORTENERS}
    out |= {f"{h}/{p.rstrip('.,;)')}" for h, p in _SHORTENER.findall(low)}
    if sender:
        s = clean(sender).lower().lstrip("@").replace(" ", "")
        if s and s not in OFFICIAL and s not in OFFICIAL_SENDERS:
            out.add("sender:" + s[:80])
    return sorted(out)
