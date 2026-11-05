#!/usr/bin/env python3
"""Normalise prompt text so that simple obfuscation does not defeat pattern matching.

Steps: Unicode NFKC (folds fullwidth forms), removal of zero-width and other invisible characters,
mapping of common Cyrillic/Greek look-alikes to Latin, case folding, mapping of digit/symbol
substitutions inside words (leetspeak), joining of letters separated by single spaces or dots
("i g n o r e"), and collapsing of whitespace. The result is logged as `prompt_normalised`, and
the content-based Wazuh rules match on that field (wazuh/rules/ai-security-lab_content.xml).
"""
import re
import unicodedata

_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎"))
_LOOKALIKE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "һ": "h", "ѕ": "s", "Α": "a", "Β": "b", "Ε": "e",
    "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
    "Τ": "t", "Χ": "x", "ο": "o",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"(?<![^\W\d_])(?:[^\W\d_][ .\-_]){3,}[^\W\d_](?![^\W\d_])")
_WORD = re.compile(r"\S+")


def _unleet(match):
    token = match.group(0)
    letters = sum(c.isalpha() for c in token)
    subs = sum(c in "013457@$" for c in token)
    # Only treat as leetspeak when the token is mostly letters with a few substitutions.
    return token.translate(_LEET) if letters >= 3 and subs and letters >= 2 * subs else token


def normalise(text):
    text = unicodedata.normalize("NFKC", str(text)).translate(_INVISIBLE)
    text = text.translate(_LOOKALIKE).casefold()
    text = _WORD.sub(_unleet, text)
    text = _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), text)
    return re.sub(r"\s+", " ", text).strip()


if __name__ == "__main__":
    import sys
    print(normalise(" ".join(sys.argv[1:])))
