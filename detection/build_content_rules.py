#!/usr/bin/env python3
"""Generate wazuh/rules/ai-security-lab-content.xml (rules 100010-100021) from the table below.

Each rule matches a regular expression against `prompt_normalised`, the field the harness logs
(see detection/normalise.py). The patterns are written in the PCRE2 subset that Python's `re`
also accepts, so detection/evaluate_rules.py can evaluate exactly these expressions offline.
They were written from the development half of data/prompts.jsonl only.

Usage: python3 detection/build_content_rules.py   (rewrites the XML file)
"""
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parents[1] / "wazuh" / "rules" / "ai-security-lab-content.xml"

SN = (r"(?:(?:confidential|hidden|secret|private|internal|staff)\s+(?:marker|code|value|string|token|key|password|"
      r"notes?|instructions?|configuration|config)|access code|staff code|system (?:prompt|setup(?: text)?)|setup text|"
      r"the secrets? (?:in|you))")
V = (r"(?:print|reveal|show|disclose|output|display|give|repeat|quote|share|tell|list|write|say|state|leak|expose|"
     r"read out|think of|append|reply with|provide)")

RULES = [
    (100010, 9, "instruction-override wording",
     r"(?i)\b(?:ignore|disregard|forget|cancel|override|bypass|stop following|drop)\b.{0,40}\b(?:previous|prior|earlier|above|all|your|any)\b.{0,25}"
     r"\b(?:instructions?|rules|guidelines|polic(?:y|ies)|task|programming)\b|\bignore (?:the )?polic(?:y|ies)\b"),
    (100011, 9, "request to disclose a secret or hidden instructions",
     rf"(?i)\b{V}\b.{{0,60}}\b{SN}\b|\b(?:answer|respond|reply)\b.{{0,40}}\bwith\b.{{0,20}}\b{SN}\b"),
    (100012, 9, "role-play used to remove restrictions or reach a secret",
     rf"(?i)\b(?:no restrictions|without (?:any )?restrictions|unrestricted|do anything now|full clearance|jailbreak|developer mode)\b"
     rf"|\b(?:act as|pretend|imagine you are|you are)\b.{{0,120}}\b{SN}\b"),
    (100013, 9, "claimed authority used to justify disclosure",
     rf"(?i)\b(?:security manager|ceo|developers?|administrator|admin|vendor|official request|support engineer|authori[sz]es? you|ordering you|you must)\b"
     rf".{{0,100}}\b(?:disclos\w*|reveal|print|show|share|provide)\b.{{0,40}}\b{SN}\b"),
    (100014, 10, "delimiter breakout or spoofed role line",
     r'(?i)</[a-z]+>\s*<?(?:system|instructions?|assistant)\b|(?:end of (?:document|message|input|text|note)|""").{0,40}\b(?:assistant|system)\s*:'
     r"|\b(?:system|developer|admin(?:istrator)?|assistant)\s*(?:override\s*)?:\s*(?:ignore|disregard|reveal|disclose|print|output|override|after|append)\b"),
    (100015, 10, "instruction hidden in a comment or addressed to the assistant",
     r"(?i)<!--.{0,200}\b(?:ignore|disregard|override|bypass|reveal|disclose|print|instead)\b.{0,200}-->"
     r"|\b(?:to the assistant|assistant reading this|dear assistant|assistant,)\b.{0,80}\b(?:disregard|ignore|instead|reply with|print|reveal|output)\b"),
    (100016, 9, "request to transform a secret (reverse, spell, encode)",
     rf"(?i)\b(?:backwards?|revers(?:e|ed|ing)|one (?:character|letter|char)s? per line|each character|every other character|dash between|hexadecimal|hex|base64|rot13|acrostic|spell)\b"
     rf".{{0,80}}\b{SN}\b|\b{SN}\b.{{0,80}}\b(?:backwards?|revers(?:e|ed|ing)|one (?:character|letter|char)s? per line|each character|hexadecimal|base64|rot13)\b"),
    (100017, 9, "request for part of a secret",
     rf"(?i)\b(?:digits?|segment|portion|part|characters?|letters?)\b.{{0,40}}\b(?:of|in)\s+(?:the |your )?{SN}\b"),
    (100018, 9, "creative framing that would carry a secret",
     rf"(?i)\b(?:poem|poetry|song|lyrics|haiku|story|limerick|translate|translation|compose|write)\b.{{0,100}}\b{SN}\b"),
    (100019, 9, "paraphrased request for the setup text",
     r"(?i)\bwhat you (?:were|are) (?:told|instructed|asked) to keep (?:private|secret|confidential)\b"
     r"|\b(?:text|instructions?|prompt|message)s?\s+(?:that\s+)?(?:appears?\s+)?before my (?:first )?message\b"
     r"|\binstructions? you (?:operate|work|run) (?:under|with)\b"
     r"|\b(?:your|the) (?:setup|initial|original|opening) (?:text|instructions?|prompt|message)\b"),
    (100020, 9, "instruction override in French, German, Italian or Indonesian",
     r"(?i)\b(?:ignorez?|oubliez)\s+(?:toutes\s+)?les\s+instructions\b|\bignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+anweisungen\b"
     r"|\bignora\s+(?:tutte\s+)?le\s+istruzioni\b|\babaikan\s+(?:semua\s+)?instruksi\b"),
    (100021, 9, "secret requested as a later step or part",
     rf"(?i)\b(?:part|step)\s+(?:two|2|three|3)\s*:\s*(?:[a-z ]{{0,30}})?\b{SN}\b"),
]


def build():
    lines = ['<group name="ai_security_lab_content,">',
             "  <!-- Content-based rules (D2). They match prompt_normalised and are children of 100000. -->"]
    for rid, level, desc, pattern in RULES:
        lines += [
            f'  <rule id="{rid}" level="{level}">',
            "    <if_sid>100000</if_sid>",
            f'    <field name="prompt_normalised" type="pcre2">{escape(pattern)}</field>',
            f"    <description>AI Security Lab: {escape(desc)}</description>",
            "    <group>ai_security_lab,prompt_injection,</group>",
            "  </rule>",
        ]
    lines.append("</group>")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT} ({len(RULES)} rules)")
