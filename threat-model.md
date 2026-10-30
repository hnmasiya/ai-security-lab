# Threat Model — Fictional AI Support Assistant

**Method:** STRIDE-oriented analysis.  
**Scope:** Local chatbot test harness only; no real tools, customers, mailboxes or business systems.

## System and trust boundaries

```text
[User / untrusted document] -> [Test harness and controls] -> [Local LLM]
             |                         |                         |
             +-------------------------+-------------------------+
                                       |
                               [Redacted local logs]
```

Trust boundaries: user/document to application; application to model; application to local logs.

## Assets

| Asset | Security property | Potential impact |
|---|---|---|
| Synthetic canary in model context | Confidentiality | Marker disclosure demonstrates failure |
| System instructions | Integrity | Manipulated behaviour |
| Model endpoint | Availability | Resource exhaustion or service interruption |
| Prompt/response logs | Confidentiality and integrity | Sensitive content exposure or loss of evidence |
| User-supplied documents | Integrity | Indirect prompt injection |

## STRIDE register

| ID | Category | Threat | Lab scenario | Example control |
|---|---|---|---|---|
| T1 | Information disclosure | Model reveals hidden context | A1, A5, A8 | Keep secrets out of model context; output screening |
| T2 | Elevation of privilege | Jailbreak changes model behaviour | A2 | Treat user text as untrusted; constrain application actions |
| T3 | Tampering | Document instructions alter response | A3, A7 | Parse documents as data; robust boundary handling |
| T4 | Spoofing | Fake authority claim is trusted | A4 | Authenticate identity outside the model |
| T5 | Repudiation | Insufficient records prevent investigation | Not exercised against a real service | Privacy-conscious audit logging |
| T6 | Denial of service | Oversized/repeated prompts exhaust service | Not exercised | Rate limits, timeouts and quotas |
| T7 | Elevation of privilege | Agent misuses broad tools | Out of scope | Tool broker, least privilege, human approval |
| T8 | Information disclosure | Staff use unapproved AI tools | Governance scenario | AI inventory, policy, vendor review |

## Assumptions and limitations

- Risk ratings are qualitative and must be adjusted using actual evidence.
- The harness uses a local model and synthetic data.
- Keyword filters are bypassable and are not a security boundary by themselves.
- Prompt instructions cannot guarantee confidentiality. Do not place real secrets in model context.
- No production security assurance is claimed.
