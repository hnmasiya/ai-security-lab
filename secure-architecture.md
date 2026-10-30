# Secure AI Architecture

## Naive design

```mermaid
flowchart LR
 U[User and documents] --> A[Chat application]
 A --> M[LLM with sensitive context]
 M --> A
 M --> T[Tools with broad permissions]
```

## Improved design

```mermaid
flowchart LR
 U[User and external documents] --> G[Gateway: identity, limits]
 G --> I[Input validation and untrusted-data handling]
 I --> M[LLM: minimal context, no secrets]
 M --> O[Output validation]
 O --> U
 M --> B[Restricted tool broker]
 B --> H{High impact?}
 H -- Yes --> A[Human approval]
 H -- No --> T[Limited action]
 A --> T
 G --> L[(Protected audit logs)]
 I --> L
 O --> L
 B --> L
 L --> D[Detection and response]
```

## Design principles

- Do not put real secrets in model context.
- Authenticate users and authorise actions outside the model.
- Treat retrieved content and user documents as untrusted data.
- Use layered controls; keyword filters alone are insufficient.
- Restrict tools, data and network access by default.
- Require human approval for consequential actions.
- Protect logs and minimise collection of personal data.
