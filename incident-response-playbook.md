# Incident Response Playbook — Suspected Prompt Injection

## Trigger
An alert, user report, unexpected model response, confidential-data disclosure, or unapproved tool action.

## Severity guide

| Severity | Example | Initial action |
|---|---|---|
| High | Confidential data exposed or unauthorised action executed | Disable affected tool/action path; preserve evidence; escalate immediately |
| Medium | Repeated injection attempts without confirmed impact | Investigate scope and strengthen monitoring |
| Low | Isolated failed attempt | Record, review and tune detections |

## Response steps

1. **Prepare:** assign system owner, maintain approved-tool inventory, test kill switch, define logging and retention.
2. **Detect and analyse:** validate alert, classify direct/indirect injection, establish whether data or actions were affected.
3. **Contain:** disable risky integrations or tool permissions; quarantine malicious documents; restrict affected accounts where justified.
4. **Eradicate:** remove unsafe context, reduce permissions, fix parsing/validation, update tests and detections.
5. **Recover:** retest benign and malicious cases; restore service gradually with monitoring.
6. **Notify:** involve privacy/legal/business owners where personal or regulated data may be affected.
7. **Learn:** update risk register, AI-BOM, policy, test cases and vendor review.

Preserve original evidence securely. Do not place personal data, credentials or unredacted logs in a public repository.
