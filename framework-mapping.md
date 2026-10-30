# Framework Mapping

This is a thematic learning aid, not a clause-by-clause compliance assessment.

## Google Secure AI Framework (SAIF)

The lab uses the six SAIF elements as a high-level lens:

1. Expand strong security foundations to the AI ecosystem.
2. Extend detection and response to include AI threats.
3. Automate defences to keep pace with threats.
4. Harmonise platform-level controls.
5. Adapt controls using feedback and changing risk.
6. Contextualise AI risks in surrounding business processes.

## ISO/IEC 42001 thematic alignment

| Lab finding / activity | Relevant management-system theme | Lab evidence |
|---|---|---|
| Prompt injection and leakage scenarios | AI risk assessment, treatment, lifecycle risk management | `threat-model.md`, `prompt-injection-lab.md` |
| Control design and test harness | AI system development, verification and validation | `lab/`, `tests/` |
| AI inventory and ownership | AI policy, roles, responsibilities and AI system inventory | `ai-inventory.md` |
| Vendor data-handling concerns | Third-party relationships and operational controls | `ai-vendor-due-diligence.md` |
| Monitoring and response | Performance evaluation, monitoring and continual improvement | `detection/`, `incident-response-playbook.md` |
| Acceptable-use policy | Organisational AI policy and operational governance | `ai-acceptable-use-policy.md` |

## Google SAIF mapping

| Finding | SAIF element(s) | Example control |
|---|---|---|
| Direct prompt injection | 1, 3, 5 | Defence in depth; repeat testing |
| Indirect document injection | 1, 6 | Treat external content as untrusted |
| Lack of AI monitoring | 2, 3 | Detection and response process |
| Inconsistent access controls | 1, 4 | Standardised identity and least privilege |
| Shadow AI | 1, 6 | AI inventory, approved tools and staff training |
| High-impact agent actions | 1, 6 | Human approval and restricted permissions |

**Important:** Verify exact ISO/IEC 42001 requirements and Annex A controls against an authorised
copy of the standard. Do not claim certification or conformance based on this lab. SAIF
elements are not a substitute for a formal risk assessment.
