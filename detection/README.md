# Detection content

`injection_detection.yml` is a Sigma-style example for application telemetry.
The `product: ai_assistant` log source and custom fields (`prompt`, `response`)
require a matching application logging schema and backend mapping. It has not
been claimed as validated by sigma-cli or deployed to a SIEM.

The Python scanner is a local demonstration. It uses simple phrase matching and
will have false positives and false negatives. DNS matches are indicators only,
not proof of policy violation or data exfiltration.
