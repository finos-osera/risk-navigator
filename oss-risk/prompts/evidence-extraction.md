# OSS Risk Evidence Extraction Prompt

Use this prompt with an open or local model after source documents have already
been gathered. The model should extract evidence into structured fields; it
should not decide the final score.

```text
You are extracting evidence for an OSS library risk scorecard.

Rules:
- Use only the supplied source text and metadata.
- Do not use prior knowledge.
- Do not infer exact counts or dates if they are not present.
- Preserve source URLs and observation timestamps.
- Mark uncertain or partial evidence with lower confidence.
- Return strict JSON only.

Project:
{{project_name}}

Package:
{{ecosystem}} / {{package_name}}

Repository:
{{repository_url}}

Source documents:
{{source_documents}}

Return this JSON shape:
{
  "project": {
    "name": "",
    "ecosystem": "",
    "package": "",
    "repository": "",
    "homepage": ""
  },
  "extracted_facts": {
    "governance_model": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    },
    "foundation_or_independent_entity": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    },
    "security_process": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    },
    "release_cadence": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    },
    "support_policy": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    },
    "maintainer_concentration_notes": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    },
    "dependency_hygiene_notes": {
      "value": "",
      "evidence": "",
      "source_url": "",
      "confidence": 0.0
    }
  },
  "missing_evidence": [],
  "recommended_collector_fields": []
}
```

