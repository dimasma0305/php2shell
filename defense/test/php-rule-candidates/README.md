# Narrow PHP rule trial

This is a **test-only rule**, not a deployable detection. It adds the PoC's `f0000` grooming field to the published boundary match. We replayed the same five loss-free [lab PCAPs](../php-upload-progress-producer/evidence/raw/) with the [candidate rule](poc-grooming.rules) in Suricata 8.0.7.

| Captured case | Candidate alerts | Retained EVE |
| --- | ---: | --- |
| Affected PoC | 1 | [Log](evidence/raw/positive.jsonl) |
| Patched progress request | 0 | [Log](evidence/raw/patched.jsonl) |
| Ordinary GET | 0 | [Log](evidence/raw/benign.jsonl) |
| Boundary without progress | 0 | [Log](evidence/raw/near-miss.jsonl) |
| Benign progress upload with same boundary | 0 | [Log](evidence/raw/lookalike.jsonl) |

The candidate removes the measured benign false positive by requiring an exact field name from this PoC. The patched sample is a small progress request without that field. These results do not show how the candidate handles a changed field name or another exploit chain. Keep the published rule experimental; this narrower fingerprint cannot be promoted as general coverage of CVE-2026-109618 or CVE-2026-109619.
