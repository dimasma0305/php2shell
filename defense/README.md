# Defender signals for PHP upload progress

No production-ready detection is shipped. The Suricata rule is a lab-tested candidate for evaluation on your sensor. The worker-sequence item is a [lab-only test](test/php-startup-oom-reused-worker/), not a SOC rule. Neither proves memory corruption or RCE. Rules and playbooks are the SOC-facing files; [test](test/) holds the validation manifest, case receipts, and raw logs.

## Detection index

| Detection | Use | Claim | Sensor | Lab cases |
| --- | --- | --- | --- | --- |
| [php-upload-progress-producer](#php-upload-progress-producer) | Rule for evaluation | attempted_trigger | ingress | TP=2 FP=1 TN=2 FN=0 UNKNOWN=0 |
| [php-startup-oom-reused-worker](#php-startup-oom-reused-worker) | Lab test only | attempted_trigger | runtime | TP=1 FP=0 TN=3 FN=0 UNKNOWN=0 |

## php-upload-progress-producer

### Claim and scope

Claim: attempted_trigger. Status: experimental. Use: Rule for evaluation. The rule saw the published PoC's multipart upload-progress request shape. The patched lab also alerts because it receives the same attempt shape. A normal upload with the same boundary and field also alerted, so the signal does not establish attacker intent.

### Telemetry and method

Suricata 8.0.7 reads plaintext HTTP on the Apache container's `eth0`. The [analytic](detections/php-upload-progress-producer.yaml) describes the signal; the [rule](rules/suricata/php-upload-progress-producer.rules) matches the PoC's 17-character `S` boundary and `PHP_SESSION_UPLOAD_PROGRESS` field.

### Evidence

| Case | Expected | Observed alerts | Capture health | Evidence | Raw log |
| --- | --- | ---: | --- | --- | --- |
| PHP 8.4.26 PoC | Alert | 2 | loss_reported | [Case](test/php-upload-progress-producer/evidence/affected-positive.json) | [EVE](test/php-upload-progress-producer/evidence/raw/affected-positive.jsonl) |
| PHP 8.4.27 same shape | Alert | 1 | no_loss_reported | [Case](test/php-upload-progress-producer/evidence/patched-control.json) | [EVE](test/php-upload-progress-producer/evidence/raw/patched-control.jsonl) |
| Ordinary upload progress | No alert | 0 | no_loss_reported | [Case](test/php-upload-progress-producer/evidence/benign.json) | [EVE](test/php-upload-progress-producer/evidence/raw/benign.jsonl) |
| Boundary without field | No alert | 0 | no_loss_reported | [Case](test/php-upload-progress-producer/evidence/near-miss.json) | [EVE](test/php-upload-progress-producer/evidence/raw/near-miss.jsonl) |
| Benign upload, same boundary | No alert | 1 | no_loss_reported | [Case](test/php-upload-progress-producer/evidence/benign-fixed-boundary.json) | [EVE](test/php-upload-progress-producer/evidence/raw/benign-fixed-boundary.jsonl) |

### Reproduce

Start the [PHP 8.4.26 Apache lab](../lab/8.4.26/php-apache/) on `127.0.0.1:18082`, then run this from the repository root. The Suricata image is pinned to digest `sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26`.

```bash
mkdir -p .tools/defense-php
docker run -d --rm --name php-defense-ids \
  --network container:php2shell-php-apache \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/defense/rules/suricata/php-upload-progress-producer.rules:/work/local.rules:ro" \
  -v "$PWD/.tools/defense-php:/work/logs" \
  jasonish/suricata@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26 \
  -i eth0 -S /work/local.rules -l /work/logs
python -u poc.py --url http://127.0.0.1:18082/ --retries 1
docker stop php-defense-ids
```

Look for SID `9000618` in `.tools/defense-php/eve.json`. The PoC's fresh `uid=` and `gid=` output is a separate RCE proof.

### Limits and next step

This rule matches one PoC boundary and misses changed boundaries or traffic encrypted before the sensor. The positive capture had 1,238 kernel packet drops and two TCP reassembly gaps. A benign request with the same boundary produced one false positive with zero reported loss. Use the [playbook](playbooks/php-upload-progress-producer.md) to inspect the full request, PHP build, worker identity, and nearby failures before attributing the event. Keep the rule in alert-only evaluation; it cannot support automatic blocking.

## php-startup-oom-reused-worker

### Claim and scope

Claim: attempted_trigger. Status: experimental. Use: Lab test only. The reference evaluator linked a startup OOM to a later request on the same Apache worker and socket in the affected lab. It is not a SOC rule.

### Telemetry and method

The [test description](test/php-startup-oom-reused-worker/analytic.yaml) requires an OOM, the POST completion, and a later keepalive request with the same worker PID and client port. The [lab collector configuration](test/php-startup-oom-reused-worker/collector.conf) supplies those fields. The [reference evaluator](https://github.com/dimasma0305/irai/blob/5bf859e7cfbc6dcb946d012c8dc61e0a6bd9cfda/.agents/skills/soc-detection-engineering/scripts/php_worker_sequence.py) runs on the retained logs; it is not a deployed detector.

### Evidence

| Case | Expected | Observed alerts | Capture health | Evidence | Raw log |
| --- | --- | ---: | --- | --- | --- |
| PHP 8.4.26 OOM then reuse | Alert | 1 | N/A | [Case](test/php-startup-oom-reused-worker/evidence/worker-affected-positive.json) | [Apache](test/php-startup-oom-reused-worker/evidence/raw/php-affected-worker-20261024.log) |
| PHP 8.4.27 same input | No alert | 0 | N/A | [Case](test/php-startup-oom-reused-worker/evidence/worker-patched-control.json) | [Apache](test/php-startup-oom-reused-worker/evidence/raw/php-fixed-worker-20261024.log) |
| Ordinary GET | No alert | 0 | N/A | [Case](test/php-startup-oom-reused-worker/evidence/worker-benign.json) | [Apache](test/php-startup-oom-reused-worker/evidence/raw/php-benign-get-20261024.log) |
| OOM without later request | No alert | 0 | N/A | [Case](test/php-startup-oom-reused-worker/evidence/worker-near-miss.json) | [Apache](test/php-startup-oom-reused-worker/evidence/raw/php-no-consumer-20261024.log) |

### Reproduce

From an irai checkout, run the evaluator on the retained affected and fixed logs:

```bash
python <irai-checkout>/.agents/skills/soc-detection-engineering/scripts/php_worker_sequence.py defense/test/php-startup-oom-reused-worker/evidence/raw/php-affected-worker-20261024.log
python <irai-checkout>/.agents/skills/soc-detection-engineering/scripts/php_worker_sequence.py defense/test/php-startup-oom-reused-worker/evidence/raw/php-fixed-worker-20261024.log
```

### Limits and next step

This lab result is not proof of a stale pointer or successful exploit. It misses OOM-free producers and consumers on another connection. The logs can interleave, so correlate timestamps, PID, client port, and keepalive number as the [test review notes](test/php-startup-oom-reused-worker/review.md) describe.

## Validation method

The [manifest](test/validation.json) fixes the claims, sensors, case labels, and evidence paths. Run the independent check against the exact committed revision:

```bash
python <irai-checkout>/.agents/skills/soc-detection-engineering/scripts/check_detection.py --repo . --revision HEAD --summary
```

The check recomputes these small lab counts and reconciles selected events and final capture statistics with committed raw logs. `loss_reported` means packet drops or TCP reassembly gaps; `no_loss_reported` means neither was reported, not complete capture. A static pass does not prove a live alert, full coverage, or a production false-positive rate.
