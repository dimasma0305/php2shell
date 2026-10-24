# Defender signals for PHP upload progress

No production-ready detection is shipped. The Suricata rule is a lab-tested candidate for evaluation on your sensor. The rule does not prove memory corruption or RCE. Rules and playbooks are the SOC-facing files; [test](test/) holds the validation manifest, case receipts, and raw logs.

## Detection index

| Detection | Use | Claim | Sensor | Lab cases |
| --- | --- | --- | --- | --- |
| [php-upload-progress-producer](#php-upload-progress-producer) | Rule for evaluation | attempted_trigger | ingress | TP=2 FP=1 TN=2 FN=0 UNKNOWN=0 |

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

## Validation method

The [manifest](test/validation.json) lists the lab cases and the linked receipts. Each receipt records a SHA-256 for its complete raw log. Check those hashes from the repository root with Python's standard library:

```bash
python -c "import hashlib,json,pathlib; m=json.loads(pathlib.Path('defense/test/validation.json').read_text()); r=[json.loads(pathlib.Path(c['evidence']).read_text()) for d in m['detections'] for c in d['cases']]; assert all(hashlib.sha256(pathlib.Path(x['capture']['raw_log']).read_bytes()).hexdigest()==x['capture']['raw_log_sha256'] for x in r); print(len(r), 'raw logs match their recorded SHA-256')"
```

The hashes and case table support an audit of these small lab results. They do not authenticate a live run, prove full sensor coverage, or establish a production false-positive rate.
