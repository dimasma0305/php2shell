# Defender experiments: PHP OOM and upload progress

This package contains two **experimental, alert-only** signals. The network
rule recognizes one published PoC producer shape. The worker-sequence reference
evaluator correlates a startup OOM with reuse of that same Apache worker and
connection. Neither signal proves memory corruption or RCE.

## Published producer shape: Suricata

The Suricata rule detects
the multipart producer request shape used by the published `poc.py` against the
PHP 8.4.26 Apache lab. An alert means **attempted trigger shape observed**. It
does not establish memory corruption or RCE on its own, and the same request
shape remains alertable on patched PHP 8.4.27.

The rule inspects plaintext HTTP after TLS termination. It looks for a POST
multipart request with the PoC's 17-character `S` boundary and the
`PHP_SESSION_UPLOAD_PROGRESS` field. The fixed boundary makes the rule precise
for this published producer, but an attacker can change it. General detection
would need application/session telemetry and Apache worker-failure correlation.

## Live lab results

| Case | Lab and input | Expected | Suricata alerts | Evidence |
| --- | --- | --- | ---: | --- |
| Affected positive | PHP 8.4.26 Apache, public `poc.py` (`id` returned) | Alert | 2 | [Case](evidence/affected-positive.json) · [raw EVE](evidence/raw/affected-positive.jsonl) |
| Patched control | PHP 8.4.27 Apache, same detected multipart field and boundary | Alert | 1 | [Case](evidence/patched-control.json) · [raw EVE](evidence/raw/patched-control.jsonl) |
| Benign | PHP 8.4.26, ordinary multipart upload-progress form with a normal boundary | No alert | 0 | [Case](evidence/benign.json) · [raw EVE](evidence/raw/benign.jsonl) |
| Near miss | PHP 8.4.26, PoC boundary without upload-progress field | No alert | 0 | [Case](evidence/near-miss.json) · [raw EVE](evidence/raw/near-miss.jsonl) |

The case labels and alert links are checked by
[`validation.json`](validation.json). The four case outcomes are TP=2, FP=0,
TN=2, FN=0 **for these exact lab requests**; the patched alert counts as a true
positive because this rule detects an attempt. This is not a production false
positive rate. The 140 MB PoC run caused 1,238 kernel packet drops in the
Suricata sidecar. It still emitted two alerts, but packet loss can hide other
requests. Do not infer complete coverage from these four cases.

## Reproduce the sensor path

Build and start the [PHP/Apache lab](../lab/8.4.26/php-apache/) on
`127.0.0.1:18082` as documented in the repository README. Use Suricata 8.0.7
image digest `sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26`.
Run it in the lab container's network namespace with `NET_RAW` and `NET_ADMIN`,
mount [the rule](rules/suricata/php-upload-progress-producer.rules) read-only,
and enable EVE logging on `eth0`. Test syntax with `suricata -T -S <rule>`.
Then run `python -u poc.py --url http://127.0.0.1:18082/ --retries 1` from the
repository root. An EVE alert with SID `9000618` is the detector result;
`PROOF: uid=... gid=...` from `poc.py` is the separate RCE result.

For a Bash shell, start the sensor before the PoC and stop it afterward:

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

Inspect `.tools/defense-php/eve.json` for SID `9000618`. The `.tools/` output
directory is ignored by Git; the reviewed case logs are retained under
`evidence/raw/`.

The patched control used official `php:8.4.27-apache` digest
`sha256:c6527b06c772a2c3cae648ce58c23a2a12ed2fed41cdfb0619ea64be008cc601`
with a local benign `index.php` mounted only to make the same `/` route return
HTTP 200. The short multipart control shares the rule's request predicates;
it is not a patched-build exploit reproduction.

## Triage and limits

See the [analytic](detections/php-upload-progress-producer.yaml) and
[playbook](playbooks/php-upload-progress-producer.md). Preserve the complete
HTTP transaction, worker identity, nearby memory-limit or crash events, and
the installed PHP build before escalating an alert. The rule is specific to
cleartext HTTP and this PoC producer boundary. It does not cover altered
boundaries, other upload-progress chains, PHP-FPM without equivalent network
visibility, or encrypted traffic upstream of the sensor.

The retained EVE logs include private Docker network addresses only. They were
recorded from local containers on 24 October 2026. No production traffic or
third-party system was tested.

## Startup OOM followed by reuse of the same worker

The second analytic uses PHP error logs and Apache access logs with PID, client
port, and keepalive request number. Its lab-only [Apache logging
configuration](rules/apache/php-worker-audit.conf) was loaded before each run.
The [canonical rule](detections/php-startup-oom-reused-worker.yaml) requires a
startup OOM (`in Unknown on line 0`), the matching POST completion, and a later
request on that same worker and socket with a greater keepalive number. The
[reference evaluator](https://github.com/dimasma0305/irai/blob/5bf859e7cfbc6dcb946d012c8dc61e0a6bd9cfda/.agents/skills/soc-detection-engineering/scripts/php_worker_sequence.py)
lives in the irai skill, keeping helper scripts out of this repository.

| Same-input local control | Reference alerts | Evidence |
| --- | ---: | --- |
| PHP 8.4.26: compact multipart producer, then another request on the connection | 1 | [Case](evidence/worker-affected-positive.json) · [full Apache log](evidence/raw/php-affected-worker-20261024.log) |
| PHP 8.4.27: same producer and continuation | 0 | [Case](evidence/worker-patched-control.json) · [full Apache log](evidence/raw/php-fixed-worker-20261024.log) |
| PHP 8.4.26: producer OOM, connection closed before a later request | 0 | [Case](evidence/worker-near-miss.json) · [full Apache log](evidence/raw/php-no-consumer-20261024.log) |
| PHP 8.4.26: ordinary GET | 0 | [Case](evidence/worker-benign.json) · [full Apache log](evidence/raw/php-benign-get-20261024.log) |

For these four exact lab cases the attempted-trigger *candidate* has TP=1,
FP=0, TN=3, FN=0. On the affected run, worker 104 logged startup OOM during
the POST and served the next request on the same socket (`keepalive=1` then
`keepalive=2`). The same producer on PHP 8.4.27 did not log OOM. The collector
may interleave stdout and stderr out of order, so the evaluator uses timestamps
and the worker/socket keys. These counts are not a field false-positive or
false-negative estimate.

To inspect the retained evidence from an irai checkout:

```shell
python <irai-checkout>/.agents/skills/soc-detection-engineering/scripts/php_worker_sequence.py defense/evidence/raw/php-affected-worker-20261024.log
python <irai-checkout>/.agents/skills/soc-detection-engineering/scripts/php_worker_sequence.py defense/evidence/raw/php-fixed-worker-20261024.log
```

The test producer calls `StockReproducer.compact_oom(execution=False)` from the
published `poc.py` on `KeepAliveEndpoint`, using its 17-byte `S` boundary and
the same cookie spray, then sends a GET on that connection. The near miss
closes the connection after the POST. This evaluator does not inspect PHP
pointer ownership, so its alert cannot establish CVE-2026-109619's stale
global dereference or a successful exploit. It also misses producers that do
not use OOM and consumers reached on another connection. The [playbook](playbooks/php-startup-oom-reused-worker.md)
records these triage limits.
