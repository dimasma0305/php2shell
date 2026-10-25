# Validation only

This folder holds the [case manifest](validation.json), live-lab packet captures, tcpdump counters, replayed Suricata EVE logs, and case receipts. These are validation artifacts. SOC operators use the [rule and playbook](../README.md).

The five captures cover the affected PoC, patched request shape, ordinary GET, near miss, and a benign upload that alerts. `tcpdump` reported zero kernel drops for each capture; Suricata's offline replay reported zero TCP gaps. A replay proves the published rule's result on these bytes. It does not prove full visibility or a production false-positive rate.

## Replay all five cases

Run from the repository root with Docker, gzip, and a Bash shell. The pinned Suricata image is the one used for the retained EVE logs. `-k none` handles checksum offload artifacts in these Docker captures.

```bash
docker run --rm \
  -v "$PWD/defense/rules/suricata/php-upload-progress-producer.rules:/work/local.rules:ro" \
  jasonish/suricata@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26 \
  -T -S /work/local.rules

for case in affected-positive patched-control benign near-miss benign-fixed-boundary; do
  mkdir -p ".tools/defense-replay/$case"
  gzip -dc "defense/test/php-upload-progress-producer/evidence/raw/$case.pcap.gz" > ".tools/defense-replay/$case.pcap"
  docker run --rm --cap-add SYS_NICE \
    -v "$PWD/.tools/defense-replay/$case.pcap:/work/case.pcap:ro" \
    -v "$PWD/defense/rules/suricata/php-upload-progress-producer.rules:/work/local.rules:ro" \
    -v "$PWD/.tools/defense-replay/$case:/work/logs" \
    jasonish/suricata@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26 \
    -r /work/case.pcap -k none -S /work/local.rules -l /work/logs
  python -c "import json,sys; e=[json.loads(x) for x in open(sys.argv[1],encoding='utf-8')]; print(sys.argv[2], sum(x.get('event_type')=='alert' for x in e), 'alerts')" \
    ".tools/defense-replay/$case/eve.json" "$case"
done
```

Expected alert counts: affected-positive **2**, patched-control **1**, benign **0**, near-miss **0**, benign-fixed-boundary **1** (false positive). The [receipts](php-upload-progress-producer/evidence/) tie each PCAP and replay log to hashes and capture counters.
