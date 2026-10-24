# Triage: PHP upload-progress producer shape

1. Confirm SID `9000618`, source and destination, URI, timestamp, and Suricata
   `flow_id`. Check for packet drops before deciding that no neighboring
   request exists. The retained benign same-boundary upload also triggered this
   signature, so treat it as a triage lead only.
2. Retrieve the full request at the TLS terminator or application gateway if
   policy permits. Validate that it is a multipart POST and inspect the
   upload-progress field, body size, session identifier, and repeated form
   fields. Avoid copying session values into a ticket.
3. Correlate the request to Apache worker PID, PHP memory-limit errors, worker
   exit/restart, and subsequent requests on the same session. Record the exact
   PHP build and SAPI.
4. Classify as **attempt observed** unless runtime evidence separately proves
   memory corruption or command execution. A patched server may still receive
   the same attempt. If the request is an expected integration test or
   legitimate upload, close with that context and retain the sample for tuning.
5. Escalate a supported exploit finding only with independent target-side
   evidence. This rule alone is not an RCE or compromise indicator.
