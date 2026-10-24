# PHP startup-OOM worker reuse candidate

1. Verify that the OOM log says `in Unknown on line 0` and that its PID and
   client socket match the producer POST access record.
2. Verify the later access record has the same PID and socket and a greater
   `keepalive` counter. Use event timestamps because Docker can interleave
   stdout and stderr lines out of order.
3. Record the exact PHP/SAPI build, request path, body size, multipart shape,
   and whether session upload progress was enabled. Preserve the full logs.
4. Label this as a **startup-OOM worker-reuse candidate**. The logs do not
   expose partially initialized PHP fields or request-owned pointer lifetime;
   they cannot prove CVE-2026-109618 corruption or CVE-2026-109619 UAF.
