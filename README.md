# php2shell

> **Restricted local-lab release.** The published client accepts only HTTP
> loopback targets on the ports used by the included labs. It intentionally
> does not expose arbitrary command execution. The fixed proof still exercises
> the complete RCE chain and succeeds only after fresh observable evidence.
> See [`AUTHORIZED_USE.md`](AUTHORIZED_USE.md).

Reproducible HTTP proof of concept for the PHP request-state vulnerabilities
tracked as CVE-2026-109618 and CVE-2026-109619. The verified chain leaks the
Zend MM heap base, leaks the loaded `libphp` base, and executes a short command
through `zif_system`.

For applications with a known web-readable writable directory, the default
command writes a random proof file there, fetches it over HTTP, and succeeds
only when the response contains `uid=`. The CodeIgniter lab instead executes a
14-byte callback command and accepts success only after `poc.py` receives its
fresh random path. No helper PHP file is installed on the target.

![Verified WordPress proof](docs/screenshots/wordpress-proof.png)

The screenshot above was rendered from the retained
[`docs/evidence/wordpress-proof.txt`](docs/evidence/wordpress-proof.txt) output
of a clean build of `lab/8.4.26/wordpress`.

## Quick start

Requirements:

- Docker with Compose support;
- Python 3.11 or newer, using only the standard library;
- an x86-64 host with enough memory for a 140 MiB request body;
- loopback access to the selected lab port.

```bash
git clone https://github.com/dimasma0305/php2shell.git
cd php2shell

docker compose -f lab/8.4.26/wordpress/compose.yaml up -d --build
./poc.py --url http://127.0.0.1:18173/
```

On Windows, use `python poc.py --url http://127.0.0.1:18173/`.

A successful run ends with output similar to:

```text
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The PoC prints `REMOTE_PROOF_REMAINS` with the random proof path so it can be
removed after the run.

## Labs

Every fixture under `lab/` has a retained successful `PROOF: uid=...` run.
Negative compatibility experiments and uncalibrated applications are not
shipped as labs.

## Verified compatibility matrix

`Affected upstream` and `RCE verified here` are different claims. The PHP
security advisory covers several release branches, while this repository only
labels an application `RCE verified` after a clean, self-checking run has been
retained under `docs/evidence/`.

| PHP build | Application or route | Status in this repository | Retained proof |
| --- | --- | --- | --- |
| 8.4.26, official Apache image | WordPress | **RCE verified** | [`wordpress-proof.txt`](docs/evidence/wordpress-proof.txt) |
| 8.4.26, official Apache image | MediaWiki Scribunto route | **RCE verified** | [`mediawiki-proof.txt`](docs/evidence/mediawiki-proof.txt) |
| 8.4.26, official Apache image | DokuWiki | **RCE verified twice** | [`dokuwiki-proof.txt`](docs/evidence/dokuwiki-proof.txt), [`run 2`](docs/evidence/dokuwiki-proof-run2.txt) |
| 8.4.26, official Apache image | Joomla installer | **RCE verified twice** | [`joomla-proof.txt`](docs/evidence/joomla-proof.txt), [`run 2`](docs/evidence/joomla-proof-run2.txt) |
| 8.4.26, official Apache image | Bare PHP endpoint | **RCE verified** | [`php-apache-proof.txt`](docs/evidence/php-apache-proof.txt) |
| 8.4.26, official Apache image | CodeIgniter appstarter 4.7.4 / framework 4.7.5 | **RCE verified twice; ASLR/layout dependent** | [`codeigniter-proof.txt`](docs/evidence/codeigniter-proof.txt), [`run 2`](docs/evidence/codeigniter-proof-run2.txt) |
| 8.4.27, official Apache image | Same CodeIgniter route | **Not vulnerable to these CVEs (fixed control)** | [`codeigniter-fixed-negative.txt`](docs/evidence/codeigniter-fixed-negative.txt) |
| 8.2.34, 8.3.35, or 8.5.11 | Any application | **Affected upstream; RCE not reproduced by this repository** | Symbol maps only; no calibrated heap layout |
| 8.2.35, 8.3.36, 8.4.27, or 8.5.12 | Any application | **Fixed upstream** | PHP security release boundary |
| PHP 8.1 and older | Any application | **No claim** | EOL or vendor-backported builds must be assessed individually |

Status meanings:

- **RCE verified**: a self-checking command proof was observed from the target;
- **DoS/crash only**: repeatable target worker termination was demonstrated,
  but command execution was not. No shipped row currently has this status;
- **Not vulnerable to these CVEs (fixed control)**: the same exploit path was
  exercised against the patched build without reaching the primitive or proof;
- **No claim**: no adequate application-specific experiment exists.

A worker crash from a wrong address or heap profile is a failed exploit
attempt, not proof of a reliable denial of service. `Fixed` describes these two
CVEs only; it does not make a broader claim about the application.

### WordPress

This is the main end-to-end fixture. It uses the exact affected PHP image,
WordPress commit `fc9832bef919c2a08541248db23af90d14ffb082`, and a deterministic
MariaDB seed.

```bash
docker compose -f lab/8.4.26/wordpress/compose.yaml up -d --build
./poc.py --url http://127.0.0.1:18173/
docker compose -f lab/8.4.26/wordpress/compose.yaml down -v
```

The PHP files are converted to the CRLF representation used during layout
calibration. This is part of the fixture because PHP parser allocations affect
the application heap shape.

### MediaWiki

The MediaWiki fixture uses the bundled, directly reachable Scribunto constants
file and writes proof under the default writable `images/` directory. A full
MediaWiki installation or database is not required for this route.

```bash
docker build -t php2shell-mediawiki lab/8.4.26/mediawiki
docker run --rm -d --name php2shell-mediawiki \
  -p 127.0.0.1:18081:80 php2shell-mediawiki
./poc.py --url http://127.0.0.1:18081/
```

The verified run is retained in
[`docs/evidence/mediawiki-proof.txt`](docs/evidence/mediawiki-proof.txt).

### DokuWiki

This fixture copies unmodified DokuWiki `2026-07-14c` application files from
the pinned official image onto the affected PHP runtime. It materializes the
official image's storage layout during the build, so no volume or setup wizard
is required.

```bash
docker build -t php2shell-dokuwiki lab/8.4.26/dokuwiki
docker run --rm -d --name php2shell-dokuwiki \
  -p 127.0.0.1:18083:80 php2shell-dokuwiki
./poc.py --url http://127.0.0.1:18083/
```

Two clean-container reproductions are retained in
[`docs/evidence/dokuwiki-proof.txt`](docs/evidence/dokuwiki-proof.txt) and
[`docs/evidence/dokuwiki-proof-run2.txt`](docs/evidence/dokuwiki-proof-run2.txt).

### Joomla

This fixture copies the Joomla `6.1.4` tree from the pinned official image,
adds the PHP extensions required by its installer, and serves the ordinary
installer route from the affected PHP runtime. It does not install a helper
endpoint or a proof reader.

```bash
docker build -t php2shell-joomla lab/8.4.26/joomla
docker run --rm -d --name php2shell-joomla \
  -p 127.0.0.1:18086:80 php2shell-joomla
./poc.py --url http://127.0.0.1:18086/
```

Two clean-container reproductions are retained in
[`docs/evidence/joomla-proof.txt`](docs/evidence/joomla-proof.txt) and
[`docs/evidence/joomla-proof-run2.txt`](docs/evidence/joomla-proof-run2.txt).

The current upstream DokuWiki and Joomla images use fixed PHP releases. These
fixtures intentionally combine their pinned application files with the exact
affected `php:8.4.26-apache` image; they do not claim that a current default
deployment of either application remains vulnerable.

### Bare PHP/Apache

The smallest fixture has a plain PHP endpoint with no `session_start()` and no
framework:

```bash
docker build -t php2shell-php-apache lab/8.4.26/php-apache
docker run --rm -d --name php2shell-php-apache \
  -p 127.0.0.1:18082:80 php2shell-php-apache
./poc.py --url http://127.0.0.1:18082/
```

The verified run is retained in
[`docs/evidence/php-apache-proof.txt`](docs/evidence/php-apache-proof.txt). A
fresh post-hardening run is retained in
[`release-boundary-proof-2026-10-22.txt`](docs/evidence/release-boundary-proof-2026-10-22.txt).

### CodeIgniter

The fixture installs unmodified CodeIgniter appstarter `4.7.4` with framework
`4.7.5` on the exact affected PHP image. The app and PHP configuration remain
at their defaults. Compose adds the hostname `x` for the exploit's 14-byte
`curl` command to reach the self-checking listener on the host; it does not add
a target endpoint or writable proof file.

```bash
docker compose -f lab/8.4.26/codeigniter/compose.yaml up -d --build
./poc.py --url http://127.0.0.1:18087/
```

Success ends with `PROOF: callback path=/.. source=...`. Two successful runs
from different fresh Apache masters are retained in
[`docs/evidence/codeigniter-proof.txt`](docs/evidence/codeigniter-proof.txt)
and [`docs/evidence/codeigniter-proof-run2.txt`](docs/evidence/codeigniter-proof-run2.txt).

This profile is sensitive to the Apache master's ASLR and inherited allocator
layout. In the measured clean-container series, compatible masters appeared
about once in four to once in five starts; incompatible masters failed the heap
wave consistently. Retrying against the same master does not remove that
limitation. The result proves RCE for the retained affected layout, not a
universal black-box exploit for every CodeIgniter deployment.

## Hard exploitation requirements

The current exploit chain needs all of the following. Missing one should be
reported as `not reproduced`, rather than silently downgraded to a crash claim.

- an affected, unpatched PHP package; a version header alone is insufficient
  because Linux and LTS vendors may backport the fix;
- a web SAPI and persistent worker model that lets the producer and consumer
  requests reach the required worker state; the published profile is calibrated
  for Apache prefork with `mod_php` and same-connection keep-alive;
- the Session extension with `session.upload_progress.enabled=1`; the upstream
  default is `1`, but server, pool, directory, or image configuration can turn
  it off;
- multipart upload progress must be reached before application code, including
  a valid progress field and file part;
- a finite and attacker-reachable allocation failure for the OOM path used by
  this chain;
- request streaming that reaches PHP without a proxy, WAF, or web server first
  buffering, rejecting, truncating, or normalizing the multipart body;
- reuse of the stale request state by the intended long-lived worker;
- an exact binary and heap-layout profile, including SAPI, architecture,
  compiler/package build, loaded extensions, PHP configuration, and relevant
  application allocation shape;
- for callback proof mode, a route from the target worker to the listener port;
- fresh runtime leaks for the Zend MM heap and loaded `libphp` base. ASLR makes
  those addresses process-specific, but ASLR is not the reason only certain PHP
  releases are vulnerable;
- the selected impact sink and its calling convention must match the mapped
  binary. The included chain targets `zif_system` on x86-64;
- enough accepted request size and memory for the calibrated requests. The
  stock profile sends a request of roughly 140 MiB.

The exact environment verified by the included profile is:

- official `php:8.4.26-apache` image digest
  `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a`;
- Debian Trixie x86-64 `libphp.so` SHA-256
  `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c`;
- Apache prefork with `mod_php`, preserving one producer/consumer pair on one
  keep-alive connection;
- stock PHP limits, including `memory_limit=128M`, `post_max_size=8M`, and
  enabled Session upload progress;
- chunked request bodies reaching Apache without proxy or WAF normalization;
- a tested application route whose allocations preserve the calibrated heap
  layout;
- a writable, web-readable output path for the default automatic HTTP proof.

The last item is a **proof requirement**, not an RCE requirement. A target may
still execute a command when it has no web-readable writable directory. In
that case the run needs another fresh, independently observable proof channel;
the PoC must not claim RCE from a timeout, connection reset, or worker crash.

PHP version alone is insufficient. Distribution patches, compiler flags,
loaded modules, SAPI, application source, configuration strings, and proxy
behavior can change the required layout. Unknown or ambiguous fingerprints
fail closed.

The upstream fixed releases are PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12. They
are controls, not supported targets.

## Profile registry

[`profiles.json`](profiles.json) separates:

1. exact binary identity and exported ELF symbol offsets;
2. heap-layout constants;
3. runtime configuration and its HTTP fingerprint.

Useful inspection commands:

```bash
./poc.py --list-builds
./poc.py --list-profiles
./poc.py --inspect-libphp /path/to/libphp.so
./poc.py --url http://127.0.0.1:18173/ --check-profile
```

`--inspect-libphp` maps binary symbols but does not infer a heap layout. A new
build is usable only after its SAPI, configuration, and application route have
been reproduced and calibrated independently.

### Candidate symbol maps

The registry also contains exact `libphp.so` identities and symbol offsets for
collected official Apache builds:

- PHP 7.0.33, 7.1.33, 7.2.34, 7.3.33, and 7.4.33 EOL final releases;
- PHP 8.2.34;
- PHP 8.3.35;
- PHP 8.4.26;
- PHP 8.5.11.

Only PHP 8.4.26 currently has calibrated heap layouts. A build entry with zero
profiles is a symbol map, not an exploitability claim. The normal `auto` mode
continues to reject it.

For an isolated lab with a known compatible layout but an unknown exact
`libphp.so`, apply one candidate explicitly:

```bash
./poc.py --url http://127.0.0.1:18086/ \
  --profile-id official-php-8.4.26-apache-trixie-stock-preapp \
  --build-id official-php-8.4.26-apache-trixie-amd64
```

Wrong symbol or layout candidates normally terminate an Apache worker. Apply a
candidate only to an isolated local lab and require a fresh self-verified proof.

## Repository layout

```text
.
├── poc.py
├── profiles.json
├── README.md
├── docs/
│   ├── evidence/
│   └── screenshots/
└── lab/
    └── 8.4.26/
        ├── php-apache/Dockerfile
        ├── wordpress/
        │   ├── Dockerfile
        │   ├── compose.yaml
        │   └── src/
        ├── mediawiki/Dockerfile
        ├── dokuwiki/Dockerfile
        ├── joomla/Dockerfile
        └── codeigniter/
            ├── Dockerfile
            ├── compose.yaml
            └── composer.lock
```

## References

- [PHP security release, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Upstream PHP 8.5.11 to 8.5.12 diff](https://github.com/php/php-src/compare/php-8.5.11...php-8.5.12)
- [Calif: PHP use-after-free research](https://calif.io/research/php-uaf)
- [Calif: php2shell](https://calif.io/php2shell/)

The released client is restricted to the included local labs. Review
[`AUTHORIZED_USE.md`](AUTHORIZED_USE.md) before use.
