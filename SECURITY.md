# Security notice

## What this repository is

A research artifact for **CVE-2026-109618 / CVE-2026-109619** ("php2shell"),
the pre-auth RCE in PHP's `session.upload_progress` handler. The vulnerability
is **already patched** in PHP **8.3.36**, **8.4.27**, and **8.5.12**, released
in October 2026. Public proof-of-concept code pre-dates this repository (see
`pocs/php2shell/CREDITS.md` for the lineage); this project adds operator
tooling, honest reach measurement, and documentation of the specific
target-config pre-filter that bounds the public chain's practical surface
(see `DISTRO_EXPLOITABILITY.md`).

## Authorized use only

The contents of this repository are intended for:

* Authorized penetration testing engagements with a scope that explicitly
  includes the target
* Defender audit of own infrastructure against the published vulnerability
  class
* Security research against lab environments the researcher controls
* Educational use in security training contexts

Use against systems you are not authorized to test is a violation of the
Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), the
Datalagringsdirektivet / corresponding statutes (EU member states), and
analogous legislation in most jurisdictions. The authors do not consent to
and disclaim all responsibility for unauthorized use.

## Vulnerability reporting

This is a public-vulnerability research repository, not a vendor security
contact. If you have found a **new** vulnerability in PHP, report it through
the official PHP security process: <https://www.php.net/security.php>.

If you have found a bug in the tooling in this repository (e.g. an offset is
wrong, `extract_offsets.py` fails on a build it should handle), open a public
GitHub issue — nothing in the tool itself is a security contact.

## Patch verification

If you are a defender auditing your installations, `PATCH_CROSSCHECK.md`
documents the five independent defense layers added in PHP 8.3.36 and how to
verify each one in a binary that may carry a backport. Any one of layers 1,
2, or 3 alone is sufficient to block the published chain.

The target-config pre-filter documented in `DISTRO_EXPLOITABILITY.md`
(`output_buffering`) is also measurable from a `phpinfo()` output — probe
your installations before assuming you are exposed, and before assuming you
are not.
