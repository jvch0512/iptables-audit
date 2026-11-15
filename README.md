# iptables-audit

iptables-audit reads the output of `iptables-save` (or a saved `rules.v4`), tracks the tables, chains and default policies, and checks the rules that decide what can reach the host: a chain that defaults to ACCEPT with nothing at the end to close it, an unconditional ACCEPT, sensitive services (databases, Docker API, Telnet, SMB, VNC) open to every source address, wide port ranges and a missing rule for established connections.

**Live demo:** https://jvch0512.github.io/iptables-audit/ (Synthetic rule sets.)

Free Pascal 3, standard units only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make build
build/iptables-audit examples
build/iptables-audit /etc/iptables/rules.v4 --tsv
build/iptables-audit ./firewalls --fail-on high       # exit 1 on any high finding
```

Pass a file or a directory (files ending in `.rules`, `.v4`, `.iptables` or `.save`, searched recursively).

| Rule | Severity | What it catches |
|---|---|---|
| FW001 | high | `INPUT` policy `ACCEPT` with no final `DROP` or `REJECT` rule |
| FW002 | high | `FORWARD` policy `ACCEPT` with no final `DROP` or `REJECT` rule |
| FW003 | high or medium | `INPUT` accepts a sensitive port from any source: databases, Docker API, Telnet, SMB, RDP, VNC and the like are high; SSH and FTP are medium |
| FW004 | high | an unconditional `-A INPUT -j ACCEPT` |
| FW005 | low | `INPUT` is closed but nothing accepts `ESTABLISHED,RELATED` traffic |
| FW006 | medium | `INPUT` accepts a range of 1000 or more ports from any source |
| FW000 | info | a rule line that could not be read |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- Only the `filter` table is judged. `nat` and `mangle` are read but not scored.
- A rule counts as restricted when it has `-s`, `-m set` or `-m iprange`. Interface and zone restrictions (`-i`) are not treated as a source limit.
- IPv6 (`ip6tables-save`) uses the same format and can be audited the same way, but the two rule sets are not compared.
- User chains are not followed: a jump into a custom chain is not expanded.
- Rules loaded by `nftables`, `firewalld` or cloud security groups are not covered.

## Where it fits

Linux hardening, CIS benchmark reviews and incident response: a quick read on what a saved ruleset really exposes.

## Tests

```bash
make test    # 53 checks, incl. 3000-case fuzzing and CLI exit codes
```

MIT.
