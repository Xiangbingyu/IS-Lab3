# Lab 3: TOCTOU race condition in a one-time coupon

**Start with the [Markdown laboratory report](report.md).** The report embeds
the [recorded experiment screenshot](evidence/run_screenshot.png) and the
[attack digraph](attack_digraph.png).

This is a local, simulated application, not a test against a real store. The
server binds to `127.0.0.1` on an ephemeral port and uses an in-memory coupon.
The demo user `alice` is a label, not a real account or authentication system.

## Reproduce

With Python 3.10 or newer, run from this directory:

```powershell
python .\toctou_lab.py --output .\evidence\run.json
```

No third-party Python packages are required for the experiment. Each scenario
starts with a fresh, unused coupon:

| Scenario | Requests | Expected HTTP status | Accepted |
| --- | --- | --- | --- |
| Vulnerable, sequential | A then B | 200, 409 | 1 |
| Vulnerable, parallel | A and B simultaneously | 200, 200 | 2 |
| Fixed, parallel | A and B simultaneously | 200, 409 in either order | 1 |

Run the regression tests with:

```powershell
python -m unittest discover -s . -p "test_*.py" -v
```

The vulnerable parallel case uses a two-party barrier **after** both requests
check the coupon. This deliberately widens the race window and makes the
underlying check/use flaw reproducible. It is not a measurement of how often
the flaw would occur in a real deployment.

`evidence/run.json` records the HTTP request fields, response status/headers/
body, per-request event sequence, and final coupon state. Request fields are
recorded by the client code; this is application-level evidence, not a packet
capture. Ports and request order can change between runs.

The screenshot is a browser view of the saved JSON results, not a screenshot
of terminal output or a packet capture.

## Repository files

| Path | Purpose |
| --- | --- |
| `toctou_lab.py` | Local-only server and three scenarios (standard library) |
| `test_toctou.py` | Regression tests for sequential, vulnerable and fixed paths |
| `report.md` | English Lab 3 report with inline screenshot and graph |
| `evidence/run.json` | Real HTTP-level records and server event sequence |
| `evidence/run_screenshot.png` | Browser screenshot displaying saved results |
| `attack_digraph.png` | State-transition digraph |

The Markdown report has placeholders for the student's surname/name and HDU
number; fill them in before submitting the repository. No DOCX or dependency
installation is required for the experiment itself.

The demonstration fix uses an in-process lock around both the check and
redemption. For production systems with multiple workers, use a database-level
atomic conditional update or an appropriately isolated transaction, plus a
uniqueness constraint where applicable. A per-process Python lock alone does
not protect across separate processes or machines.

Source references: [CWE-367](https://cwe.mitre.org/data/definitions/367.html),
[PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions),
and [OWASP Race Conditions](https://owasp.org/www-community/pages/vulnerabilities/race_conditions).
