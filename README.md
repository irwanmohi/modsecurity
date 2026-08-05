# Virtualmin ModSecurity Manager

A Webmin/Virtualmin module to **view ModSecurity blocks and tune false positives
per virtual server** — without hand-editing CRS rules or per-domain Apache
configs.

It reads what ModSecurity has blocked, groups it by **Rule ID + domain**, and
lets you whitelist a rule for a single site with one click. It can also toggle
the rule engine and install/tune the OWASP Core Rule Set.

---

## Features

- **Dashboard** — every ModSecurity event grouped by Rule ID and domain, with
  hit counts, the rule message, and the last URI that triggered it.
- **One-click allow** — whitelist a rule for a single domain (scoped by `Host`
  header, so other sites stay protected) or globally. Optionally whitelist just
  one parameter of a rule instead of the whole rule (`ctl:ruleRemoveTargetById`).
- **Trusted IP whitelist** — let your admin/office IPs, monitoring, or payment
  callbacks bypass ModSecurity entirely (`@ipMatch`).
- **By-IP view + blocklist** — see attempts grouped by client IP (hits, blocks,
  domains targeted) and one-click **whitelist** a trusted IP or **block** an
  attacker (denied with 403).
- **Undo anything** — list all applied exclusions and remove them. Allowed
  rules are hidden from the dashboard so the list only shows what still needs
  attention.
- **Live log + statistics** — auto-refreshing tail of recent events, plus
  top-rules / top-domains breakdowns and a per-day events timeline.
- **Config backups** — changes are backed up (throttled to one per hour by
  default, with rotation); the Backups page restores any previous version with
  the same test-and-reload safety.
- **CRS version check & update** — see the installed CRS version, check the
  latest from OWASP (GitHub), and upgrade the package via apt from the UI.
- **Safe writes** — every config change is tested with `apache2ctl configtest`
  and automatically rolled back if it would break Apache.
- **Engine control** — switch `SecRuleEngine` between On / DetectionOnly / Off,
  globally or **per virtual server** (host-scoped `ctl:ruleEngine`).
- **OWASP CRS** — install, enable/disable, and set Paranoia Level + inbound
  anomaly threshold from the UI.
- **Safe by default** — every change runs `apache2ctl configtest` first and
  only reloads Apache if it passes.

---

## Requirements

- A server running **Webmin** (and usually **Virtualmin**).
- **Apache** with ModSecurity. On Ubuntu/Debian:

  ```bash
  sudo apt install libapache2-mod-security2 -y
  sudo a2enmod security2

  # Activate the recommended config:
  sudo mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  # Edit it and set:  SecRuleEngine On     (or DetectionOnly to start)

  sudo systemctl restart apache2
  ```

> You can do the `SecRuleEngine` step and CRS install from the module itself
> after it's installed — see [Usage](#usage).

### Platform support (Debian/Ubuntu and RHEL family)

The module auto-detects the web server. On Debian/Ubuntu it uses the `apache2`
paths (`apache2ctl`, `/var/log/apache2`, `/etc/apache2`, `apt`). On
**AlmaLinux/CentOS/RHEL (httpd)** it automatically switches to the `httpd`
equivalents — `apachectl`, `/var/log/httpd/error_log`, `/etc/httpd/conf.d`,
`/etc/httpd/conf.d/mod_security.conf`, `dnf`/`yum`, and writes its managed rule
files to `/etc/httpd/modsecurity.d/local_rules/`. Detection is in-memory only;
your saved Module Config is never overwritten, and you can still override any
path there. The **Logs** page shows the detected platform and effective paths.

> On RHEL the CRS package/paths vary by build — if CRS install/version checks
> don't work, set `crs_dir` / `crs_load` / `crs_setup` under Module Config. Also
> confirm your `mod_security.conf` includes `modsecurity.d/local_rules/*.conf`
> (the stock package usually does) so the allow/block rules are loaded.

---

## Installation

### Method 1 — Webmin UI (recommended)

1. Download the latest **`virtualmin-modsec.wbm.gz`** from the
   [Releases](https://github.com/irwanmohi/modsecurity/releases) page
   (or build it yourself — see below).
2. In Webmin go to **Webmin Configuration → Webmin Modules**.
3. Under **Install Module**, choose **From uploaded file**, select
   `virtualmin-modsec.wbm.gz`, and click **Install Module**.
4. Open the module under the **Others** or **Servers** category →
   **ModSecurity Manager**.

### Method 2 — Manual (SSH)

```bash
git clone https://github.com/irwanmohi/modsecurity.git
sudo cp -r modsecurity/virtualmin-modsec /usr/share/webmin/
sudo /usr/share/webmin/install-module.pl /usr/share/webmin/virtualmin-modsec
sudo systemctl restart webmin
```

### Build the .wbm.gz yourself

From the repo root:

```bash
tar czf virtualmin-modsec.wbm.gz virtualmin-modsec
```

The archive must contain the `virtualmin-modsec/` folder at its top level (with
`module.info` inside it) — that's what Webmin looks for.

---

## Usage

### 1. Dashboard

The main page shows ModSecurity's status and a table of everything that has been
blocked or flagged, **grouped by Rule ID and domain**:

| Rule ID | Domain | Hits | Message | Last URI | |
|---------|--------|------|---------|----------|-|
| 942100  | client-a.com | 14 | SQL Injection Attack… | /wp-admin/post.php | **Allow** |

Use the **domain filter** at the top to focus on one site.

### 2. Allow a rule (fix a false positive)

Click **Allow** next to a rule, confirm, and the module writes a host-scoped
exclusion so **that rule stops blocking that domain only**. Other rules and
other domains are unaffected. Apache is config-tested and reloaded
automatically.

The confirm screen offers a **scope** dropdown, pre-filled with the fields this
rule has actually flagged — read from the `found within …` data in your own
logs, so you are choosing from real culprits rather than guessing:

- **The whole rule** — the rule stops checking anything on this site. Simple,
  but the protection it gave is gone.
- **A single field** (e.g. `ARGS:jform[articletext]` for a Joomla article body)
  — the rule stops checking only that parameter and keeps protecting every
  other one. Prefer this whenever the log names a field.

A free-text box is there for fields the logs haven't shown yet.

> **Aggregate rules are flagged.** `949110` and `980130` fire because *other*
> rules scored enough points to cross the anomaly threshold — they are the
> scoring mechanism, not a detection. Allowing one switches off blocking for
> the site instead of fixing the false positive, so the screen warns you and
> points at the specific `941xxx`/`942xxx` entry to allow instead.

### Behind a reverse proxy (HAProxy, nginx, load balancer)

By default the IP whitelist and blocklist match `REMOTE_ADDR`, the address
Apache sees the connection coming from. **If this server sits behind a reverse
proxy, that address is the proxy** — so a whitelist would never let anyone
through and a blocklist would never stop anyone. Both fail silently.

Under **Module Config**, set *Where to read the visitor's IP from* to
**X-Forwarded-For**, and list your proxy/load-balancer addresses in *Trusted
proxy addresses*. The module then writes a chained rule that first proves the
request really came from one of those proxies, and only then matches the
forwarded IP:

```apache
SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" \
    "id:9200000,phase:1,pass,nolog,ctl:ruleEngine=Off,chain"
    SecRule REQUEST_HEADERS:X-Forwarded-For "@ipMatch 203.0.113.5"
```

The proxy check is mandatory — the module refuses to save without it. Matching
`X-Forwarded-For` on its own would let anyone send that header to bypass the
WAF or dodge a block. The IP pages show which mode is active.

Two caveats worth knowing:

- **`@ipMatch` expects a single address.** If `X-Forwarded-For` arrives with
  several comma-separated hops, the match can fail. Have the proxy set a single
  value (HAProxy: `http-request set-header X-Forwarded-For %[src]`).
- **The By-IP view and dashboard read the IP from Apache's error log**, which
  also shows the proxy unless Apache itself is resolving the real address.

Both are solved properly by **`mod_remoteip`**, which rewrites the address
Apache uses everywhere — logs included — so you can leave this setting on
*Connection address*:

```apache
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 10.0.0.1
```

Use `mod_remoteip` if you can; use the X-Forwarded-For mode when you can't.

### Trusted IP whitelist

Open **Trusted IP whitelist** from the dashboard and enter one IP or CIDR per
line (IPv4 or IPv6). Requests from those addresses bypass ModSecurity entirely
— ideal for your admin IP, monitoring probes, or payment-gateway callbacks that
keep tripping the rules.

### Events by IP (whitelist or block attackers)

Open **By IP** from the dashboard to see events grouped by the client IP that
caused them, with hit counts, how many were blocked, and which domains were
targeted. From there:

- **Whitelist** an IP you recognise (it bypasses ModSecurity) — useful when a
  legitimate client keeps tripping rules.
- **Block** an IP that's clearly attacking you — it's denied with HTTP 403 on
  every site. Manage the full list under **IP blocklist**.

### 3. Review / remove exclusions

**View applied exclusions** lists everything you've allowed. Click **Remove** to
re-enable a rule (Apache reloads again).

### 4. Engine & Core Rule Set settings

From the dashboard, open **Engine & Core Rule Set settings** to:

- Switch the engine mode (**On** / **DetectionOnly** / **Off**).
- **Install** and **enable** the OWASP Core Rule Set.
- Set the **Paranoia Level** (1 = fewest false positives … 4 = strictest) and
  the **inbound anomaly threshold** (lower = blocks more aggressively).
- See the **installed CRS version**, **Check latest from OWASP** (GitHub), and
  **Update CRS via apt**. The apt update installs the newest packaged version;
  major upstream jumps (3.x → 4.x) aren't auto-applied since they can break
  sites and need a manual migration.
- Enable **Application Exclusions** — tick WordPress, Drupal, Nextcloud,
  phpMyAdmin, etc. (auto-detected from the installed CRS) to load the CRS's
  ready-made false-positive exclusions for those apps.
- Turn on **DoS Protection** — basic per-IP rate limiting via the CRS DoS
  rules (max requests / time window / block duration). Note this is
  application-layer only; it is **not** a substitute for network DDoS
  protection (Cloudflare / your provider + fail2ban).

> **CMS tuning note:** OWASP CRS works fine with WordPress and Joomla — at
> **Paranoia Level 1** (the default). PL3–4 will flag normal CMS traffic as
> attacks. For WordPress, also tick its Application Exclusion. The CRS has no
> Joomla package, so for Joomla stay at PL1 and Allow the specific rules that
> false-positive (use DetectionOnly first to find them).

### Per-domain engine mode

Open **Per-domain engine mode** from the dashboard to set ModSecurity to
**Default / On / DetectionOnly / Off** for each virtual server independently.
"Default" means the domain follows the global engine setting. This is done with
host-scoped `ctl:ruleEngine` rules in
`/etc/modsecurity/virtualmin-modsec-domains.conf` — no vhost editing, and a
problem site can be set to DetectionOnly while every other site stays On.

### Per-path engine mode (CMS admin areas)

A whole domain is often too blunt. Editing an article in Joomla or WordPress
trips XSS and HTML-injection rules on the editor field, which would stop staff
saving content — but the public side of that same site is exactly where
scanners probe and must stay enforced.

Open **Per-path engine mode** and add a URL prefix with its own mode, e.g.
`/administrator/` → **Detection only**. Leave the domain blank to apply it to
every site, or pick one. The module writes to
`/etc/modsecurity/virtualmin-modsec-engine-paths.conf`:

```apache
# domain blank — applies to every site
SecRule REQUEST_URI "@beginsWith /administrator/" \
    "id:9400000,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"

# scoped to one domain
SecRule REQUEST_HEADERS:Host "@rx ^(?:www\.)?skm\.gov\.my(?::\d+)?$" \
    "id:9400001,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly,chain"
    SecRule REQUEST_URI "@beginsWith /administrator/"
```

Common prefixes: Joomla `/administrator/`, WordPress `/wp-admin/`, Drupal
`/admin/`. Matching is by prefix, so `/administrator/` covers everything below
it.

**Precedence** — path rules override the per-domain and global engine mode; a
whitelisted IP still overrides both. This comes from load order, which is why
the managed files are named the way they are.

> Treat a DetectionOnly admin area as temporary. Once a week or two of logs has
> accumulated, replace it with precise exclusions for the fields that actually
> trip — via **Allow** with a parameter, e.g. rule 941100 on
> `ARGS:jform[articletext]` — then delete the path rule so the admin area is
> enforced again.

> **Migrating a hand-written rule?** Delete it after adding the equivalent here.
> Two rules doing the same job is confusing, and if the old one uses an id in a
> range the module generates (`9000001+` exclusions, `9100000+` per-domain,
> `9200000` whitelist, `9300000` blocklist, `9400000+` per-path) Apache will
> refuse to start with *"Found another rule with the same id"* the next time
> that feature is used.

### Recommended workflow

1. Set the engine to **DetectionOnly** and install the CRS.
2. Let real traffic run for a few days — nothing is blocked, only logged.
3. On the dashboard, **Allow** any rule that's a false positive for a site.
4. Switch the engine to **On**.

This avoids breaking client sites while you tune the rules.

---

## How it works

### Where the "blocked" data comes from

ModSecurity logs every event to the Apache **error log** with structured tags:

```
[client 1.2.3.4] ModSecurity: Access denied with code 403 ...
[id "942100"] [msg "SQL Injection..."] [hostname "client-a.com"] [uri "/wp-admin/post.php"]
```

Virtualmin usually gives **each domain its own error log** (e.g.
`/home/<user>/logs/error_log`). The module auto-discovers them all by reading
the `ErrorLog` directive from every vhost under `/etc/apache2/sites-enabled`,
plus the globs in `extra_log_globs` (default `/home/*/logs/error_log` and
`/var/log/virtualmin/*_error_log`), and the global log. It then aggregates
events from every log and groups them by the `hostname` tag, so one dashboard
shows all domains. The status panel shows how many logs were scanned —
**Logs scanned → view** lists the exact files (handy if a domain is missing).

If your paths differ, set `log_files` (an explicit list), `apache_sites`, or
`extra_log_globs` under Module Config. (Set `SecAuditLogFormat JSON` and
`audit_format=json` for cleaner parsing if you use the audit log instead.)

> **Tip on which rules to allow:** rules `949110` (anomaly threshold) and
> `980130` (correlation) are *aggregate* rules — they fire because some other
> rule scored points. Don't allow these; allow the specific rule that actually
> matched (e.g. `942100` SQLi, `941180` XSS). The Action column shows which
> rules truly **BLOCKED** vs only **warning**.

### How "allow" works

Instead of editing each domain's vhost, the module writes **host-scoped runtime
exclusions** to a single file
(`/etc/modsecurity/virtualmin-modsec-exclusions.conf`, auto-loaded by the
default `IncludeOptional /etc/modsecurity/*.conf`):

```apache
# virtualmin-modsec: domain=client-a.com ruleid=942100
SecRule REQUEST_HEADERS:Host "@rx ^(?:www\.)?client-a\.com(?::\d+)?$" \
    "id:9000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

- `ctl:ruleRemoveById` is a **runtime** action, so config load order doesn't
  matter and it survives CRS updates.
- Scoped by `Host`, so allowing a rule for one site never weakens another.
- Leaving the domain empty writes a global `SecRuleRemoveById` instead.

**Why a regex and not an exact match** — Virtualmin lists a site as
`example.com` while visitors normally arrive as `www.example.com`, and the Host
header can carry a port. An exact comparison would simply never fire, silently.
The pattern is anchored at both ends, so it accepts the bare name, the `www.`
form and an optional `:port`, while `evil-example.com` and
`example.com.attacker.net` still do not match.

---

## Configuration

Edit paths under **Module Config** (gear/cog icon at the top of the module) if
your system differs from the defaults:

| Setting | Default |
|---------|---------|
| Apache error log | `/var/log/apache2/error.log` |
| ModSecurity audit log | `/var/log/apache2/modsec_audit.log` |
| Audit log format | `native` (or `json`) |
| Exclusion rules file | `/etc/modsecurity/virtualmin-modsec-exclusions.conf` |
| Main config | `/etc/modsecurity/modsecurity.conf` |
| CRS load file | `/usr/share/modsecurity-crs/owasp-crs.load` |
| CRS setup file | `/etc/modsecurity/crs/crs-setup.conf` |
| Apache test / reload | `apache2ctl configtest` / `systemctl reload apache2` |

> CRS paths vary by distro. The defaults match the Ubuntu/Debian
> `modsecurity-crs` package. If you installed CRS from GitHub, point
> `crs_load` and `crs_setup` at your install location.

---

## Changelog

### 0.25 — input validation, ACLs, and write safety

**Per-domain engine rules were generated without validating the domain name.**
Review `/etc/modsecurity/virtualmin-modsec-domains.conf` for anything you did
not intend before upgrading — a name that escaped its quoting would appear there
as extra Apache directives.

Apache parses that file as root at config load, so an unvalidated name was
arbitrary Apache configuration written by anyone who could reach the per-domain
form. The sibling function `write_path_engine` had always validated; only
`write_domain_engine` and its CGI were missing the check. Both now use one
shared `valid_domain_name()`, and `host_match_op()` refuses a name it cannot
safely turn into a pattern rather than escaping only the dot.

Also in this release:

- `write_domain_engine` now tests and rolls back like every other writer. A
  rejected config no longer stays on disk waiting for the next Apache restart
  to fail.
- **`acl_security.pl` added.** Without it Webmin rendered no ACL form, so the
  rights the code checks could never be granted or revoked and every check
  passed for anyone holding the module. They are now editable per user.
- The `view` right is enforced on the nine read-only pages, which previously
  showed log contents, visitor IPs and the full IP lists to any user.
- State-changing pages require POST, and removing an exclusion or path rule now
  asks for confirmation instead of acting on a bare link.
- Module config values are HTML-escaped on the Logs page.

**Default rights are unchanged** — `view`, `allow`, `remove` and `toggle` are
still granted by `defaultacl`. Restricting them by default would lock existing
administrators out of their own WAF controls on upgrade, which is its own risk;
in Webmin's model, assigning a user the module is the authorisation step. The
change that matters is that they can now be restricted at all. If you grant this
module to anyone beyond your administrators, set their rights explicitly.

As always, **upgrading does not rewrite rules already on disk.** Re-save the
per-domain engine modes from the UI to regenerate that file.

### 0.24 — `xff` mode never worked under `mod_remoteip`

**If this server runs `mod_remoteip` — the normal configuration behind a reverse
proxy — then any IP whitelist or blocklist configured with
`client_ip_source = xff` was inert.** Re-check those lists after upgrading.

`mod_remoteip` consumes `X-Forwarded-For` and removes it from the request
*before* ModSecurity's phase 1 runs, so rules matching
`REQUEST_HEADERS:X-Forwarded-For` can never fire. The mode was also unnecessary
there: `mod_remoteip` has already replaced `REMOTE_ADDR` with the genuine client
address, so `remote_addr` is not a fallback but the correct source.

The failure had the same shape as 0.23 — the UI showed the list, the config file
contained the rule, Apache accepted it, and it protected nobody.

**What changed.** The module now detects `mod_remoteip` (loaded *and* configured
with a `RemoteIPHeader`; loaded alone does nothing) and, when it is active,
matches on `REMOTE_ADDR` regardless of the configured mode. Overriding an
explicit setting is not something to do quietly, so it is stated on the IP pages
and written into the generated file's header comment. `xff` mode is unchanged
and still correct on servers without `mod_remoteip`, chained proxy check
included — this release is about detecting when it cannot work, not removing it.

As in 0.23, **upgrading does not rewrite rules already on disk.** Re-save the IP
whitelist and blocklist from the UI, then confirm what was written:

```bash
grep -E 'REMOTE_ADDR|X-Forwarded-For' /etc/modsecurity/virtualmin-modsec-ip*.conf
```

To check whether your server is affected, send one request carrying a forwarded
header plus an arbitrary marker, then read section B of the audit log. If the
marker appears and `X-Forwarded-For` does not, `mod_remoteip` consumed it:

```bash
curl -s -o /dev/null -H 'X-Forwarded-For: 203.0.113.99' -H 'X-Probe: abc123' https://<site>/
grep -A20 -- '-B--' /var/log/apache2/modsec_audit.log | tail -25
```

Guarded by `tests/remoteip-detection.t`, which exercises the real search against
a symlinked config directory — `grep -r` skips symlinks while recursing and
`conf-enabled/` is a directory of them, so a search written that way reports
"not configured" on a server where it plainly is.

### 0.23 — security fix, upgrade required

**Versions 0.18 to 0.22 did not enforce ModSecurity as configured** in two
cases. Both were silent: Apache accepted the config, the config file said
`SecRuleEngine On`, and the UI agreed.

In ModSecurity 2.x a non-disruptive action (`ctl`, `setvar`, `t:`) executes as
soon as the rule *carrying it* matches — it does not wait for the rest of a
chain. Only disruptive actions (`deny`, `block`, `drop`) are deferred. This
module put `ctl:ruleEngine=…` on chain starters, so the second condition
stopped gating anything.

| Affected | Effect |
|---|---|
| **Per-path engine mode with a domain set** | The mode applied to the whole site, not just the path. A `/administrator/` entry set to DetectionOnly left the entire site unenforced. |
| **IP whitelist with `client_ip_source=xff`** | The chain starter tested the *proxy's* address, true for every proxied request, so `ctl:ruleEngine=Off` fired on all traffic — a complete WAF bypass. |

The IP **blocklist** was not affected: it uses `deny`, which is disruptive and
correctly deferred until the whole chain matches.

**Upgrading the module is not enough.** The bad rules are already written to
disk and are not rewritten until something regenerates them. After updating,
re-save each per-path entry and the IP whitelist from the UI, then confirm on
disk that no line ending in `,chain"` contains `ctl:`:

```bash
grep -A2 'chain"' /etc/modsecurity/virtualmin-modsec-*.conf
```

Verify enforcement from the audit log rather than the config file or the UI —
it is the only place that reports the engine state *after* all `ctl` actions
have been applied:

```bash
grep Engine-Mode /var/log/apache2/modsec_audit.log | tail
```

Send the same payload to a host that matches a configured domain and to one
that does not, on a path *outside* any configured path. Both should now report
`ENABLED`. Two traps when testing: put the payload in a POST body or
`User-Agent`, not a query string (Joomla's stock `.htaccess` blocks `<script>`
in query strings itself and returns 403 before ModSecurity rules), and use
`grep -R` rather than `grep -r` on Apache config, since `sites-enabled/*.conf`
are symlinks that `-r` skips.

`tests/generated-rules.t` now asserts the invariant. Run it with
`perl tests/generated-rules.t`.

---

## Troubleshooting

### Apache won't start after installing the CRS

```
Could not open configuration file /etc/modsecurity/crs/crs-setup.conf: No such file or directory
```

The CRS loader (`owasp-crs.load`) requires `crs-setup.conf`, but some package
builds ship it only as a `.example`. Create the real file and restart:

```bash
sudo mkdir -p /etc/modsecurity/crs
sudo cp /etc/modsecurity/crs/crs-setup.conf.example \
        /etc/modsecurity/crs/crs-setup.conf   # adjust path if needed
sudo rm -f /etc/modsecurity/zz-virtualmin-crs.conf   # drop any duplicate include
sudo apache2ctl configtest && sudo systemctl restart apache2
```

Module **v0.2+** does this automatically (`ensure_crs_setup`) and won't add a
second include when Apache already loads the CRS itself.

### "Found another rule with the same id"

The CRS is being loaded twice — usually because both Apache's stock
`security2.conf` glob **and** the module's `zz-virtualmin-crs.conf` include it.
Remove the module's copy and reload:

```bash
sudo rm -f /etc/modsecurity/zz-virtualmin-crs.conf
sudo apache2ctl configtest && sudo systemctl restart apache2
```

---

## Uninstall

In **Webmin Configuration → Webmin Modules**, select **ModSecurity Manager**
under *Delete Modules* and remove it. The exclusion file it created
(`/etc/modsecurity/virtualmin-modsec-exclusions.conf`) is left in place — delete
it manually and reload Apache if you want the rules back to default.

---

## Roadmap

Ticked items are shipped. **Unticked items are not built yet** — there is no
setting for them in the module.

- [x] Dashboard with per-domain grouping
- [x] One-click allow / remove (host-scoped)
- [x] SecRuleEngine toggle (global)
- [x] Per-domain engine mode (On / DetectionOnly / Off)
- [x] Per-path engine mode (CMS admin areas)
- [x] CRS install / enable + Paranoia Level + anomaly threshold
- [x] Per-parameter whitelist (`ctl:ruleRemoveTargetById`)
- [x] Trusted IP whitelist (`@ipMatch`)
- [x] Auto-rollback on bad config
- [x] Live log tail (auto-refresh) + statistics (top rules/domains)
- [x] Hide already-allowed rules from the dashboard
- [x] Scan all per-domain Virtualmin error logs
- [x] Per-day attack timeline chart
- [x] Config backup + restore before each change (throttled + rotated)
- [x] Events grouped by client IP, with one-click whitelist / block
- [x] IP blocklist (deny 403)
- [x] CRS application exclusions (WordPress, Drupal, phpMyAdmin, …)
- [x] CRS version check (OWASP) + update via package manager
- [x] Auto-detect httpd (AlmaLinux/CentOS/RHEL) as well as apache2
- [x] DoS protection toggle (per-IP rate limiting via CRS)
- [ ] fail2ban integration (auto-ban repeat offenders at the firewall)
- [ ] Email/notification on attack spikes

**Out of scope:** network-layer (volumetric) DDoS protection. ModSecurity is a
Layer-7 WAF — use Cloudflare or your provider's DDoS service, plus fail2ban,
for that.

---

## License

MIT
