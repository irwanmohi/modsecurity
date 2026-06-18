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

On the confirm screen you can optionally enter a **parameter** (e.g.
`ARGS:content`, `ARGS:email`, `REQUEST_COOKIES:sessionid`) to whitelist only
that field instead of disabling the whole rule — safer, since the rule still
protects every other parameter.

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
SecRule REQUEST_HEADERS:Host "@streq client-a.com" \
    "id:9000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

- `ctl:ruleRemoveById` is a **runtime** action, so config load order doesn't
  matter and it survives CRS updates.
- Scoped by `Host`, so allowing a rule for one site never weakens another.
- Leaving the domain empty writes a global `SecRuleRemoveById` instead.

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

- [x] Dashboard with per-domain grouping
- [x] One-click allow / remove (host-scoped)
- [x] SecRuleEngine toggle (global)
- [x] Per-domain engine mode (On / DetectionOnly / Off)
- [x] CRS install / enable + Paranoia Level + anomaly threshold
- [x] Per-parameter whitelist (`ctl:ruleRemoveTargetById`)
- [x] Trusted IP whitelist (`@ipMatch`)
- [x] Auto-rollback on bad config
- [x] Live log tail (auto-refresh) + statistics (top rules/domains)
- [x] Hide already-allowed rules from the dashboard
- [x] Scan all per-domain Virtualmin error logs
- [x] Per-day attack timeline chart
- [x] Config backup + restore before each change

---

## License

MIT
