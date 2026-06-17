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
  header, so other sites stay protected). Falls back to global if no host.
- **Undo anything** — list all applied exclusions and remove them.
- **Engine control** — switch `SecRuleEngine` between On / DetectionOnly / Off.
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

### 3. Review / remove exclusions

**View applied exclusions** lists everything you've allowed. Click **Remove** to
re-enable a rule (Apache reloads again).

### 4. Engine & Core Rule Set settings

From the dashboard, open **Engine & Core Rule Set settings** to:

- Switch the engine mode (**On** / **DetectionOnly** / **Off**).
- **Install** and **enable** the OWASP Core Rule Set.
- Set the **Paranoia Level** (1 = fewest false positives … 4 = strictest) and
  the **inbound anomaly threshold** (lower = blocks more aggressively).

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

Even with dozens of Virtualmin domains, they all log to **one** error log. The
module groups by the `hostname` tag — no per-domain log files needed. (Set
`SecAuditLogFormat JSON` and `audit_format=json` in the module config for
cleaner parsing.)

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
- [x] SecRuleEngine toggle
- [x] CRS install / enable + Paranoia Level + anomaly threshold
- [ ] `SecRuleUpdateTargetById` (whitelist a single parameter, not the whole rule)
- [ ] IP whitelist
- [ ] Live log tail + attack statistics chart
- [ ] Config backup before each change

---

## License

MIT
