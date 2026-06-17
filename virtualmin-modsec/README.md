# Virtualmin ModSecurity Manager

A Webmin/Virtualmin module (Perl) to view ModSecurity blocks and tune false
positives per virtual server — without editing CRS rules or per-domain Apache
configs by hand.

## What it does

- **Dashboard** (`index.cgi`) — reads the Apache error log (or JSON audit log),
  groups every ModSecurity event by **Rule ID + domain**, shows hit counts,
  message, and the last URI that triggered it.
- **Allow** (`allow.cgi`) — whitelists a rule for one domain (or globally).
- **Applied exclusions** (`list_exclusions.cgi` / `remove_exclusion.cgi`) —
  review and undo anything you've allowed.

## Where the "blocked" data comes from

ModSecurity logs every block to the Apache **error log** with structured tags:

```
[client 1.2.3.4] ModSecurity: Access denied with code 403 ...
[id "942100"] [msg "SQL Injection..."] [hostname "client-a.com"] [uri "/wp-admin/post.php"]
```

Even with 50 Virtualmin domains, they all log to **one** error log. The module
groups by the `hostname` tag, so per-domain data needs no extra log files.
(Set `SecAuditLogFormat JSON` and `audit_format=json` in config for cleaner
parsing.)

## How "allow" works (the key design choice)

Instead of editing each domain's Apache vhost, the module writes **Host-scoped
runtime exclusions** to a single file
(`/etc/modsecurity/virtualmin-modsec-exclusions.conf`, auto-loaded by the
default `IncludeOptional /etc/modsecurity/*.conf`):

```apache
# virtualmin-modsec: domain=client-a.com ruleid=942100
SecRule REQUEST_HEADERS:Host "@streq client-a.com" \
    "id:9000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

- `ctl:ruleRemoveById` is a **runtime** action, so config load order doesn't
  matter and it survives CRS updates.
- Scoped by `Host` header, so allowing a rule for `client-a.com` does **not**
  weaken `client-b.com`.
- Leaving the domain empty writes a global `SecRuleRemoveById` instead.

Every change runs `apache2ctl configtest` first and only reloads if it passes.

## Install (on the Ubuntu/Virtualmin server)

```bash
# Prereq (your usual setup):
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
sudo mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# set SecRuleEngine On in that file

# Install the module:
sudo cp -r virtualmin-modsec /usr/share/webmin/
sudo /usr/share/webmin/install-module.pl /usr/share/webmin/virtualmin-modsec
sudo systemctl restart webmin
```

Then open Webmin → Webmin Configuration → ModSecurity Manager (under Security).

## Roadmap / next steps

- [ ] `SecRuleEngine` toggle (On / DetectionOnly / Off) from the UI
- [ ] Install / enable OWASP CRS + Paranoia Level + anomaly threshold controls
- [ ] `SecRuleUpdateTargetById` (whitelist one parameter, safer than removing
      the whole rule)
- [ ] IP whitelist
- [ ] Live log tail + attack stats chart
- [ ] Config backup before each change
```
