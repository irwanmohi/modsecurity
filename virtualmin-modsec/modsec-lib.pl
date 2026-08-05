# modsec-lib.pl
# Core functions for the Virtualmin ModSecurity Manager module.

BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();
%access = &get_module_acl();
&platform_adjust();

# platform_adjust()
# Switch the shipped Debian/Ubuntu (apache2) defaults to the RHEL family
# (AlmaLinux/CentOS, httpd) equivalents when httpd is detected. Only values
# still at their Debian default are changed, so user overrides are respected.
# Changes are in-memory for this request only -- the saved config is untouched.
sub platform_adjust
{
return if (&has_command("apache2ctl"));            # Debian/Ubuntu: leave as-is
return if (!&has_command("apachectl") && !&has_command("httpd"));  # not httpd

my $lr = "/etc/httpd/modsecurity.d/local_rules";   # RHEL custom-rules dir
my %map = (
  apache_test        => [ "apache2ctl configtest", "apachectl configtest" ],
  apache_reload      => [ "systemctl reload apache2", "systemctl reload httpd" ],
  error_log          => [ "/var/log/apache2/error.log", "/var/log/httpd/error_log" ],
  apache_sites       => [ "/etc/apache2/sites-enabled", "/etc/httpd/conf.d" ],
  modsec_conf        => [ "/etc/modsecurity/modsecurity.conf",
			  "/etc/httpd/conf.d/mod_security.conf" ],
  exclusion_file     => [ "/etc/modsecurity/virtualmin-modsec-exclusions.conf",
			  "$lr/virtualmin-modsec-exclusions.conf" ],
  domain_engine_file => [ "/etc/modsecurity/virtualmin-modsec-domains.conf",
			  "$lr/virtualmin-modsec-domains.conf" ],
  path_engine_file   => [ "/etc/modsecurity/virtualmin-modsec-engine-paths.conf",
			  "$lr/virtualmin-modsec-engine-paths.conf" ],
  ip_whitelist_file  => [ "/etc/modsecurity/virtualmin-modsec-ipwhitelist.conf",
			  "$lr/virtualmin-modsec-ipwhitelist.conf" ],
  ip_blocklist_file  => [ "/etc/modsecurity/virtualmin-modsec-ipblock.conf",
			  "$lr/virtualmin-modsec-ipblock.conf" ],
  crs_enable_file    => [ "/etc/modsecurity/zz-virtualmin-crs.conf",
			  "$lr/zz-virtualmin-crs.conf" ],
  pkg_install        => [ "apt-get install -y", "dnf install -y" ],
  crs_pkg            => [ "modsecurity-crs", "mod_security_crs" ],
  );
foreach my $k (keys %map) {
	my ($deb, $rh) = @{$map{$k}};
	$config{$k} = $rh if ($config{$k} eq $deb);
	}
$config{'pkg_install'} = "yum install -y"
	if ($config{'pkg_install'} eq "dnf install -y" &&
	    !&has_command("dnf") && &has_command("yum"));
# Best-effort CRS locations (vary by RPM); only touch Debian defaults.
if ($config{'crs_dir'} eq "/usr/share/modsecurity-crs") {
	foreach my $d ("/usr/share/mod_modsecurity_crs", "/usr/lib/modsecurity.d",
		       "/etc/httpd/modsecurity.d") {
		if (-d $d) { $config{'crs_dir'} = $d; last; }
		}
	}
if ($config{'crs_setup'} eq "/etc/modsecurity/crs/crs-setup.conf") {
	foreach my $f ("/etc/httpd/modsecurity.d/crs-setup.conf",
		       "$config{'crs_dir'}/crs-setup.conf") {
		if (-r $f) { $config{'crs_setup'} = $f; last; }
		}
	}
}

# ensure_parent_dir($file)
# Create the directory that will hold $file if it doesn't exist (needed on RHEL
# where /etc/httpd/modsecurity.d/local_rules may be absent until we write).
sub ensure_parent_dir
{
my ($file) = @_;
my ($dir) = $file =~ m{^(.*)/[^/]+$};
&make_dir($dir, 0755) if ($dir && !-d $dir);
}

# can_access($action)
# Return true if the current user's ACL grants the named action.
sub can_access
{
return $access{$_[0]};
}

# require_post()
# Refuse a state-changing request that did not arrive by POST. Webmin's
# miniserv already checks the Referer, which is what actually blocks CSRF here;
# this makes the module safe on its own rather than relying entirely on a
# server setting it does not control, and it stops a change being triggered by
# a bare link.
sub require_post
{
$ENV{'REQUEST_METHOD'} eq 'POST' || &error($text{'err_post'});
}

# module_version()
# This module's own version, shown on the dashboard so you can tell at a glance
# which build a server is running -- useful when a feature is missing simply
# because the installed copy is older than the repo.
sub module_version
{
my %mi;
eval { %mi = &get_module_info($module_name); };
return $mi{'version'} if ($mi{'version'});
foreach my $f ("$module_root_directory/module.info", "module.info") {
	next if (!$f || !-r $f);
	foreach my $l (@{&read_file_lines($f, 1)}) {
		return $1 if ($l =~ /^version=(\S+)/);
		}
	}
return undef;
}

# modsec_footer(@args)
# Print a small "created by" credit, then the standard Webmin module footer.
# All module pages call this instead of ui_print_footer directly.
sub modsec_footer
{
print "<hr>\n";
print "<div style='text-align:center;font-size:11px;opacity:0.6;margin:6px 0'>",
      "Created by <a href='https://github.com/irwanmohi' target='_blank'>",
      "github.com/irwanmohi</a></div>\n";
&ui_print_footer(@_);
}

# get_engine_state()
# Returns the current SecRuleEngine value (On / DetectionOnly / Off / undef)
# by reading the main modsecurity.conf.
sub get_engine_state
{
my $conf = $config{'modsec_conf'};
return undef if (!-r $conf);
my $val;
open(my $fh, "<", $conf) || return undef;
while(my $l = <$fh>) {
	next if ($l =~ /^\s*#/);
	if ($l =~ /^\s*SecRuleEngine\s+(\S+)/i) {
		$val = $1;
		}
	}
close($fh);
return $val;
}

# parse_blocks()
# Reads the configured log file and returns a list of hash refs, one per
# ModSecurity event, with keys: id, msg, hostname, uri, client, action, time.
# Supports both the native error.log format and JSON audit log.
sub parse_blocks
{
if ($config{'audit_format'} eq 'json' && -r $config{'audit_log'}) {
	return &parse_blocks_json();
	}
return &parse_blocks_native();
}

# matched_target($logline)
# The request field a rule actually fired on, taken from the log's data tag:
#   [data "Matched Data: sos found within ARGS:video: ..."]
# yields "ARGS:video". This is what makes a precise exclusion possible -- the
# log already names the culprit, so nobody has to guess which field to
# whitelist. Returns undef when the rule logged no field (aggregate rules like
# 949110 score the whole request rather than one parameter).
sub matched_target
{
my ($line) = @_;
my ($data) = $line =~ /\[data\s+"([^"]*)"\]/;
return undef if (!$data);
# Field names can carry array subscripts, e.g. ARGS:jform[articletext].
return $1 if ($data =~ /found within ([A-Za-z_]+(?::[^:\s]+)?):/);
return undef;
}

# rule_targets($ruleid, $domain)
# The fields this rule has actually tripped on, most frequent first, so the
# Allow screen can offer real choices instead of a blank box. $domain may be
# empty to look across every site.
sub rule_targets
{
my ($ruleid, $domain) = @_;
my %seen;
foreach my $e (&parse_blocks()) {
	next if ($e->{'id'} ne $ruleid);
	next if ($domain ne "" && $e->{'hostname'} ne $domain);
	$seen{$e->{'target'}}++ if ($e->{'target'});
	}
return sort { $seen{$b} <=> $seen{$a} || $a cmp $b } keys %seen;
}

# is_aggregate_rule($id)
# True for the CRS rules that act on the accumulated anomaly score rather than
# on one request field -- the 949 (blocking evaluation) and 980 (correlation)
# families. They appear in the dashboard as the rules that "did the blocking",
# which makes them tempting to allow, but excluding one switches off the scoring
# mechanism itself instead of fixing a false positive. The real fix is to allow
# the specific rule that scored the points.
sub is_aggregate_rule
{
return $_[0] =~ /^9(?:49|80)\d{3}$/ ? 1 : 0;
}

# log_files()
# Return the list of Apache error logs to scan. Virtualmin gives every domain
# its own error log, so we gather them from each vhost's ErrorLog directive
# plus optional globs (home-dir logs), and always include the global one.
# An explicit "log_files" config overrides auto-discovery.
sub log_files
{
my @files;
if ($config{'log_files'} =~ /\S/) {
	@files = split(/\s+/, $config{'log_files'});
	}
else {
	push(@files, $config{'error_log'}) if ($config{'error_log'});
	# ErrorLog paths from each Apache/Virtualmin vhost.
	my $dir = $config{'apache_sites'};
	if ($dir && -d $dir) {
		foreach my $vf (glob("$dir/*.conf")) {
			my $lref = &read_file_lines($vf, 1);
			foreach my $l (@$lref) {
				next if ($l =~ /^\s*#/);
				if ($l =~ /^\s*ErrorLog\s+"?(\S+?)"?\s*$/i) {
					# Skip piped logs and unresolved variables.
					push(@files, $1) if ($1 =~ m{^/});
					}
				}
			}
		}
	# Extra globs (e.g. home-dir logs).
	foreach my $g (split(/\s+/, $config{'extra_log_globs'})) {
		push(@files, glob($g));
		}
	}
# Dedupe by physical file (device + inode) so symlinked duplicates are only
# scanned once. Virtualmin points /home/<user>/logs/error_log at the same file
# as /var/log/virtualmin/<domain>_error_log, so a plain path dedupe would
# double-count every event.
my (%seen, @out);
foreach my $f (@files) {
	next if (!$f || !-r $f);
	my @st = stat($f);
	my $key = @st ? "$st[0]:$st[1]" : $f;
	next if ($seen{$key}++);
	push(@out, $f);
	}
return @out;
}

# parse_blocks_native()
# Parse ModSecurity messages out of every discovered Apache error log.
sub parse_blocks_native
{
my @out;
my $per = $config{'max_lines'} || 20000;
foreach my $log (&log_files()) {
	# Read at most max_lines from the tail of each file to stay fast.
	foreach my $l (&tail_lines($log, $per)) {
		next if ($l !~ /ModSecurity:/);
		my %e;
		($e{'id'})       = $l =~ /\[id\s+"([^"]*)"\]/;
		($e{'msg'})      = $l =~ /\[msg\s+"([^"]*)"\]/;
		($e{'hostname'}) = $l =~ /\[hostname\s+"([^"]*)"\]/;
		($e{'uri'})      = $l =~ /\[uri\s+"([^"]*)"\]/;
		($e{'severity'}) = $l =~ /\[severity\s+"([^"]*)"\]/;
		$e{'target'} = &matched_target($l);
		($e{'client'})   = $l =~ /\[client\s+([^\]\s]+?)(?::\d+)?\]/;
		$e{'action'} = ($l =~ /Access denied/i) ? "blocked" : "warning";
		($e{'time'}) = $l =~ /^\[([^\]]+)\]/;
		next if (!$e{'id'});      # skip non-rule lines (startup, etc.)
		push(@out, \%e);
		}
	}
return @out;
}

# parse_blocks_json()
# Parse a JSON-format audit log (SecAuditLogFormat JSON). One JSON object
# per line. Requires the JSON Perl module to be available.
sub parse_blocks_json
{
my $log = $config{'audit_log'};
my @out;
return @out if (!-r $log);
eval { require JSON; };
if ($@) { return &parse_blocks_native(); }   # fall back if no JSON module
my @lines = &tail_lines($log, $config{'max_lines'} || 20000);
foreach my $l (@lines) {
	next if ($l !~ /^\s*\{/);
	my $j = eval { JSON::decode_json($l) };
	next if (!$j || !$j->{'transaction'});
	my $host = $j->{'request'}->{'headers'}->{'Host'} || $j->{'transaction'}->{'host'};
	my $uri  = $j->{'request'}->{'uri'};
	my $ip   = $j->{'transaction'}->{'remote_address'} || $j->{'transaction'}->{'client_ip'};
	my $time = $j->{'transaction'}->{'time'};
	foreach my $m (@{$j->{'audit_data'}->{'messages'} || []}) {
		my %e = (hostname => $host, uri => $uri, client => $ip, time => $time);
		($e{'id'})       = $m =~ /\[id\s+"([^"]*)"\]/;
		($e{'msg'})      = $m =~ /\[msg\s+"([^"]*)"\]/;
		($e{'severity'}) = $m =~ /\[severity\s+"([^"]*)"\]/;
		$e{'target'} = &matched_target($m);
		$e{'action'} = ($m =~ /denied/i) ? "blocked" : "warning";
		next if (!$e{'id'});
		push(@out, \%e);
		}
	}
return @out;
}

# group_blocks(\@events)
# Aggregate raw events by id+hostname. Returns a list of hash refs sorted by
# count descending, with keys: id, hostname, msg, count, last_uri, last_client.
sub group_blocks
{
my ($events) = @_;
my %g;
foreach my $e (@$events) {
	my $key = $e->{'id'} . "\0" . ($e->{'hostname'} || "");
	if (!$g{$key}) {
		$g{$key} = { id => $e->{'id'}, hostname => $e->{'hostname'},
			     msg => $e->{'msg'}, severity => $e->{'severity'},
			     action => 'warning', count => 0 };
		}
	$g{$key}->{'count'}++;
	# A group counts as "blocked" if any of its events were denied.
	$g{$key}->{'action'} = 'blocked' if ($e->{'action'} eq 'blocked');
	$g{$key}->{'last_uri'} = $e->{'uri'};
	$g{$key}->{'last_client'} = $e->{'client'};
	}
return sort { $b->{'count'} <=> $a->{'count'} } values %g;
}

# list_domains()
# Returns the list of Virtualmin domain names if the virtual-server module is
# available, otherwise an empty list (the UI then relies on log hostnames).
sub list_domains
{
my @doms;
if (&foreign_check("virtual-server")) {
	&foreign_require("virtual-server");
	@doms = map { $_->{'dom'} } &virtual_server::list_domains();
	}
return sort @doms;
}

# host_match_op($domain)
# The operator and argument that match a site's Host header.
# An exact match is wrong here: Virtualmin lists a site as "example.com" while
# visitors normally arrive as "www.example.com", and the header can carry a
# port. A strict comparison would simply never fire, with no error to show for
# it -- so accept the bare name, the www. form, and an optional :port.
sub host_match_op
{
my ($dom) = @_;
$dom = "" if (!defined $dom);
$dom =~ s/^www\.//i;         # normalise, so either form yields one pattern
# Refuse rather than escape. Escaping only the dot was safe by accident: two of
# the three callers happened to validate first. Anything else here would either
# break out of the quoted operator or act as a regex metacharacter and silently
# widen or narrow what the rule matches -- and a rule that matches the wrong
# hosts is exactly the failure this module keeps having. Callers still validate;
# this is the backstop, and it fails loudly instead of guessing.
return undef if (!&valid_domain_name($dom));
$dom =~ s/\./\\./g;          # the only metacharacter a valid hostname can hold
return '@rx ^(?:www\.)?'.$dom.'(?::\d+)?$';
}

# valid_domain_name($d)
# The single definition of what may be used as a site name in a generated rule.
# Apache parses these files as root at config load, so a name that escapes its
# quoting is arbitrary Apache configuration written by whoever can reach the
# form. Everything that builds or accepts a domain goes through here.
sub valid_domain_name
{
my ($d) = @_;
return 0 if (!defined $d || $d eq "" || length($d) > 253);
return $d =~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ ? 1 : 0;
}

# list_exclusions()
# Parse the managed exclusion file and return existing entries as hash refs
# with keys: ruleid, domain, genid (the generated SecRule id), line.
sub list_exclusions
{
my $f = $config{'exclusion_file'};
my @out;
return @out if (!-r $f);
my $lref = &read_file_lines($f, 1);
my $i = 0;
while ($i < @$lref) {
	if ($lref->[$i] =~ /^#\s*virtualmin-modsec:\s*domain=(\S*)\s+ruleid=(\S+?)(?:\s+target=(\S+))?\s*$/) {
		my ($dom, $rid, $tgt) = ($1, $2, $3);
		# Scan the block's rule lines for the generated id.
		my ($gid, $j) = (undef, $i + 1);
		while ($j < @$lref && $lref->[$j] ne "" &&
		       $lref->[$j] !~ /^#\s*virtualmin-modsec:/) {
			if ($lref->[$j] =~ /id:(\d+)/) { $gid = $1; last; }
			$j++;
			}
		push(@out, { domain => $dom, ruleid => $rid,
			     target => $tgt, genid => $gid });
		}
	$i++;
	}
return @out;
}

# next_gen_id()
# Pick the next free generated rule id, starting from id_base in config.
sub next_gen_id
{
my $base = $config{'id_base'} || 9000000;
my @ex = &list_exclusions();
my $max = $base;
foreach my $e (@ex) {
	$max = $e->{'genid'} if ($e->{'genid'} && $e->{'genid'} >= $max);
	}
return $max + 1;
}

# add_exclusion($ruleid, $domain, $target)
# Whitelist a rule using a runtime ctl action (order-independent, survives CRS
# updates). With $target set (e.g. "ARGS:content") only that parameter is
# removed from the rule; otherwise the whole rule is removed. With $domain set
# it is scoped to that site by Host header; otherwise it applies globally.
# Returns (1) on success or (0, error) on failure.
sub add_exclusion
{
my ($ruleid, $domain, $target) = @_;
$domain = "" if (!defined $domain);
$target = "" if (!defined $target);
$ruleid =~ /^\d+$/ || return (0, "Invalid rule id");
# An empty domain means "all sites" here, so only a non-empty one is checked.
$domain ne "" && !&valid_domain_name($domain) &&
	return (0, "Invalid domain: $domain");
$target ne "" && $target !~ /^[A-Za-z0-9_:\-\.\[\]]+$/ &&
	return (0, "Invalid target");
my $f = $config{'exclusion_file'};
my $old = -r $f ? &read_file_contents($f) : undef;
my @lines = -r $f ? @{&read_file_lines($f, 1)} : ();
if (!@lines) {
	push(@lines, "# Managed by Virtualmin ModSecurity Manager. Do not edit by hand.");
	}
my $gid = &next_gen_id();
my $ctl = $target ne "" ? "ctl:ruleRemoveTargetById=$ruleid;$target"
			: "ctl:ruleRemoveById=$ruleid";
push(@lines, "");
push(@lines, "# virtualmin-modsec: domain=$domain ruleid=$ruleid".
	     ($target ne "" ? " target=$target" : ""));
if ($domain) {
	my $host = &host_match_op($domain);
	$host || return (0, "Invalid domain: $domain");
	push(@lines, "SecRule REQUEST_HEADERS:Host \"$host\" \\");
	push(@lines, "    \"id:$gid,phase:1,pass,nolog,$ctl\"");
	}
else {
	push(@lines, "SecAction \\");
	push(@lines, "    \"id:$gid,phase:1,pass,nolog,$ctl\"");
	}
return &write_test_rollback($f, \@lines, $old);
}

# remove_exclusion($genid)
# Delete the exclusion block whose generated rule id is $genid, then reload.
# Parses block by block (marker .. blank/next marker) so it works for both the
# two-line SecRule/SecAction forms. Returns (1) or (0, error).
sub remove_exclusion
{
my ($genid) = @_;
my $f = $config{'exclusion_file'};
return (0, "No exclusion file") if (!-r $f);
my $old = &read_file_contents($f);
my $lref = &read_file_lines($f, 1);
my @out;
my $i = 0;
while ($i < @$lref) {
	if ($lref->[$i] =~ /^#\s*virtualmin-modsec:/) {
		my @block = ($lref->[$i]);
		my $j = $i + 1;
		while ($j < @$lref && $lref->[$j] ne "" &&
		       $lref->[$j] !~ /^#\s*virtualmin-modsec:/) {
			push(@block, $lref->[$j]);
			$j++;
			}
		my ($bid) = join("\n", @block) =~ /id:(\d+)/;
		if (defined $bid && $bid == $genid) {
			# Drop this block plus one preceding blank line.
			pop(@out) if (@out && $out[$#out] =~ /^\s*$/);
			$i = $j;
			next;
			}
		push(@out, @block);
		$i = $j;
		next;
		}
	push(@out, $lref->[$i]);
	$i++;
	}
return &write_test_rollback($f, \@out, $old);
}

# apply_changes()
# Run the Apache config test; if it passes, reload. Returns (1) or (0, output).
sub apply_changes
{
my $out = &backquote_command("$config{'apache_test'} 2>&1");
if ($? != 0) {
	return (0, "Apache config test failed:\n$out");
	}
$out = &backquote_command("$config{'apache_reload'} 2>&1");
if ($? != 0) {
	return (0, "Apache reload failed:\n$out");
	}
return (1);
}

# write_test_rollback($file, \@newlines, $oldcontent)
# Write @newlines to $file and apply. If Apache's config test fails, restore
# the previous content (or delete the file if it was new) so a bad edit can
# never leave Apache unable to start. Returns (1) or (0, error).
sub write_test_rollback
{
my ($file, $newlines, $old) = @_;
&ensure_parent_dir($file);
&backup_file($file);
&open_tempfile(my $FH, ">$file", 1) || return (0, "Cannot write $file");
&print_tempfile($FH, join("\n", @$newlines)."\n");
&close_tempfile($FH);
my ($ok, $err) = &apply_changes();
return (1) if ($ok);
if (defined $old) {
	&open_tempfile(my $F2, ">$file", 1);
	&print_tempfile($F2, $old);
	&close_tempfile($F2);
	}
else {
	unlink($file) if (-e $file);
	}
return (0, $err);
}

# event_date($timestring)
# Normalise a log timestamp to YYYY-MM-DD, or undef if unparseable.
sub event_date
{
my ($t) = @_;
return undef if (!$t);
my %mon = (Jan=>'01',Feb=>'02',Mar=>'03',Apr=>'04',May=>'05',Jun=>'06',
	   Jul=>'07',Aug=>'08',Sep=>'09',Oct=>'10',Nov=>'11',Dec=>'12');
# Native Apache: "Thu Jun 18 01:08:07.421795 2026"
if ($t =~ /^\w+\s+(\w{3})\s+(\d+)\s+[\d:.]+\s+(\d{4})/) {
	return $mon{$1} ? sprintf("%04d-%s-%02d", $3, $mon{$1}, $2) : undef;
	}
# ISO: "2026-06-18..."
return "$1-$2-$3" if ($t =~ /^(\d{4})-(\d{2})-(\d{2})/);
# CLF style: "18/Jun/2026:..."
if ($t =~ m{^(\d{1,2})/(\w{3})/(\d{4})}) {
	return $mon{$2} ? sprintf("%04d-%s-%02d", $3, $mon{$2}, $1) : undef;
	}
return undef;
}

# --- Config backups -------------------------------------------------------

# backup_file($file)
# Copy $file into the backup directory with a timestamp before it is changed,
# pruning to the configured retention count. Silently does nothing if the file
# doesn't exist yet (nothing to back up).
sub backup_file
{
my ($file) = @_;
return if (!$file || !-r $file);
my $dir = $config{'backup_dir'} || "/etc/modsecurity/virtualmin-modsec-backups";
&make_dir($dir, 0700) if (!-d $dir);
my ($base) = $file =~ m{([^/]+)$};
# Throttle: keep at most one backup per backup_interval seconds (default
# hourly) so frequent edits don't pile up. Rotation is handled below.
my $interval = $config{'backup_interval'};
$interval = 3600 if (!defined $interval || $interval eq '');
if ($interval > 0) {
	my @prev = sort glob("$dir/$base.*");
	if (@prev) {
		my $mtime = (stat($prev[-1]))[9];
		return if ($mtime && (time() - $mtime) < $interval);
		}
	}
my @t = localtime();
my $ts = sprintf("%04d%02d%02d-%02d%02d%02d",
		 $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
# Keep the filename unique even for several changes in the same second.
my $dest = "$dir/$base.$ts";
my $n = 1;
while (-e $dest) { $dest = "$dir/$base.$ts.$n"; $n++; }
&copy_source_dest($file, $dest);
# Prune old backups of this file.
my $keep = $config{'backup_keep'} || 30;
my @b = sort glob("$dir/$base.*");
while (@b > $keep) { unlink(shift(@b)); }
}

# list_backups()
# Return all backups newest-first as hash refs: file, name, base, ts, size.
sub list_backups
{
my $dir = $config{'backup_dir'} || "/etc/modsecurity/virtualmin-modsec-backups";
my @out;
return @out if (!-d $dir);
foreach my $f (reverse sort glob("$dir/*")) {
	next if (!-f $f);
	my ($name) = $f =~ m{([^/]+)$};
	my ($base, $ts) = $name =~ /^(.*)\.(\d{8}-\d{6})(?:\.\d+)?$/;
	next if (!$ts);
	push(@out, { file => $f, name => $name, base => $base,
		     ts => $ts, size => (stat($f))[7] });
	}
return @out;
}

# managed_paths()
# The live config files this module edits (used to map a backup back to its
# original location on restore).
sub managed_paths
{
my @keys = qw(modsec_conf crs_setup exclusion_file domain_engine_file
	      path_engine_file ip_whitelist_file ip_blocklist_file
	      crs_enable_file);
return grep { $_ } map { $config{$_} } @keys;
}

# restore_backup($name)
# Restore the backup named $name (basename only) over its original file, with
# the usual test-and-rollback safety. Returns (1) or (0, error).
sub restore_backup
{
my ($name) = @_;
$name =~ m{/} && return (0, "Invalid backup name");
my ($base) = $name =~ /^(.*)\.\d{8}-\d{6}(?:\.\d+)?$/;
$base || return (0, "Invalid backup name");
my $dir = $config{'backup_dir'} || "/etc/modsecurity/virtualmin-modsec-backups";
my $src = "$dir/$name";
-r $src || return (0, "Backup not found");
my ($target) = grep { m{(?:^|/)\Q$base\E$} } &managed_paths();
$target || return (0, "Unknown original location for $base");
my $old = -r $target ? &read_file_contents($target) : undef;
my @lines = split(/\n/, &read_file_contents($src));
return &write_test_rollback($target, \@lines, $old);
}

# get_ip_whitelist()
# Return the list of trusted IPs/CIDRs that bypass ModSecurity.
sub get_ip_whitelist
{
my @ips;
my $f = $config{'ip_whitelist_file'};
return @ips if (!-r $f);
my $lref = &read_file_lines($f, 1);
foreach my $l (@$lref) {
	if ($l =~ /^#\s*virtualmin-modsec-ipwhitelist:\s*(.*\S)/) {
		@ips = split(/\s*,\s*/, $1);
		}
	}
return @ips;
}

# valid_ip_entry($ip)
# Loosely validate an IPv4/IPv6 address with optional CIDR suffix.
sub valid_ip_entry
{
my ($ip) = @_;
return 1 if ($ip =~ /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/);       # IPv4
return 1 if ($ip =~ /:/ && $ip =~ /^[0-9a-fA-F:]+(\/\d{1,3})?$/); # IPv6
return 0;
}

# ip_rule_lines($gid, $list, $rule_actions, $ctl)
# Build the SecRule lines that match the visitor's IP against $list. Behind a
# reverse proxy (HAProxy, nginx, a load balancer) REMOTE_ADDR is the proxy's
# address, not the visitor's, so plain REMOTE_ADDR rules never match --
# whitelists let nobody through and blocklists stop nobody. In "xff" mode we
# chain two conditions: first prove the request really arrived from a trusted
# proxy, then match the forwarded client IP. The proxy check is not optional --
# matching X-Forwarded-For alone would let anyone spoof that header to bypass
# the WAF (whitelist) or dodge a block.
#
# $ctl is a separate argument, deliberately. See the chain-action note above
# write_path_engine: a non-disruptive action fires the moment the rule carrying
# it matches, so ctl:ruleEngine=Off on the chain starter here would disable the
# engine for every request arriving through the proxy -- a total WAF bypass,
# since the starter tests the proxy's own address. It must ride on the final
# link, the one testing the client IP. Disruptive actions behave the opposite
# way: deny waits for the whole chain, so the blocklist correctly leaves it in
# $rule_actions and passes no $ctl at all.
# Returns (\@lines) on success, or (undef, $error).
sub ip_rule_lines
{
my ($gid, $list, $rule_actions, $ctl) = @_;
$ctl = "" if (!defined $ctl);
if (&client_ip_source() ne 'xff') {
	# One unchained rule, so everything can sit on it safely.
	return ([ "SecRule REMOTE_ADDR \"\@ipMatch $list\" \\",
		  "    \"id:$gid,$rule_actions".($ctl ? ",$ctl" : "")."\"" ]);
	}
my ($plist, $perr) = &trusted_proxy_list();
$plist || return (undef, $perr);
return ([ "SecRule REMOTE_ADDR \"\@ipMatch $plist\" \\",
	  "    \"id:$gid,$rule_actions,chain\"",
	  "    SecRule REQUEST_HEADERS:X-Forwarded-For \"\@ipMatch $list\"".
	  ($ctl ? " \"$ctl\"" : "") ]);
}

# apache_config_root()
# The Apache configuration directory, derived from the vhost directory the
# module already knows about: /etc/apache2/sites-enabled -> /etc/apache2,
# /etc/httpd/conf.d -> /etc/httpd. Reusing that setting keeps one source of
# truth rather than introducing a second way to locate Apache.
sub apache_config_root
{
my $d = $config{'apache_sites'};
return undef if (!$d);
$d =~ s{/+$}{};
$d =~ s{/[^/]+$}{};
return $d;
}

# remoteip_loaded()
# True if mod_remoteip is loaded, asked of the same Apache control binary the
# module already uses for configtest.
sub remoteip_loaded
{
my ($ctl) = split(/\s+/, $config{'apache_test'});
return 0 if (!$ctl);
my $out = &backquote_command("$ctl -M 2>/dev/null");
return $out =~ /remoteip_module/ ? 1 : 0;
}

# remoteip_header_configured()
# True if a RemoteIPHeader directive exists anywhere in the Apache config tree.
# Being loaded is not enough -- without RemoteIPHeader the module does nothing.
#
# SEARCH TRAP: this uses grep -R, not -r. The lowercase form does not follow
# symlinks while recursing, and sites-enabled/ and conf-enabled/ are entire
# directories of symlinks -- on Debian the directive normally lives in
# conf-enabled/remoteip.conf, a symlink. Using -r here would report "not
# configured" on a server where it plainly is, which would defeat the whole
# point of this detection.
sub remoteip_header_configured
{
my $root = &apache_config_root();
return 0 if (!$root || !-d $root);
my $out = &backquote_command(
	"grep -RIl -E '^[[:space:]]*RemoteIPHeader[[:space:]]' ".
	quotemeta($root)." 2>/dev/null");
return $out =~ /\S/ ? 1 : 0;
}

# remoteip_active()
# True when mod_remoteip is both loaded and actually configured. Cached for the
# request, since it shells out twice. Tests reset $remoteip_cache directly.
our $remoteip_cache;
sub remoteip_active
{
return $remoteip_cache if (defined $remoteip_cache);
$remoteip_cache = (&remoteip_loaded() && &remoteip_header_configured()) ? 1 : 0;
return $remoteip_cache;
}

# client_ip_source()
# Where the visitor's IP is actually read from: "remote_addr" (direct
# connections, and anywhere mod_remoteip is doing its job) or "xff" (behind a
# reverse proxy with no mod_remoteip).
#
# mod_remoteip consumes X-Forwarded-For and removes it from the request before
# ModSecurity's phase 1 runs, so rules matching REQUEST_HEADERS:X-Forwarded-For
# can never fire on such a server -- a whitelist configured that way silently
# protects nobody and a blocklist stops nobody. mod_remoteip has meanwhile put
# the genuine client address into REMOTE_ADDR, so remote_addr is not a fallback
# here, it is the correct source. We therefore override the setting rather than
# emit rules that are known to be inert. The override is disclosed in the
# generated file's header and on the IP pages -- see client_ip_source_overridden.
sub client_ip_source
{
my $want = $config{'client_ip_source'} eq 'xff' ? 'xff' : 'remote_addr';
return 'remote_addr' if ($want eq 'xff' && &remoteip_active());
return $want;
}

# client_ip_source_overridden()
# True when the configured source was xff but mod_remoteip forced remote_addr.
sub client_ip_source_overridden
{
return ($config{'client_ip_source'} eq 'xff' && &remoteip_active()) ? 1 : 0;
}

# ip_source_header_comment()
# Header lines recording the override in the generated file itself, so someone
# reading the config on disk is not left wondering why it says REMOTE_ADDR when
# the module config asked for X-Forwarded-For.
sub ip_source_header_comment
{
return () if (!&client_ip_source_overridden());
return ("# NOTE: module config requests X-Forwarded-For, but mod_remoteip is",
	"# active here. It consumes that header before ModSecurity evaluates,",
	"# so such rules could never match, and it has already placed the real",
	"# client address in REMOTE_ADDR. These rules match REMOTE_ADDR instead.");
}

# trusted_proxy_list()
# Validated, comma-joined list of proxy addresses for the chain check.
# Returns (undef, $error) when unset or malformed, since an unverified
# X-Forwarded-For match would be a security hole rather than a fix.
sub trusted_proxy_list
{
my @prox;
foreach my $p (split(/[\s,]+/, $config{'trusted_proxies'})) {
	next if ($p eq "");
	&valid_ip_entry($p) ||
		return (undef, "Invalid trusted proxy address: $p");
	push(@prox, $p);
	}
@prox || return (undef,
	"Reverse-proxy mode is on but no trusted proxy addresses are set. ".
	"Add your proxy/load-balancer IPs under Module Config, otherwise ".
	"anyone could spoof X-Forwarded-For to bypass or dodge these rules.");
return (join(",", @prox));
}

# ip_mode_note()
# One line describing how visitor IPs are currently matched, shown on the IP
# pages so a wrong proxy setting is visible instead of silently doing nothing.
sub ip_mode_note
{
if (&client_ip_source_overridden()) {
	return "<font color=#cc8800><b>".$text{'ip_mode_remoteip'}."</b></font>";
	}
if (&client_ip_source() eq 'xff') {
	my ($plist, $perr) = &trusted_proxy_list();
	return "<font color=#cc0000>".&html_escape($perr)."</font>" if (!$plist);
	return &text('ip_mode_xff', "<tt>".&html_escape($plist)."</tt>");
	}
return $text{'ip_mode_direct'};
}

# set_ip_whitelist(\@ips)
# Replace the trusted-IP whitelist with @ips (one ipMatch rule that turns the
# engine off for those addresses), then reload with rollback on failure.
sub set_ip_whitelist
{
my ($ips) = @_;
my @clean;
foreach my $ip (@$ips) {
	$ip =~ s/^\s+|\s+$//g;
	next if ($ip eq "");
	&valid_ip_entry($ip) || return (0, "Invalid IP/CIDR: $ip");
	push(@clean, $ip);
	}
my $f = $config{'ip_whitelist_file'};
my $old = -r $f ? &read_file_contents($f) : undef;
if (!@clean) {
	# Back up before removing: clearing a list is exactly the change
	# you would want to undo, and the other writers already do this.
	&backup_file($f);
	unlink($f) if (-e $f);
	return &apply_changes();
	}
my $gid = ($config{'id_base'} || 9000000) + 200000;
my $list = join(",", @clean);
my ($rule, $rerr) = &ip_rule_lines($gid, $list, "phase:1,pass,nolog",
				   "ctl:ruleEngine=Off");
$rule || return (0, $rerr);
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - trusted IP whitelist.",
	&ip_source_header_comment(),
	"# virtualmin-modsec-ipwhitelist: $list",
	@$rule);
return &write_test_rollback($f, \@lines, $old);
}

# add_ip_whitelist($ip)
# Append a single IP to the trusted whitelist (no-op if already present).
sub add_ip_whitelist
{
my ($ip) = @_;
$ip =~ s/^\s+|\s+$//g;
&valid_ip_entry($ip) || return (0, "Invalid IP/CIDR: $ip");
my @ips = &get_ip_whitelist();
return (1) if (grep { $_ eq $ip } @ips);
push(@ips, $ip);
return &set_ip_whitelist(\@ips);
}

# get_ip_blocklist()
# Return the list of IPs/CIDRs that are denied outright.
sub get_ip_blocklist
{
my @ips;
my $f = $config{'ip_blocklist_file'};
return @ips if (!-r $f);
foreach my $l (@{&read_file_lines($f, 1)}) {
	if ($l =~ /^#\s*virtualmin-modsec-ipblocklist:\s*(.*\S)/) {
		@ips = split(/\s*,\s*/, $1);
		}
	}
return @ips;
}

# set_ip_blocklist(\@ips)
# Replace the IP blocklist with @ips (one ipMatch rule that denies them with
# 403), then reload with rollback on failure.
sub set_ip_blocklist
{
my ($ips) = @_;
my @clean;
foreach my $ip (@$ips) {
	$ip =~ s/^\s+|\s+$//g;
	next if ($ip eq "");
	&valid_ip_entry($ip) || return (0, "Invalid IP/CIDR: $ip");
	push(@clean, $ip);
	}
my $f = $config{'ip_blocklist_file'};
my $old = -r $f ? &read_file_contents($f) : undef;
if (!@clean) {
	# Back up before removing: clearing a list is exactly the change
	# you would want to undo, and the other writers already do this.
	&backup_file($f);
	unlink($f) if (-e $f);
	return &apply_changes();
	}
my $gid = ($config{'id_base'} || 9000000) + 300000;
my $list = join(",", @clean);
my ($rule, $rerr) = &ip_rule_lines($gid, $list,
	"phase:1,deny,status:403,log,msg:'IP blocked by ModSecurity Manager'");
$rule || return (0, $rerr);
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - IP blocklist.",
	&ip_source_header_comment(),
	"# virtualmin-modsec-ipblocklist: $list",
	@$rule);
return &write_test_rollback($f, \@lines, $old);
}

# add_ip_blocklist($ip)
# Append a single IP to the blocklist (no-op if already present).
sub add_ip_blocklist
{
my ($ip) = @_;
$ip =~ s/^\s+|\s+$//g;
&valid_ip_entry($ip) || return (0, "Invalid IP/CIDR: $ip");
my @ips = &get_ip_blocklist();
return (1) if (grep { $_ eq $ip } @ips);
push(@ips, $ip);
return &set_ip_blocklist(\@ips);
}

# group_by_ip(\@events)
# Aggregate events by client IP. Returns hash refs sorted by hit count desc:
# ip, count, blocked, domains (hashref), last_id, last_uri, last_msg.
sub group_by_ip
{
my ($events) = @_;
my %g;
foreach my $e (@$events) {
	my $ip = $e->{'client'} || "-";
	$g{$ip} ||= { ip => $ip, count => 0, blocked => 0, domains => {} };
	$g{$ip}->{'count'}++;
	$g{$ip}->{'blocked'}++ if ($e->{'action'} eq 'blocked');
	$g{$ip}->{'domains'}->{$e->{'hostname'}}++ if ($e->{'hostname'});
	$g{$ip}->{'last_id'}  = $e->{'id'};
	$g{$ip}->{'last_uri'} = $e->{'uri'};
	$g{$ip}->{'last_msg'} = $e->{'msg'};
	}
return sort { $b->{'count'} <=> $a->{'count'} } values %g;
}

# set_engine_state($value)
# Set SecRuleEngine in modsecurity.conf to On / DetectionOnly / Off, then
# reload Apache. Returns (1) or (0, error).
sub set_engine_state
{
my ($val) = @_;
$val =~ /^(On|Off|DetectionOnly)$/ || return (0, "Invalid engine value");
my $conf = $config{'modsec_conf'};
return (0, "Cannot read $conf") if (!-r $conf);
my $lref = &read_file_lines($conf);
my $found = 0;
foreach my $l (@$lref) {
	if ($l =~ /^\s*SecRuleEngine\s+/i) {
		$l = "SecRuleEngine $val";
		$found = 1;
		}
	}
push(@$lref, "SecRuleEngine $val") if (!$found);
&backup_file($conf);
&flush_file_lines($conf);
return &apply_changes();
}

# crs_installed()
# True if the OWASP Core Rule Set appears to be installed on disk.
sub crs_installed
{
return (-d $config{'crs_dir'} || -r $config{'crs_load'}) ? 1 : 0;
}

# crs_enabled()
# True if the CRS is actually loaded -- either via our managed include, or via
# Apache's stock security2.conf glob with crs-setup.conf in place.
sub crs_enabled
{
return 1 if (-r $config{'crs_enable_file'});
return 1 if (&package_loads_crs() && -r $config{'crs_setup'});
return 0;
}

# package_loads_crs()
# True if Apache's stock security2.conf already globs the CRS loader. If so we
# must NOT add a second include, or every rule loads twice and Apache refuses
# to start ("another rule with the same id").
sub package_loads_crs
{
foreach my $c ("/etc/apache2/mods-enabled/security2.conf",
	       "/etc/apache2/mods-available/security2.conf",
	       $config{'modsec_conf'}) {
	next if (!$c || !-r $c);
	foreach my $l (@{&read_file_lines($c, 1)}) {
		next if ($l =~ /^\s*#/);
		return 1 if ($l =~ /modsecurity[-_]crs.*\.load/i ||
			     ($config{'crs_load'} && $l =~ /\Q$config{'crs_load'}\E/));
		}
	}
return 0;
}

# ensure_crs_setup()
# owasp-crs.load hard-Includes crs-setup.conf. Some package builds ship it only
# as a .example, so Apache won't start until the real file exists. Create it
# from whatever template we can find. Returns 1 if the file exists afterwards.
sub ensure_crs_setup
{
my $target = $config{'crs_setup'};
return 1 if (-r $target);
my ($dir) = $target =~ m{^(.*)/[^/]+$};
&make_dir($dir, 0755) if ($dir && !-d $dir);
foreach my $ex ($target.".example",
		"$config{'crs_dir'}/crs-setup.conf.example",
		"$config{'crs_dir'}/crs-setup.conf") {
	if ($ex ne $target && -r $ex) {
		&copy_source_dest($ex, $target);
		return 1 if (-r $target);
		}
	}
return 0;
}

# install_crs()
# Install the CRS package, then ensure it is enabled. Returns (1) or (0, err).
sub install_crs
{
my $out = &backquote_logged(
	"$config{'pkg_install'} $config{'crs_pkg'} 2>&1");
if ($? != 0) {
	return (0, "Package install failed:\n$out");
	}
return &enable_crs();
}

# enable_crs()
# Make sure crs-setup.conf exists (or Apache won't start), then load the CRS.
# Only adds our own include if Apache's stock config doesn't already load it,
# to avoid loading every rule twice.
sub enable_crs
{
&crs_installed() || return (0, "CRS is not installed");
&ensure_crs_setup() ||
	return (0, "Could not create $config{'crs_setup'} (no template found). ".
		   "CRS not enabled to avoid breaking Apache.");
my $f = $config{'crs_enable_file'};
&ensure_parent_dir($f);
&backup_file($f);
if (&package_loads_crs()) {
	# Apache already loads the CRS itself; make sure our include is gone so
	# rules don't load twice.
	unlink($f) if (-e $f);
	}
else {
	&open_tempfile(my $FH, ">$f", 1) || return (0, "Cannot write $f");
	&print_tempfile($FH, "# Managed by Virtualmin ModSecurity Manager.\n");
	&print_tempfile($FH, "IncludeOptional $config{'crs_load'}\n");
	&close_tempfile($FH);
	}
return &apply_changes();
}

# disable_crs()
# Remove our managed include and reload. If Apache loads the CRS via its own
# stock config, report that the user must disable it there.
sub disable_crs
{
my $f = $config{'crs_enable_file'};
&backup_file($f);
unlink($f) if (-e $f);
if (&package_loads_crs()) {
	return (0, "The CRS is loaded by Apache's own security2.conf. ".
		   "Disable it there (or run 'a2dismod security2') to turn it off.");
	}
return &apply_changes();
}

# list_domain_engine()
# Return a hash of domain => engine mode (On/Off/DetectionOnly) for every
# per-domain override currently configured.
sub list_domain_engine
{
my %map;
my $f = $config{'domain_engine_file'};
return %map if (!-r $f);
my $lref = &read_file_lines($f, 1);
foreach my $l (@$lref) {
	if ($l =~ /^#\s*virtualmin-modsec-engine:\s*domain=(\S+)\s+mode=(\S+)/) {
		$map{$1} = $2;
		}
	}
return %map;
}

# write_domain_engine(\%map)
# Rewrite the per-domain engine file from a domain => mode hash. Modes of
# "default" (or empty) are skipped (the domain inherits the global engine).
# If nothing is left, the file is removed. Returns (1) or (0, error).
sub write_domain_engine
{
my ($map) = @_;
my $f = $config{'domain_engine_file'};
my $old = -r $f ? &read_file_contents($f) : undef;
my @active = grep { $map->{$_} && $map->{$_} ne 'default' } keys %$map;
if (!@active) {
	&backup_file($f);
	unlink($f) if (-e $f);
	return &apply_changes();
	}
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - per-domain engine modes.",
	"# Do not edit by hand.");
# Use a separate id range so these never clash with allow exclusions.
my $gid = ($config{'id_base'} || 9000000) + 100000;
foreach my $dom (sort @active) {
	my $mode = $map->{$dom};
	# Reject rather than skip. A silently dropped entry looks to the user
	# exactly like one that was applied, which is the failure mode this
	# module has repeatedly shipped.
	$mode =~ /^(On|Off|DetectionOnly)$/ ||
		return (0, "Invalid mode for $dom: $mode");
	&valid_domain_name($dom) || return (0, "Invalid domain: $dom");
	my $host = &host_match_op($dom);
	$host || return (0, "Invalid domain: $dom");
	push(@lines, "");
	push(@lines, "# virtualmin-modsec-engine: domain=$dom mode=$mode");
	push(@lines, "SecRule REQUEST_HEADERS:Host \"$host\" \\");
	push(@lines, "    \"id:$gid,phase:1,pass,nolog,ctl:ruleEngine=$mode\"");
	$gid++;
	}
# Test and roll back like every other writer, so a rejected config never
# survives on disk waiting for the next Apache restart to fail.
return &write_test_rollback($f, \@lines, $old);
}

# --- Per-path engine mode ------------------------------------------------
# A whole domain is often too blunt. A Joomla or WordPress admin area behind a
# login triggers false positives that would stop staff saving content, while
# the public side is exactly where scanners attack and must stay enforced. So
# a URL prefix can carry its own engine mode, overriding the domain and global
# setting. These rules live in their own file, named so it loads after the
# per-domain file (more specific wins) but before the IP whitelist (a trusted
# IP still gets the final say).

# valid_engine_path($path)
# A URL prefix we can safely embed in a rule: absolute, and free of quotes,
# backslashes and whitespace that would break out of the SecRule argument.
sub valid_engine_path
{
my ($p) = @_;
return 0 if (!defined $p);
# No % either: the path is interpolated into @beginsWith, and ModSecurity
# macro-expands operator arguments, so %{tx.something} would be substituted at
# request time instead of matched literally. Quotes, backslash and whitespace
# would break the rule's own syntax.
return $p =~ m{^/[^"'\\\s%]*$} ? 1 : 0;
}

# backup_dir_hazard()
# True when the backup directory sits inside the directory Apache scans for
# ModSecurity configuration -- the same place the module's own rule files live,
# because that is what makes them load. Backups survive there only because they
# are named with a trailing timestamp and the stock include is *.conf. Change
# either and every retained backup becomes live configuration with duplicate
# rule ids, which stops Apache starting. Cheap to detect, so the Backups page
# says so rather than leaving it to be discovered during an outage.
sub backup_dir_hazard
{
my $bdir = $config{'backup_dir'};
my $excl = $config{'exclusion_file'};
return 0 if (!$bdir || !$excl);
my ($scanned) = $excl =~ m{^(.*)/[^/]+$};
return 0 if (!$scanned);
$bdir =~ s{/+$}{};
return ($bdir eq $scanned || index($bdir, "$scanned/") == 0) ? 1 : 0;
}

# list_path_engine()
# Parse the managed per-path file into hash refs: domain (may be empty),
# path, mode, genid.
sub list_path_engine
{
my $f = $config{'path_engine_file'};
my @out;
return @out if (!-r $f);
my $lref = &read_file_lines($f, 1);
my $i = 0;
while ($i < @$lref) {
	if ($lref->[$i] =~
	    /^#\s*virtualmin-modsec-path:\s*domain=(\S*)\s+mode=(\S+)\s+path=(\S+)/) {
		my ($dom, $mode, $path) = ($1, $2, $3);
		my ($gid, $j) = (undef, $i + 1);
		while ($j < @$lref && $lref->[$j] ne "" &&
		       $lref->[$j] !~ /^#\s*virtualmin-modsec-path:/) {
			if ($lref->[$j] =~ /id:(\d+)/) { $gid = $1; last; }
			$j++;
			}
		push(@out, { domain => $dom, mode => $mode, path => $path,
			     genid => $gid });
		}
	$i++;
	}
return @out;
}

# write_path_engine(\@entries)
# Rebuild the per-path file from scratch. Each entry needs domain (possibly
# empty), path and mode. Returns (1) or (0, error).
#
# CHAIN ACTIONS -- read before touching the rule below.
# In ModSecurity 2.x a non-disruptive action (ctl, setvar, t:) executes the
# moment the rule *carrying it* matches. It does NOT wait for the rest of the
# chain. Only disruptive actions (deny, block, drop, redirect) are deferred
# until every link matches. So ctl:ruleEngine must go on the LAST link, the one
# testing the path. Putting it on the chain starter, which tests only the Host
# header, silently applies the mode to the entire site whatever the path.
# That shipped in v0.18-v0.22 and left a production portal unenforced for over
# a week while both the config file and the UI reported the engine as On.
# A chained link must not carry id or phase; ctl is exactly what belongs there.
# tests/generated-rules.t asserts this and fails if it regresses.
sub write_path_engine
{
my ($ents) = @_;
my $f = $config{'path_engine_file'};
my $old = -r $f ? &read_file_contents($f) : undef;
if (!@$ents) {
	&backup_file($f);
	unlink($f) if (-e $f);
	return &apply_changes();
	}
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - per-path engine modes.",
	"# Do not edit by hand.");
# Own id range so these never collide with the exclusion, per-domain or IP
# rules the module also generates.
my $gid = ($config{'id_base'} || 9000000) + 400000;
foreach my $e (@$ents) {
	my ($dom, $path, $mode) = ($e->{'domain'}, $e->{'path'}, $e->{'mode'});
	$dom = "" if (!defined $dom);
	$mode =~ /^(On|Off|DetectionOnly)$/ || return (0, "Invalid mode: $mode");
	&valid_engine_path($path) || return (0, "Invalid path: $path");
	# Empty means "all sites", so only a non-empty domain is checked.
	$dom ne "" && !&valid_domain_name($dom) &&
		return (0, "Invalid domain: $dom");
	push(@lines, "");
	push(@lines, "# virtualmin-modsec-path: domain=$dom mode=$mode path=$path");
	if ($dom) {
		my $host = &host_match_op($dom);
		$host || return (0, "Invalid domain: $dom");
		push(@lines, "SecRule REQUEST_HEADERS:Host \"$host\" \\");
		push(@lines, "    \"id:$gid,phase:1,pass,nolog,chain\"");
		push(@lines, "    SecRule REQUEST_URI \"\@beginsWith $path\" ".
			     "\"ctl:ruleEngine=$mode\"");
		}
	else {
		push(@lines, "SecRule REQUEST_URI \"\@beginsWith $path\" \\");
		push(@lines, "    \"id:$gid,phase:1,pass,nolog,ctl:ruleEngine=$mode\"");
		}
	$gid++;
	}
return &write_test_rollback($f, \@lines, $old);
}

# add_path_engine($domain, $path, $mode)
# Add or update the rule for one domain+path pair, then reload.
sub add_path_engine
{
my ($domain, $path, $mode) = @_;
$domain = "" if (!defined $domain);
$path =~ s/^\s+|\s+$//g;
&valid_engine_path($path) ||
	return (0, "Path must start with / and contain no spaces or quotes, ".
		   "for example /administrator/");
$mode =~ /^(On|Off|DetectionOnly)$/ || return (0, "Invalid engine mode");
$domain ne "" && !&valid_domain_name($domain) &&
	return (0, "Invalid domain: $domain");
my @ents = grep { !($_->{'domain'} eq $domain && $_->{'path'} eq $path) }
		&list_path_engine();
push(@ents, { domain => $domain, path => $path, mode => $mode });
return &write_path_engine(\@ents);
}

# remove_path_engine($genid)
# Drop the rule with this generated id, then reload.
sub remove_path_engine
{
my ($genid) = @_;
$genid =~ /^\d+$/ || return (0, "Invalid rule id");
my @ents = grep { $_->{'genid'} ne $genid } &list_path_engine();
return &write_path_engine(\@ents);
}

# set_domain_engine($domain, $mode)
# Set a single domain's engine mode and reload. $mode is default/On/Off/
# DetectionOnly. Returns (1) or (0, error).
sub set_domain_engine
{
my ($domain, $mode) = @_;
&valid_domain_name($domain) || return (0, "Invalid domain: $domain");
$mode =~ /^(default|On|Off|DetectionOnly)$/ || return (0, "Invalid mode");
my %map = &list_domain_engine();
if ($mode eq 'default') { delete $map{$domain}; }
else                    { $map{$domain} = $mode; }
my ($ok, $err) = &write_domain_engine(\%map);
return ($ok, $err) if (!$ok);
return &apply_changes();
}

# crs_version_installed()
# Best-effort detection of the installed CRS version (e.g. "3.3.2").
sub crs_version_installed
{
my $v;
foreach my $f ($config{'crs_setup'},
	       "$config{'crs_dir'}/rules/REQUEST-901-INITIALIZATION.conf") {
	next if (!$f || !-r $f);
	foreach my $l (@{&read_file_lines($f, 1)}) {
		if ($l =~ m{OWASP_CRS/(\d+\.\d+\.\d+)}) { $v = $1; last; }
		}
	last if ($v);
	}
if (!$v) {
	my $o = &backquote_command(
		"dpkg-query -W -f='\${Version}' $config{'crs_pkg'} 2>/dev/null");
	($v) = $o =~ /(\d+\.\d+\.\d+)/;
	}
return $v;
}

# crs_version_latest()
# Fetch the latest CRS release tag from GitHub (returns e.g. "4.10.0"), or
# undef if it can't be reached. Network call is bounded by a short timeout.
sub crs_version_latest
{
my $url = "https://api.github.com/repos/coreruleset/coreruleset/releases/latest";
my $o = &backquote_command("curl -fsS --max-time 8 ".quotemeta($url)." 2>/dev/null");
$o = &backquote_command("wget -qO- --timeout=8 ".quotemeta($url)." 2>/dev/null")
	if ($o !~ /tag_name/);
my ($v) = $o =~ /"tag_name"\s*:\s*"v?([0-9][0-9.]*)"/;
return $v;
}

# version_newer($a, $b)
# True if version string $a is strictly newer than $b.
sub version_newer
{
my ($a, $b) = @_;
return 0 if (!$a || !$b);
my @a = split(/\./, $a);
my @b = split(/\./, $b);
for (my $i = 0; $i < 3; $i++) {
	my $x = $a[$i] || 0;
	my $y = $b[$i] || 0;
	return 1 if ($x > $y);
	return 0 if ($x < $y);
	}
return 0;
}

# update_crs_apt()
# Refresh the package list and upgrade the CRS package only, then make sure
# crs-setup.conf exists and reload. Returns (1) or (0, error).
#
# Uses whatever package manager the platform detection settled on rather than
# assuming apt. install_crs already did this; this function did not, so on the
# RHEL family -- where platform_adjust switches pkg_install to dnf or yum --
# the Update CRS button ran apt-get and simply failed.
sub update_crs_apt
{
my ($pm) = split(/\s+/, $config{'pkg_install'});
$pm ||= "apt-get";
if ($pm eq "apt-get" || $pm eq "apt") {
	&backquote_logged("$pm update -y 2>&1");
	my $o = &backquote_logged("DEBIAN_FRONTEND=noninteractive $pm ".
				  "install --only-upgrade -y ".
				  quotemeta($config{'crs_pkg'})." 2>&1");
	if ($? != 0) {
		return (0, "CRS package upgrade failed:\n$o");
		}
	}
else {
	# dnf/yum upgrade a named package in one step and refresh metadata
	# themselves, so there is no separate update call.
	my $o = &backquote_logged("$pm upgrade -y ".
				  quotemeta($config{'crs_pkg'})." 2>&1");
	if ($? != 0) {
		return (0, "CRS package upgrade failed:\n$o");
		}
	}
&ensure_crs_setup();
return &apply_changes();
}

# get_crs_params()
# Return (paranoia_level, anomaly_threshold) from our managed block in
# crs-setup.conf, or sensible defaults if not set.
sub get_crs_params
{
my ($pl, $an) = (1, 5);
my $f = $config{'crs_setup'};
return ($pl, $an) if (!-r $f);
my $lref = &read_file_lines($f, 1);
foreach my $l (@$lref) {
	next if ($l =~ /^\s*#/);   # skip comments and our BEGIN/END markers
	$pl = $1 if ($l =~ /setvar:tx\.paranoia_level=(\d+)/);
	$an = $1 if ($l =~ /setvar:tx\.inbound_anomaly_score_threshold=(\d+)/);
	}
return ($pl, $an);
}

# set_crs_params($paranoia, $anomaly)
# Write/replace a managed SecAction block at the end of crs-setup.conf that
# overrides the paranoia level and inbound anomaly threshold.
sub set_crs_params
{
my ($pl, $an) = @_;
$pl =~ /^[1-4]$/ || return (0, "Paranoia level must be 1-4");
# The CRS blocks when anomaly_score >= threshold, and a clean request scores 0,
# so a threshold of 0 would deny every single request. Refuse it rather than
# take every site on the server down.
($an =~ /^\d+$/ && $an >= 1) ||
	return (0, "Anomaly threshold must be 1 or higher. A threshold of 0 ".
		   "would block every request, including legitimate traffic ".
		   "(the CRS blocks when the score reaches the threshold, and ".
		   "clean requests score 0). The CRS default is 5; to turn ".
		   "blocking off, set the rule engine to Off or DetectionOnly.");
my $f = $config{'crs_setup'};
return (0, "Cannot read $f") if (!-r $f);
my $lref = &read_file_lines($f);
my @keep;
my $in = 0;
foreach my $l (@$lref) {
	$in = 1 if ($l =~ /^#\s*BEGIN virtualmin-modsec/);
	push(@keep, $l) if (!$in);
	$in = 0 if ($l =~ /^#\s*END virtualmin-modsec/);
	}
my $gid = ($config{'id_base'} || 9000000) - 1;
push(@keep, "# BEGIN virtualmin-modsec");
push(@keep, "SecAction \\");
push(@keep, "  \"id:$gid,phase:1,nolog,pass,t:none,\\");
push(@keep, "    setvar:tx.paranoia_level=$pl,\\");
push(@keep, "    setvar:tx.inbound_anomaly_score_threshold=$an\"");
push(@keep, "# END virtualmin-modsec");
@$lref = @keep;
&backup_file($f);
&flush_file_lines($f);
return &apply_changes();
}

# available_crs_exclusions()
# Auto-detect which application exclusion packages the installed CRS ships
# (e.g. wordpress, drupal, nextcloud...) by scanning its rule files.
sub available_crs_exclusions
{
my (%seen, @out);
foreach my $f (glob("$config{'crs_dir'}/rules/*-EXCLUSION-RULES.conf")) {
	my ($name) = $f =~ m{-([A-Za-z0-9]+)-EXCLUSION-RULES\.conf$};
	next if (!$name);
	my $key = lc($name);
	next if ($key eq 'crs');   # the generic BEFORE/AFTER-CRS files
	next if ($seen{$key}++);
	push(@out, $key);
	}
return sort @out;
}

# get_crs_exclusions()
# Return a hash of the application exclusions we have enabled.
sub get_crs_exclusions
{
my %on;
my $f = $config{'crs_setup'};
return %on if (!-r $f);
my $in = 0;
foreach my $l (@{&read_file_lines($f, 1)}) {
	$in = 1 if ($l =~ /^#\s*BEGIN vmm-appexcl/);
	$on{$1} = 1 if ($in && $l =~ /setvar:tx\.crs_exclusions_(\w+)=1/);
	$in = 0 if ($l =~ /^#\s*END vmm-appexcl/);
	}
return %on;
}

# set_crs_exclusions(\@apps)
# Write/replace a managed SecAction block in crs-setup.conf that enables the
# CRS application exclusions for the given apps. Empty list removes the block.
sub set_crs_exclusions
{
my ($apps) = @_;
my @clean = grep { /^[a-z0-9]+$/ } @$apps;
my $f = $config{'crs_setup'};
return (0, "Cannot read $f") if (!-r $f);
my $lref = &read_file_lines($f);
my (@keep, $in);
foreach my $l (@$lref) {
	$in = 1 if ($l =~ /^#\s*BEGIN vmm-appexcl/);
	push(@keep, $l) if (!$in);
	$in = 0 if ($l =~ /^#\s*END vmm-appexcl/);
	}
if (@clean) {
	my $gid = ($config{'id_base'} || 9000000) - 2;
	push(@keep, "# BEGIN vmm-appexcl");
	push(@keep, "SecAction \\");
	push(@keep, "  \"id:$gid,phase:1,nolog,pass,t:none,\\");
	for my $i (0 .. $#clean) {
		my $end = ($i == $#clean) ? "\"" : ",\\";
		push(@keep, "    setvar:tx.crs_exclusions_$clean[$i]=1$end");
		}
	push(@keep, "# END vmm-appexcl");
	}
@$lref = @keep;
&backup_file($f);
&flush_file_lines($f);
return &apply_changes();
}

# dos_available()
# True if the CRS ships the DoS-protection ruleset.
sub dos_available
{
return scalar(glob("$config{'crs_dir'}/rules/*DOS-PROTECTION*.conf")) ? 1 : 0;
}

# get_dos_params()
# Return the DoS-protection settings: enabled flag + burst/threshold/timeout.
sub get_dos_params
{
my %p = (enabled => 0, slice => 60, threshold => 100, timeout => 600);
my $f = $config{'crs_setup'};
return %p if (!-r $f);
my $in = 0;
foreach my $l (@{&read_file_lines($f, 1)}) {
	$in = 1 if ($l =~ /^#\s*BEGIN vmm-dos/);
	if ($in) {
		$p{'enabled'}   = 1;
		$p{'slice'}     = $1 if ($l =~ /setvar:tx\.dos_burst_time_slice=(\d+)/);
		$p{'threshold'} = $1 if ($l =~ /setvar:tx\.dos_counter_threshold=(\d+)/);
		$p{'timeout'}   = $1 if ($l =~ /setvar:tx\.dos_block_timeout=(\d+)/);
		}
	$in = 0 if ($l =~ /^#\s*END vmm-dos/);
	}
return %p;
}

# set_dos_params($enabled, $slice, $threshold, $timeout)
# Write/replace a managed SecAction block that turns the CRS per-IP DoS
# protection on (with thresholds) or removes it when disabled.
sub set_dos_params
{
my ($enabled, $slice, $threshold, $timeout) = @_;
# Zero is rejected for the same reason as the anomaly threshold: a request
# counter limit of 0 would throttle every visitor immediately.
foreach my $v ($slice, $threshold, $timeout) {
	($v =~ /^\d+$/ && $v >= 1) ||
		return (0, "DoS values must be 1 or higher. A limit of 0 would ".
			   "throttle every visitor. Defaults: 100 requests / ".
			   "60 seconds / 600 second block.");
	}
my $f = $config{'crs_setup'};
return (0, "Cannot read $f") if (!-r $f);
my $lref = &read_file_lines($f);
my (@keep, $in);
foreach my $l (@$lref) {
	$in = 1 if ($l =~ /^#\s*BEGIN vmm-dos/);
	push(@keep, $l) if (!$in);
	$in = 0 if ($l =~ /^#\s*END vmm-dos/);
	}
if ($enabled) {
	my $gid = ($config{'id_base'} || 9000000) - 3;
	push(@keep, "# BEGIN vmm-dos");
	push(@keep, "SecAction \\");
	push(@keep, "  \"id:$gid,phase:1,nolog,pass,t:none,\\");
	push(@keep, "    setvar:tx.dos_burst_time_slice=$slice,\\");
	push(@keep, "    setvar:tx.dos_counter_threshold=$threshold,\\");
	push(@keep, "    setvar:tx.dos_block_timeout=$timeout\"");
	push(@keep, "# END vmm-dos");
	}
@$lref = @keep;
&backup_file($f);
&flush_file_lines($f);
return &apply_changes();
}

# tail_lines($file, $n)
# Return the last $n lines of a file without slurping the whole thing.
sub tail_lines
{
my ($file, $n) = @_;
my $out = &backquote_command("tail -n ".quotemeta($n)." ".quotemeta($file)." 2>/dev/null");
return split(/\n/, $out);
}

1;
