# modsec-lib.pl
# Core functions for the Virtualmin ModSecurity Manager module.

BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();
%access = &get_module_acl();

# can_access($action)
# Return true if the current user's ACL grants the named action.
sub can_access
{
return $access{$_[0]};
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
# Dedupe and keep only readable files.
my (%seen, @out);
foreach my $f (@files) {
	next if (!$f || $seen{$f}++);
	push(@out, $f) if (-r $f);
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
$domain =~ /[^a-zA-Z0-9\.\-\_]/ && return (0, "Invalid domain");
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
	push(@lines, "SecRule REQUEST_HEADERS:Host \"\@streq $domain\" \\");
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
	      ip_whitelist_file ip_blocklist_file crs_enable_file);
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
	unlink($f) if (-e $f);
	return &apply_changes();
	}
my $gid = ($config{'id_base'} || 9000000) + 200000;
my $list = join(",", @clean);
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - trusted IP whitelist.",
	"# virtualmin-modsec-ipwhitelist: $list",
	"SecRule REMOTE_ADDR \"\@ipMatch $list\" \\",
	"    \"id:$gid,phase:1,pass,nolog,ctl:ruleEngine=Off\"");
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
	unlink($f) if (-e $f);
	return &apply_changes();
	}
my $gid = ($config{'id_base'} || 9000000) + 300000;
my $list = join(",", @clean);
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - IP blocklist.",
	"# virtualmin-modsec-ipblocklist: $list",
	"SecRule REMOTE_ADDR \"\@ipMatch $list\" \\",
	"    \"id:$gid,phase:1,deny,status:403,log,".
	"msg:'IP blocked by ModSecurity Manager'\"");
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
	       "/etc/apache2/mods-available/security2.conf") {
	next if (!-r $c);
	my $lref = &read_file_lines($c, 1);
	foreach my $l (@$lref) {
		next if ($l =~ /^\s*#/);
		return 1 if ($l =~ /modsecurity-crs.*\.load/i ||
			     $l =~ /\Q$config{'crs_load'}\E/);
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
my @active = grep { $map->{$_} && $map->{$_} ne 'default' } keys %$map;
&backup_file($f);
if (!@active) {
	unlink($f) if (-e $f);
	return 1;
	}
my @lines = (
	"# Managed by Virtualmin ModSecurity Manager - per-domain engine modes.",
	"# Do not edit by hand.");
# Use a separate id range so these never clash with allow exclusions.
my $gid = ($config{'id_base'} || 9000000) + 100000;
foreach my $dom (sort @active) {
	my $mode = $map->{$dom};
	next if ($mode !~ /^(On|Off|DetectionOnly)$/);
	push(@lines, "");
	push(@lines, "# virtualmin-modsec-engine: domain=$dom mode=$mode");
	push(@lines, "SecRule REQUEST_HEADERS:Host \"\@streq $dom\" \\");
	push(@lines, "    \"id:$gid,phase:1,pass,nolog,ctl:ruleEngine=$mode\"");
	$gid++;
	}
&open_tempfile(my $FH, ">$f", 1) || return (0, "Cannot write $f");
&print_tempfile($FH, join("\n", @lines)."\n");
&close_tempfile($FH);
return 1;
}

# set_domain_engine($domain, $mode)
# Set a single domain's engine mode and reload. $mode is default/On/Off/
# DetectionOnly. Returns (1) or (0, error).
sub set_domain_engine
{
my ($domain, $mode) = @_;
$domain =~ /^[a-zA-Z0-9\.\-\_]+$/ || return (0, "Invalid domain");
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
sub update_crs_apt
{
&backquote_logged("apt-get update -y 2>&1");
my $o = &backquote_logged(
	"DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y ".
	"$config{'crs_pkg'} 2>&1");
if ($? != 0) {
	return (0, "CRS package upgrade failed:\n$o");
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
$an =~ /^\d+$/   || return (0, "Anomaly threshold must be a number");
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

# tail_lines($file, $n)
# Return the last $n lines of a file without slurping the whole thing.
sub tail_lines
{
my ($file, $n) = @_;
my $out = &backquote_command("tail -n ".quotemeta($n)." ".quotemeta($file)." 2>/dev/null");
return split(/\n/, $out);
}

1;
