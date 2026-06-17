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

# parse_blocks_native()
# Parse ModSecurity messages out of the Apache error.log.
sub parse_blocks_native
{
my $log = $config{'error_log'};
my @out;
return @out if (!-r $log);
# Read at most max_lines from the tail of the file to stay fast.
my @lines = &tail_lines($log, $config{'max_lines'} || 20000);
foreach my $l (@lines) {
	next if ($l !~ /ModSecurity:/);
	my %e;
	($e{'id'})       = $l =~ /\[id\s+"([^"]*)"\]/;
	($e{'msg'})      = $l =~ /\[msg\s+"([^"]*)"\]/;
	($e{'hostname'}) = $l =~ /\[hostname\s+"([^"]*)"\]/;
	($e{'uri'})      = $l =~ /\[uri\s+"([^"]*)"\]/;
	($e{'severity'}) = $l =~ /\[severity\s+"([^"]*)"\]/;
	($e{'client'})   = $l =~ /\[client\s+([0-9a-fA-F\.:]+)/;
	$e{'action'} = ($l =~ /Access denied/i) ? "blocked" : "warning";
	($e{'time'}) = $l =~ /^\[([^\]]+)\]/;
	next if (!$e{'id'});      # skip non-rule lines (startup, etc.)
	push(@out, \%e);
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
			     count => 0 };
		}
	$g{$key}->{'count'}++;
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
for(my $i=0; $i<@$lref; $i++) {
	# Marker comment we write above each generated rule.
	if ($lref->[$i] =~ /^#\s*virtualmin-modsec:\s*domain=(\S*)\s+ruleid=(\S+)/) {
		my ($dom, $rid) = ($1, $2);
		my ($gid) = $lref->[$i+1] =~ /id:(\d+)/;
		push(@out, { domain => $dom, ruleid => $rid, genid => $gid, line => $i });
		}
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

# add_exclusion($ruleid, $domain)
# Append a Host-scoped ctl:ruleRemoveById exclusion to the managed file.
# If $domain is empty, the exclusion applies globally (all sites).
# Returns (1) on success or (0, error) on failure.
sub add_exclusion
{
my ($ruleid, $domain) = @_;
$ruleid =~ /^\d+$/ || return (0, "Invalid rule id");
$domain =~ /[^a-zA-Z0-9\.\-\_]/ && return (0, "Invalid domain");
my $f = $config{'exclusion_file'};
my $lref = -r $f ? &read_file_lines($f) : [];
if (!@$lref) {
	push(@$lref, "# Managed by Virtualmin ModSecurity Manager. Do not edit by hand.");
	}
my $gid = &next_gen_id();
push(@$lref, "");
push(@$lref, "# virtualmin-modsec: domain=$domain ruleid=$ruleid");
if ($domain) {
	push(@$lref, "SecRule REQUEST_HEADERS:Host \"\@streq $domain\" \\");
	push(@$lref, "    \"id:$gid,phase:1,pass,nolog,ctl:ruleRemoveById=$ruleid\"");
	}
else {
	push(@$lref, "SecRuleRemoveById $ruleid");
	}
&flush_file_lines($f);
return &apply_changes();
}

# remove_exclusion($genid)
# Delete the exclusion block (marker + rule lines) identified by its generated
# id, then reload Apache. Returns (1) or (0, error).
sub remove_exclusion
{
my ($genid) = @_;
my $f = $config{'exclusion_file'};
return (0, "No exclusion file") if (!-r $f);
my $lref = &read_file_lines($f);
my @keep;
my $skip = 0;
foreach my $l (@$lref) {
	if ($l =~ /^#\s*virtualmin-modsec:/) {
		$skip = 0;   # reset; decide on the rule line
		}
	if ($l =~ /id:$genid\b/) {
		# Drop this rule line and its preceding marker/blank.
		pop(@keep) while (@keep && $keep[$#keep] =~ /^(#\s*virtualmin-modsec:|\s*$|.*\\\s*$)/ && $keep[$#keep] !~ /SecRule/);
		next;
		}
	push(@keep, $l);
	}
@$lref = @keep;
&flush_file_lines($f);
return &apply_changes();
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
unlink($f) if (-e $f);
if (&package_loads_crs()) {
	return (0, "The CRS is loaded by Apache's own security2.conf. ".
		   "Disable it there (or run 'a2dismod security2') to turn it off.");
	}
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
	($pl) = $l =~ /setvar:tx\.paranoia_level=(\d+)/ if ($l =~ /virtualmin-modsec/ || $l =~ /paranoia_level/);
	($an) = $l =~ /setvar:tx\.inbound_anomaly_score_threshold=(\d+)/ if ($l =~ /anomaly_score_threshold/);
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
