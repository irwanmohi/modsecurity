#!/usr/bin/perl
# Guard for input validation and write safety.
#
# The module's serious defects have all had one shape: the config file looks
# right, Apache accepts it, the UI reports the intended state, and the
# protection silently does not apply. These checks are written accordingly --
# they assert that hostile input is *rejected*, not merely that good input
# produces a good-looking string.
#
# Apache parses the generated files as root at config load, so a domain name
# that escapes its quoting is arbitrary Apache configuration written by whoever
# can reach the form.
#
# Run:  perl tests/validation.t

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/lib";

my $moddir = "$FindBin::Bin/../virtualmin-modsec";
chdir($moddir) || die "cannot enter module dir: $!";
require './modsec-lib.pl';

no warnings 'once';

my $tmp = tempdir(CLEANUP => 1);
my $fails = 0;
my $count = 0;

# The ($$) prototype forces scalar context on both arguments. Without it a bare
# m// argument returns an empty list on failure, silently sliding the name into
# the condition slot -- a trap this suite hit while being written.
sub ok($$)
{
my ($cond, $name) = @_;
$count++;
if ($cond) { print "ok $count - $name\n"; }
else       { print "not ok $count - $name\n"; $fails++; }
}

sub slurp
{
my ($f) = @_;
open(my $h, "<", $f) || return "";
local $/;
my $d = <$h>;
close($h);
return $d;
}

# Inputs that must never reach a generated rule. The first is the demonstrated
# escape: it closes the operator quote, injects a deny action, and lands
# SecRuleEngine Off as a server-level directive.
my @hostile = (
	"good.com\" \"id:1,phase:1,deny\"\nSecRuleEngine Off",
	'a"b.com',
	'a b.com',
	"a\nb.com",
	'a|b.com',
	'a*b.com',
	'a$b.com',
	'a(b).com',
	'a`b.com',
	"a\\b.com",
	);

# Run commands for real, so setting apache_test to a failing command genuinely
# fails the config test. The default stub returns success without executing,
# which would make the rollback check pass without exercising anything.
$WebminCore::BACKQUOTE = sub { my $o = `$_[0]`; return $o; };

%main::config = (
	domain_engine_file => "$tmp/domains.conf",
	backup_dir         => "$tmp/backups",
	backup_interval    => 0,
	apache_test        => "true",
	apache_reload      => "true",
	id_base            => 9000000,
	client_ip_source   => "remote_addr",
	);

# --- Issue 1: write_domain_engine must reject, not silently skip -----------
foreach my $bad (@hostile) {
	unlink("$tmp/domains.conf");
	my ($okv, $err) = &write_domain_engine({ $bad => 'On' });
	my $shown = $bad;
	$shown =~ s/\s+/ /g;
	$shown = substr($shown, 0, 28);
	ok(!$okv && $err, "write_domain_engine rejects with an error: $shown");

	my $body = &slurp("$tmp/domains.conf");
	ok($body !~ /SecRuleEngine|,deny|id:1,/,
	   "  ...and writes no injected directive for it");
	}

# A legitimate domain must still work.
unlink("$tmp/domains.conf");
my ($okv) = &write_domain_engine({ 'skm.gov.my' => 'DetectionOnly' });
ok($okv, "write_domain_engine still accepts a valid domain");
ok(&slurp("$tmp/domains.conf") =~ /ctl:ruleEngine=DetectionOnly/,
   "  ...and generates its rule");

# --- Issue 3: host_match_op is safe on its own ----------------------------
# Assert the shape of the whole output, not the absence of a character list:
# the anchor $ legitimately appears in the suffix, so a naive "contains no $"
# check would be wrong. Anything between the fixed prefix and suffix must be
# hostname characters and escaped dots only.
foreach my $bad (@hostile, 'ok.com') {
	my $op = &host_match_op($bad);
	my $shown = $bad;
	$shown =~ s/\s+/ /g;
	$shown = substr($shown, 0, 24);
	if (!defined $op) {
		ok($bad ne 'ok.com', "host_match_op refuses hostile input: $shown");
		next;
		}
	ok($op =~ /^\@rx \^\(\?:www\\\.\)\?[A-Za-z0-9\\._-]+\(\?::\\d\+\)\?\$$/,
	   "host_match_op emits only a safe pattern for: $shown");
	}

# --- Issue 4: write_domain_engine rolls back a failed config test ---------
unlink("$tmp/domains.conf");
&write_domain_engine({ 'first.example' => 'On' });
my $before = &slurp("$tmp/domains.conf");
ok($before =~ /first\.example/, "baseline domain file written");

$main::config{'apache_test'} = "false";        # make configtest fail
my ($okv2, $err2) = &write_domain_engine({ 'second.example' => 'Off' });
$main::config{'apache_test'} = "true";
ok(!$okv2, "write_domain_engine reports failure when the config test fails");
ok(&slurp("$tmp/domains.conf") eq $before,
   "write_domain_engine restores the previous file after a failed config test");

# --- Issue 6: read-only pages enforce the view right ----------------------
foreach my $cgi (qw(byip.cgi domains.cgi engine.cgi index.cgi ipblock.cgi
		    ipwhitelist.cgi logs.cgi stats.cgi tail.cgi)) {
	my $src = &slurp("$moddir/$cgi");
	ok($src =~ /can_access\(["']view["']\)/, "$cgi enforces the view right");
	}

# --- Issue 5: the ACL form exists so those rights can be granted ----------
ok(-r "$moddir/acl_security.pl", "acl_security.pl exists");
my $acl = &slurp("$moddir/acl_security.pl");
ok($acl =~ /sub acl_security_form/, "acl_security.pl defines acl_security_form");
ok($acl =~ /sub acl_security_save/, "acl_security.pl defines acl_security_save");
foreach my $right (qw(view allow remove toggle)) {
	ok($acl =~ /\b$right\b/, "the ACL form covers the '$right' right");
	}

# --- Issue 8: state-changing pages require POST ---------------------------
foreach my $cgi (qw(save_domains.cgi save_engine.cgi save_ipblock.cgi
		    save_ipwhitelist.cgi save_paths.cgi remove_exclusion.cgi
		    remove_path.cgi)) {
	# The check lives in require_post(); assert the call, not the mechanism.
	my $src = &slurp("$moddir/$cgi");
	ok($src =~ /require_post\(\)/, "$cgi checks the request method");
	}

# --- Issue 2: the CGI validates the hidden domain list --------------------
# Require the shared helper by name rather than any regex: the file already
# validates its manual-entry field, so a loose pattern passes while the hidden
# field -- the actual reach path -- stays unchecked.
my $sd = &slurp("$moddir/save_domains.cgi");
ok($sd =~ /valid_domain_name/,
   "save_domains.cgi validates each domain from the hidden field");
ok(&valid_domain_name('skm.gov.my') && !&valid_domain_name('a"b.com') &&
   !&valid_domain_name('a b.com') && !&valid_domain_name("a\nb.com") &&
   !&valid_domain_name(''),
   "valid_domain_name accepts a real host and rejects quotes, spaces, newlines");

# --- clearing an IP list must still leave a restorable backup -------------
# The other two writers back up before unlinking. Clearing a whitelist is
# exactly the change you would want to undo, so it must not be the one case
# that leaves nothing in the Backups page.
foreach my $pair ([ 'ip_whitelist_file', \&set_ip_whitelist, 'whitelist' ],
		  [ 'ip_blocklist_file', \&set_ip_blocklist, 'blocklist' ]) {
	my ($key, $fn, $label) = @$pair;
	$main::config{$key} = "$tmp/$label.conf";
	system("rm -rf ".quotemeta("$tmp/backups"));
	$fn->([ "203.0.113.5" ]);              # create it
	$fn->([]);                             # clear it
	my @b = grep { /^$label\.conf\./ }
		map { $_->{'name'} } &list_backups();
	ok(scalar(@b) > 0, "clearing the IP $label leaves a backup to restore");
	ok(!-e "$tmp/$label.conf", "  ...and removes the live file");
	}

# --- a path must not carry a ModSecurity macro ----------------------------
# The path is interpolated into @beginsWith, whose argument is macro-expanded,
# so %{...} would be substituted at request time rather than matched literally.
ok(&valid_engine_path('/administrator/'), "a normal path is accepted");
ok(!&valid_engine_path('/admin%{tx.foo}/'), "a path carrying a macro is rejected");
ok(!&valid_engine_path('/admin%{'), "a path with a bare macro opener is rejected");

# --- CRS update must use the configured package manager -------------------
# platform_adjust switches pkg_install to dnf/yum on the RHEL family, so an
# update path that hardcodes apt-get simply fails there.
my @cmds;
my $prev = $WebminCore::BACKQUOTE;
$WebminCore::BACKQUOTE = sub { push(@cmds, $_[0]); $? = 0; return ""; };
$main::config{'pkg_install'} = "dnf install -y";
$main::config{'crs_pkg'}     = "mod_security_crs";
$main::config{'crs_setup'}   = "$tmp/crs-setup.conf";
system("echo '# crs' > ".quotemeta("$tmp/crs-setup.conf"));
&update_crs_apt();
$WebminCore::BACKQUOTE = $prev;
my $all = join(" | ", @cmds);
ok($all !~ /apt-get/, "CRS update does not hardcode apt-get");
ok($all =~ /dnf/, "CRS update uses the configured package manager");

# --- backups must not sit where Apache scans for configuration ------------
$main::config{'exclusion_file'} = "/etc/modsecurity/virtualmin-modsec-exclusions.conf";
$main::config{'backup_dir'}     = "/etc/modsecurity/virtualmin-modsec-backups";
ok(&backup_dir_hazard(), "a backup dir inside the Apache-scanned tree is flagged");
$main::config{'backup_dir'}     = "/var/lib/virtualmin-modsec/backups";
ok(!&backup_dir_hazard(), "a backup dir outside that tree is not flagged");
$main::config{'backup_dir'}     = "$tmp/backups";

print "\n1..$count\n";
if ($fails) { print "FAILED $fails of $count\n"; exit(1); }
print "All $count checks passed\n";
exit(0);
