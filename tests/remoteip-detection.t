#!/usr/bin/perl
# Guard for mod_remoteip detection and the client-IP source it forces.
#
# Why this exists: mod_remoteip consumes X-Forwarded-For before ModSecurity's
# phase 1 runs, so rules matching that header can never fire. A whitelist
# configured in xff mode on such a server silently protects nobody -- the UI
# shows it, the config file contains it, Apache accepts it, and it is inert.
# Detection must therefore be reliable in both directions: missing it leaves
# dead rules in place, and false-positives would override a setting that was
# actually correct.
#
# The RemoteIPHeader search deliberately runs the real grep against a real
# directory tree, including a symlinked config directory. That is the failure
# mode most likely to slip through: grep -r skips symlinks while recursing and
# would report "not configured" on a server where it plainly is.
#
# Run:  perl tests/remoteip-detection.t

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/lib";

chdir("$FindBin::Bin/../virtualmin-modsec") || die "cannot enter module dir: $!";
require './modsec-lib.pl';

# Silence "used only once" for the two package globals this test drives.
no warnings 'once';

my $tmp = tempdir(CLEANUP => 1);
my $fails = 0;
my $count = 0;
my $skips = 0;

sub ok
{
my ($cond, $name) = @_;
$count++;
if ($cond) { print "ok $count - $name\n"; }
else       { print "not ok $count - $name\n"; $fails++; }
}

sub skip
{
my ($name, $why) = @_;
$count++;
$skips++;
print "ok $count - $name # SKIP $why\n";
}

# --- a fake Apache tree ----------------------------------------------------
# etc/apache2/apache2.conf              plain file, no RemoteIPHeader
# etc/apache2/conf-available/remoteip.conf   holds the directive
# etc/apache2/conf-enabled/remoteip.conf     symlink to the above (Debian style)
my $root = "$tmp/etc/apache2";
mkdir("$tmp/etc");
mkdir($root);
mkdir("$root/conf-available");
mkdir("$root/conf-enabled");
mkdir("$root/sites-enabled");

open(my $h, ">", "$root/apache2.conf") || die $!;
print $h "ServerRoot \"/etc/apache2\"\nInclude conf-enabled/*.conf\n";
close($h);

open($h, ">", "$root/conf-available/remoteip.conf") || die $!;
print $h "RemoteIPHeader X-Forwarded-For\nRemoteIPInternalProxy 10.0.0.1\n";
close($h);

my $have_symlink = symlink("$root/conf-available/remoteip.conf",
			   "$root/conf-enabled/remoteip.conf") ? 1 : 0;

# Route grep to the real shell so the symlink behaviour is genuinely exercised;
# answer apache2ctl -M from $mods so tests can toggle "module loaded".
my $mods = "";
$WebminCore::BACKQUOTE = sub {
	my ($cmd) = @_;
	return $mods if ($cmd =~ /-M\b/);
	return scalar(`$cmd`) if ($cmd =~ /^grep /);
	return "";
	};

%main::config = (
	apache_test      => "apache2ctl configtest",
	apache_sites     => "$root/sites-enabled",
	client_ip_source => "xff",
	trusted_proxies  => "10.0.0.1",
	);

sub reset_cache { $main::remoteip_cache = undef; }

# --- config root derivation ------------------------------------------------
ok(&apache_config_root() eq $root,
   "apache_config_root strips the vhost dir off the configured path");

# --- module not loaded -----------------------------------------------------
$mods = " core_module (static)\n security2_module (shared)\n";
&reset_cache();
ok(!&remoteip_loaded(), "remoteip_loaded false when absent from -M output");
ok(!&remoteip_active(), "remoteip_active false when the module is not loaded");
ok(&client_ip_source() eq 'xff',
   "xff is left alone when mod_remoteip is not loaded");
ok(!&client_ip_source_overridden(), "no override reported when not loaded");

# --- loaded, and configured behind a symlinked directory -------------------
$mods = " core_module (static)\n remoteip_module (shared)\n security2_module (shared)\n";
&reset_cache();
ok(&remoteip_loaded(), "remoteip_loaded true when -M lists remoteip_module");

if ($have_symlink) {
	ok(&remoteip_header_configured(),
	   "RemoteIPHeader found behind a symlinked conf-enabled directory");
	}
else {
	skip("RemoteIPHeader found behind a symlinked conf-enabled directory",
	     "symlinks unavailable on this filesystem");
	}

&reset_cache();
ok(&remoteip_active(), "remoteip_active true when loaded and configured");
ok(&client_ip_source() eq 'remote_addr',
   "xff is overridden to remote_addr, since xff rules could never match");
ok(&client_ip_source_overridden(), "the override is reported, not silent");
# Assign to an array first: scalar() on the call would impose scalar context on
# the sub and hand back its last value rather than a count.
my @note = &ip_source_header_comment();
ok(scalar(@note) > 0,
   "the override is disclosed in the generated file header");

# --- loaded but NOT configured ---------------------------------------------
# A loaded module with no RemoteIPHeader does nothing, so xff must stand.
unlink("$root/conf-enabled/remoteip.conf");
unlink("$root/conf-available/remoteip.conf");
&reset_cache();
ok(!&remoteip_header_configured(),
   "RemoteIPHeader absent once the config is removed");
ok(!&remoteip_active(), "remoteip_active false when loaded but not configured");
ok(&client_ip_source() eq 'xff',
   "xff stands when mod_remoteip is loaded but does nothing");
@note = &ip_source_header_comment();
ok(scalar(@note) == 0, "no override note when there is no override");

# --- the generated rule follows the override -------------------------------
open($h, ">", "$root/conf-available/remoteip.conf") || die $!;
print $h "RemoteIPHeader X-Forwarded-For\n";
close($h);
$have_symlink = symlink("$root/conf-available/remoteip.conf",
			"$root/conf-enabled/remoteip.conf") ? 1 : 0;
&reset_cache();
$main::config{'ip_whitelist_file'} = "$tmp/wl.conf";
$main::config{'backup_dir'}        = "$tmp/backups";
$main::config{'backup_interval'}   = 0;
$main::config{'apache_reload'}     = "true";
$main::config{'id_base'}           = 9000000;

if ($have_symlink && &remoteip_active()) {
	&set_ip_whitelist([ "203.0.113.5" ]);
	open(my $r, "<", "$tmp/wl.conf") || die $!;
	my $body = do { local $/; <$r> };
	close($r);
	ok($body =~ /REMOTE_ADDR/ && $body !~ /X-Forwarded-For "\@ipMatch/,
	   "whitelist matches REMOTE_ADDR, not the header mod_remoteip removed");
	ok($body =~ /mod_remoteip is/,
	   "the generated file explains why it differs from the configured mode");
	}
else {
	skip("whitelist matches REMOTE_ADDR under mod_remoteip",
	     "symlinks unavailable on this filesystem");
	skip("the generated file explains the override",
	     "symlinks unavailable on this filesystem");
	}

print "\n1..$count\n";
if ($fails) { print "FAILED $fails of $count\n"; exit(1); }
print "All $count checks passed".($skips ? " ($skips skipped)" : "")."\n";
exit(0);
