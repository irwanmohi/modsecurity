#!/usr/bin/perl
# Regression guard for generated ModSecurity rules.
#
# The defect this exists to catch is silent: Apache accepts the config, the UI
# reports the intended state, and the rules simply do the wrong thing. In
# ModSecurity 2.x a non-disruptive action (ctl, setvar, t:) runs as soon as the
# rule carrying it matches -- it does not wait for the rest of the chain. Put
# one on a chain starter and the remaining conditions stop gating it.
#
# Rules span continuation lines, so everything here is checked against folded
# logical rules rather than raw lines; a per-line check would miss the defect
# entirely, because the operator and the action list sit on different lines.
#
# Run:  perl tests/generated-rules.t

use strict;
use warnings;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/lib";

chdir("$FindBin::Bin/../virtualmin-modsec") || die "cannot enter module dir: $!";
require './modsec-lib.pl';

my $tmp = tempdir(CLEANUP => 1);
my $fails = 0;
my $count = 0;

sub ok
{
my ($cond, $name) = @_;
$count++;
if ($cond) { print "ok $count - $name\n"; }
else       { print "not ok $count - $name\n"; $fails++; }
}

# logical_rules($file)
# Read a generated file and fold backslash continuations, so each element is
# one complete SecRule/SecAction as ModSecurity sees it.
sub logical_rules
{
my ($f) = @_;
open(my $h, "<", $f) || return ();
my (@out, $cur);
$cur = "";
while (my $l = <$h>) {
	chomp($l);
	next if ($l =~ /^\s*#/ || $l !~ /\S/);
	$l =~ s/\s+$//;
	if ($l =~ s/\\$//) { $cur .= $l; next; }
	$cur .= $l;
	push(@out, $cur);
	$cur = "";
	}
close($h);
push(@out, $cur) if ($cur =~ /\S/);
return @out;
}

sub is_chain_starter { return $_[0] =~ /,chain"/ ? 1 : 0; }
sub has_nondisruptive { return $_[0] =~ /\b(?:ctl|setvar|t):/ ? 1 : 0; }

# no_action_on_starter(@rules)
# The core invariant, stated once: no chain starter may carry a non-disruptive
# action, because it would fire without the rest of the chain gating it.
sub no_action_on_starter
{
foreach my $r (@_) {
	return 0 if (&is_chain_starter($r) && &has_nondisruptive($r));
	}
return 1;
}

%main::config = (
	path_engine_file  => "$tmp/paths.conf",
	ip_whitelist_file => "$tmp/wl.conf",
	ip_blocklist_file => "$tmp/bl.conf",
	backup_dir        => "$tmp/backups",
	backup_interval   => 0,
	apache_test       => "true",
	apache_reload     => "true",
	id_base           => 9000000,
	client_ip_source  => "remote_addr",
	trusted_proxies   => "",
);

# --- per-path engine mode scoped to a domain (chained) --------------------
&write_path_engine([ { domain => "skm.gov.my", path => "/administrator/",
		       mode => "DetectionOnly" } ]);
my @r = &logical_rules("$tmp/paths.conf");
ok(scalar(@r) == 2, "per-path with domain: emits a two-link chain");
ok(&no_action_on_starter(@r),
   "per-path: chain starter carries no ctl");
ok(!!($r[0] =~ /REQUEST_HEADERS:Host/ && !&has_nondisruptive($r[0])),
   "per-path: the Host test carries no ctl, so it cannot set the mode alone");
ok(!!($r[1] =~ /REQUEST_URI.*\@beginsWith \/administrator\// &&
   $r[1] =~ /ctl:ruleEngine=DetectionOnly/),
   "per-path: ctl rides on the path test, so the mode is genuinely path-scoped");

# --- per-path with no domain (single unchained rule) ----------------------
&write_path_engine([ { domain => "", path => "/wp-admin/", mode => "Off" } ]);
@r = &logical_rules("$tmp/paths.conf");
ok(scalar(@r) == 1 && !&is_chain_starter($r[0]),
   "per-path without domain: one unchained rule");
ok(!!($r[0] =~ /ctl:ruleEngine=Off/),
 "per-path without domain: ctl still applied");

# --- IP whitelist, direct connections -------------------------------------
&set_ip_whitelist([ "203.0.113.5" ]);
@r = &logical_rules("$tmp/wl.conf");
ok(scalar(@r) == 1 && !&is_chain_starter($r[0]),
   "whitelist direct: one unchained rule");
ok(!!($r[0] =~ /REMOTE_ADDR/ && $r[0] =~ /ctl:ruleEngine=Off/),
   "whitelist direct: matches REMOTE_ADDR and applies ctl");

# --- IP whitelist behind a proxy (chained) --------------------------------
$main::config{'client_ip_source'} = "xff";
$main::config{'trusted_proxies'}  = "10.0.0.1";
&set_ip_whitelist([ "203.0.113.5" ]);
@r = &logical_rules("$tmp/wl.conf");
ok(scalar(@r) == 2, "whitelist xff: emits a two-link chain");
ok(&no_action_on_starter(@r),
   "whitelist xff: chain starter carries no ctl (else every proxied request bypasses the WAF)");
ok(!!($r[0] =~ /REMOTE_ADDR.*10\.0\.0\.1/ && !&has_nondisruptive($r[0])),
   "whitelist xff: the proxy-address test carries no ctl");
ok(!!($r[1] =~ /X-Forwarded-For/ && $r[1] =~ /ctl:ruleEngine=Off/),
   "whitelist xff: ctl rides on the forwarded client-IP test");

# --- IP blocklist behind a proxy ------------------------------------------
# deny is disruptive, so ModSecurity defers it until every link matches. It is
# therefore correct -- and required, being disruptive -- on the chain starter.
&set_ip_blocklist([ "216.73.217.50" ]);
@r = &logical_rules("$tmp/bl.conf");
ok(&no_action_on_starter(@r), "blocklist xff: chain starter carries no ctl");
ok(!!($r[0] =~ /,chain"/ && $r[0] =~ /deny/),
   "blocklist xff: deny stays on the chain starter, where it is deferred");
ok(!!($r[1] =~ /X-Forwarded-For.*216\.73\.217\.50/),
   "blocklist xff: the client IP is tested on the chained link");

print "\n1..$count\n";
if ($fails) { print "FAILED $fails of $count\n"; exit(1); }
print "All $count checks passed\n";
exit(0);
