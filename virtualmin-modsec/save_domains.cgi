#!/usr/bin/perl
# save_domains.cgi
# Apply per-domain engine modes from domains.cgi in one pass, then reload.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'dom_err'});
&can_access("toggle") || &error($text{'eng_eacl'});

# Rebuild the full map from the submitted form.
my %map;
foreach my $d (split(/,/, $in{'domains'})) {
	my $m = $in{"mode_".$d};
	next if (!$m || $m eq 'default');
	$map{$d} = $m;
	}

# Optional manual entry.
if ($in{'newdom'} =~ /\S/) {
	my $nd = $in{'newdom'};
	$nd =~ s/^\s+|\s+$//g;
	$nd =~ /^[a-zA-Z0-9\.\-\_]+$/ || &error($text{'dom_badname'});
	$map{$nd} = $in{'newmode'} if ($in{'newmode'} ne 'default');
	}

my ($ok, $err) = &write_domain_engine(\%map);
$ok || &error($err);
($ok, $err) = &apply_changes();
$ok || &error($err);
&redirect("domains.cgi");
