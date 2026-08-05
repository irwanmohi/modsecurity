#!/usr/bin/perl
# save_domains.cgi
# Apply per-domain engine modes from domains.cgi in one pass, then reload.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'dom_err'});
&require_post();
&can_access("toggle") || &error($text{'eng_eacl'});

# Rebuild the full map from the submitted form. The domain list arrives in a
# hidden field, so it is attacker-controlled like any other input and is
# validated here as strictly as the manual-entry box below -- these names end
# up inside a quoted ModSecurity operator that Apache parses as root.
my %map;
foreach my $d (split(/,/, $in{'domains'})) {
	next if ($d !~ /\S/);
	&valid_domain_name($d) || &error($text{'dom_badname'});
	my $m = $in{"mode_".$d};
	next if (!$m || $m eq 'default');
	$m =~ /^(On|Off|DetectionOnly)$/ || &error($text{'dom_badmode'});
	$map{$d} = $m;
	}

# Optional manual entry.
if ($in{'newdom'} =~ /\S/) {
	my $nd = $in{'newdom'};
	$nd =~ s/^\s+|\s+$//g;
	&valid_domain_name($nd) || &error($text{'dom_badname'});
	$in{'newmode'} =~ /^(default|On|Off|DetectionOnly)$/ ||
		&error($text{'dom_badmode'});
	$map{$nd} = $in{'newmode'} if ($in{'newmode'} ne 'default');
	}

my ($ok, $err) = &write_domain_engine(\%map);
$ok || &error($err);
&redirect("index.cgi");
