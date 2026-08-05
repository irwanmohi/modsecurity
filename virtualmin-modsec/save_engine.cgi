#!/usr/bin/perl
# save_engine.cgi
# Apply changes from engine.cgi (engine mode, CRS install/enable, tuning).

require './modsec-lib.pl';
&ReadParse();
&require_post();
&can_access("toggle") || &error($text{'eng_eacl'});

my $sec = $in{'section'};
my ($ok, $err);

if ($sec eq "engine") {
	($ok, $err) = &set_engine_state($in{'engine'});
	}
elsif ($sec eq "install_crs") {
	($ok, $err) = &install_crs();
	}
elsif ($sec eq "enable_crs") {
	($ok, $err) = &enable_crs();
	}
elsif ($sec eq "disable_crs") {
	($ok, $err) = &disable_crs();
	}
elsif ($sec eq "tune") {
	($ok, $err) = &set_crs_params($in{'pl'}, $in{'an'});
	}
elsif ($sec eq "update_crs") {
	($ok, $err) = &update_crs_apt();
	}
elsif ($sec eq "appexcl") {
	my @apps = grep { $in{"excl_$_"} } &available_crs_exclusions();
	($ok, $err) = &set_crs_exclusions(\@apps);
	}
elsif ($sec eq "dos") {
	($ok, $err) = &set_dos_params($in{'dos_on'}, $in{'dos_slice'},
				      $in{'dos_threshold'}, $in{'dos_timeout'});
	}
else {
	&error($text{'eng_badsec'});
	}

&error($err) if (!$ok);
&redirect("engine.cgi");
