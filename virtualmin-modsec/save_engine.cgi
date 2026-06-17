#!/usr/bin/perl
# save_engine.cgi
# Apply changes from engine.cgi (engine mode, CRS install/enable, tuning).

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'eng_err'});
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
else {
	&error($text{'eng_badsec'});
	}

&error($err) if (!$ok);
&redirect("engine.cgi");
