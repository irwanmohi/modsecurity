#!/usr/bin/perl
# save_paths.cgi
# Add or update one per-path engine rule.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'path_err'});
&can_access("toggle") || &error($text{'eng_eacl'});

my ($ok, $err) = &add_path_engine($in{'domain'}, $in{'path'}, $in{'mode'});
$ok || &error($err);
&redirect("paths.cgi");
