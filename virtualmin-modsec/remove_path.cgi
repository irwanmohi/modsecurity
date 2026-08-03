#!/usr/bin/perl
# remove_path.cgi
# Remove one per-path engine rule and reload.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'path_rmerr'});
&can_access("toggle") || &error($text{'eng_eacl'});

my ($ok, $err) = &remove_path_engine($in{'genid'});
$ok || &error($err);
&redirect("paths.cgi");
