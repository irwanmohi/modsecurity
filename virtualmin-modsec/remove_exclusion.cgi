#!/usr/bin/perl
# remove_exclusion.cgi
# Remove a previously-applied exclusion and reload Apache.

require './modsec-lib.pl';
&ReadParse();
&error_setup($text{'exc_rmerr'});
&can_access("remove") || &error($text{'allow_eacl'});

my $genid = $in{'genid'};
$genid =~ /^\d+$/ || &error($text{'exc_badid'});

my ($ok, $err) = &remove_exclusion($genid);
&error($err) if (!$ok);
&redirect("list_exclusions.cgi");
