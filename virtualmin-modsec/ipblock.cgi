#!/usr/bin/perl
# ipblock.cgi
# Manage the list of IPs/CIDRs that are blocked (denied with 403).

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'ipbl_title'}, "");

my @ips = &get_ip_blocklist();

print "<p>",$text{'ipbl_intro'},"</p>\n";
print &ui_form_start("save_ipblock.cgi", "post");
print &ui_textarea("ips", join("\n", @ips), 8, 50);
print "<p><font size=-1>",$text{'ipbl_hint'},"</font></p>\n";
print &ui_form_end([ [ undef, $text{'eng_save'} ] ]);

&modsec_footer("index.cgi", $text{'index_return'});
