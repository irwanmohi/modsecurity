#!/usr/bin/perl
# ipwhitelist.cgi
# Manage the list of trusted IPs/CIDRs that bypass ModSecurity entirely.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'ip_title'}, "");

my @ips = &get_ip_whitelist();

print "<p>",$text{'ip_intro'},"</p>\n";
print &ui_form_start("save_ipwhitelist.cgi", "post");
print &ui_textarea("ips", join("\n", @ips), 8, 50);
print "<p><font size=-1>",$text{'ip_hint'},"</font></p>\n";
print &ui_form_end([ [ undef, $text{'eng_save'} ] ]);

&ui_print_footer("index.cgi", $text{'index_return'});
