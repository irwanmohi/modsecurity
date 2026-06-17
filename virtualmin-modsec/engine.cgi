#!/usr/bin/perl
# engine.cgi
# Settings page: SecRuleEngine mode, CRS install/enable, paranoia level and
# anomaly threshold.

require './modsec-lib.pl';
&ReadParse();
&ui_print_header(undef, $text{'eng_title'}, "");

# --- Rule engine mode ---
print &ui_form_start("save_engine.cgi", "post");
print &ui_hidden("section", "engine");
print &ui_table_start($text{'eng_engine'}, "width=100%", 2);
my $state = &get_engine_state() || "Off";
print &ui_table_row($text{'eng_mode'},
	&ui_radio("engine", $state,
		[ [ "On", $text{'eng_on'} ],
		  [ "DetectionOnly", $text{'eng_detect'} ],
		  [ "Off", $text{'eng_off'} ] ]));
print &ui_table_end();
print &ui_form_end([ [ undef, $text{'eng_save'} ] ]);

# --- Core Rule Set ---
print &ui_hr();
print &ui_table_start($text{'eng_crs'}, "width=100%", 2);
if (!&crs_installed()) {
	print &ui_table_row($text{'eng_crs_state'},
		"<font color=#cc0000>$text{'eng_crs_missing'}</font>");
	print &ui_table_end();
	print &ui_form_start("save_engine.cgi", "post");
	print &ui_hidden("section", "install_crs");
	print &ui_form_end([ [ undef, $text{'eng_crs_install'} ] ]);
	}
else {
	my $en = &crs_enabled();
	print &ui_table_row($text{'eng_crs_state'},
		$en ? $text{'eng_crs_on'} :
		      "<font color=#cc8800>$text{'eng_crs_off'}</font>");
	print &ui_table_end();

	# Enable/disable toggle
	print &ui_form_start("save_engine.cgi", "post");
	print &ui_hidden("section", $en ? "disable_crs" : "enable_crs");
	print &ui_form_end([ [ undef, $en ? $text{'eng_crs_disable'}
					  : $text{'eng_crs_enable'} ] ]);

	# Tuning
	if ($en) {
		my ($pl, $an) = &get_crs_params();
		print &ui_form_start("save_engine.cgi", "post");
		print &ui_hidden("section", "tune");
		print &ui_table_start($text{'eng_tune'}, "width=100%", 2);
		print &ui_table_row($text{'eng_pl'},
			&ui_select("pl", $pl,
				[ [1,"1 ($text{'eng_pl1'})"], [2,2], [3,3],
				  [4,"4 ($text{'eng_pl4'})"] ]));
		print &ui_table_row($text{'eng_anomaly'},
			&ui_textbox("an", $an, 5)." ".$text{'eng_anomaly_hint'});
		print &ui_table_end();
		print &ui_form_end([ [ undef, $text{'eng_save'} ] ]);
		}
	}

&modsec_footer("index.cgi", $text{'index_return'});
