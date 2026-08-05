# acl_security.pl
# Webmin ACL editor for this module.
#
# Without this file Webmin renders no ACL form, so the rights the code checks
# can never be granted or revoked and %access always falls back to defaultacl.
# Every can_access test is then true for anyone holding the module at all --
# which matters here, because this module rewrites Apache configuration that
# Apache parses as root.

do 'modsec-lib.pl';

# acl_security_form(\%access)
# Emit the per-user rights form.
sub acl_security_form
{
my ($a) = @_;
print &ui_table_row($text{'acl_view'},
	&ui_yesno_radio("view", $a->{'view'} ? 1 : 0));
print &ui_table_row($text{'acl_allow'},
	&ui_yesno_radio("allow", $a->{'allow'} ? 1 : 0));
print &ui_table_row($text{'acl_remove'},
	&ui_yesno_radio("remove", $a->{'remove'} ? 1 : 0));
print &ui_table_row($text{'acl_toggle'},
	&ui_yesno_radio("toggle", $a->{'toggle'} ? 1 : 0));
}

# acl_security_save(\%access, \%in)
# Store the submitted rights.
sub acl_security_save
{
my ($a, $i) = @_;
$i ||= \%in;
foreach my $r ('view', 'allow', 'remove', 'toggle') {
	$a->{$r} = $i->{$r} ? 1 : 0;
	}
}

1;
