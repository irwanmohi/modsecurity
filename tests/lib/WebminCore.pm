# Minimal WebminCore stand-in so the rule generators can be exercised without a
# Webmin installation. Only what modsec-lib.pl touches is provided, and the
# file-writing helpers work on real temp files so generated output can be read
# back exactly as it would be written on a server.
package WebminCore;

my %CACHE;

# Set by tests to a coderef taking the command string and returning its output.
our $BACKQUOTE;

sub import
{
my $c = caller;
no strict 'refs';
*{"${c}::init_config"}     = sub { };
*{"${c}::get_module_acl"}  = sub { return (allow=>1, remove=>1, toggle=>1); };
*{"${c}::has_command"}     = sub { return $_[0] eq 'apache2ctl' ? '/usr/sbin/apache2ctl' : undef; };
*{"${c}::read_file_lines"} = sub {
	my ($f) = @_;
	my @a;
	if (open(my $h, "<", $f)) { while (<$h>) { chomp; push(@a, $_); } close($h); }
	$CACHE{$f} = \@a;
	return \@a;
	};
*{"${c}::flush_file_lines"} = sub {
	my ($f) = @_;
	open(my $h, ">", $f) || return;
	print $h join("\n", @{$CACHE{$f}}), "\n";
	close($h);
	};
*{"${c}::read_file_contents"} = sub {
	my ($f) = @_;
	local $/;
	open(my $h, "<", $f) || return undef;
	my $d = <$h>;
	close($h);
	return $d;
	};
*{"${c}::open_tempfile"} = sub {
	my $m = $_[1];
	$m =~ s/^(>>?)//;
	open(my $h, ($1 || ">"), $m) || return 0;
	$_[0] = $h;
	return 1;
	};
*{"${c}::print_tempfile"}   = sub { print {$_[0]} $_[1]; };
*{"${c}::close_tempfile"}   = sub { close($_[0]); };
*{"${c}::backquote_command"} = sub {
	# Tests set $WebminCore::BACKQUOTE to fake (or pass through) shell output,
	# which is how the mod_remoteip detection gets exercised without Apache.
	return $WebminCore::BACKQUOTE->($_[0]) if ($WebminCore::BACKQUOTE);
	$? = 0;
	return "";
	};
*{"${c}::backquote_logged"}  = sub { $? = 0; return ""; };
*{"${c}::foreign_check"}     = sub { return 0; };
*{"${c}::foreign_require"}   = sub { };
*{"${c}::make_dir"}          = sub { mkdir($_[0]); };
*{"${c}::copy_source_dest"}  = sub { };
*{"${c}::get_module_info"}   = sub { return (); };
*{"${c}::config"} = \%{"${c}::config"};
*{"${c}::access"} = \%{"${c}::access"};
*{"${c}::text"}   = \%{"${c}::text"};
}

1;
