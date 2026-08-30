use strict;
use Safe;
use utf8;

my @emit_list;
#===============================================================================
package rdlppp_utils;

sub emit_ref {
    my ($ref) = @_;
    push @emit_list, {
        type => "ref",
        ref => $ref
    };
}

sub emit_text {
    my ($ref, $text) = @_;
    push @emit_list, {
        type => "text",
        ref => $ref,
        text => $text
    };
}

#===============================================================================
package main;

# Get safe opcodes from commandline arg
my @safe_opcodes = split /,/, $ARGV[0];

# Collect preprocess miniscript from stdin
my $miniscript;
while(<STDIN>) {
    $miniscript .= $_;
}

# Run miniscript in restricted context
my $compartment = new Safe;
foreach my $opcode (@safe_opcodes) {
    $compartment->permit($opcode);
}
# %ENV is no longer shared into the compartment. The miniscript is generated from
# perl blocks embedded in the .rdl source being compiled, so sharing the parent
# process's environment handed that source read access to every environment
# variable of the build -- CI secrets, API tokens, signing keys -- with
# rdlppp_utils::emit_text() available as a ready-made exfiltration channel that
# writes the value straight into the preprocessed output. Nothing in the register
# map expansion needs it; a design that must parameterise on the environment
# should have the value passed in explicitly by the tool invoking the compiler.
$compartment->share_from('main', [
    'rdlppp_utils::emit_ref',
    'rdlppp_utils::emit_text'
]);
$compartment->reval($miniscript);

if($@) {
    print STDERR $@;
    exit 1;
}


# Simplified serialization to JSON
my %esc = (
    "\n" => '\n',
    "\r" => '\r',
    "\t" => '\t',
    "\f" => '\f',
    "\b" => '\b',
    "\"" => '\"',
    "\\" => '\\\\',
    "\'" => '\\\'',
);

sub escape_string {
    my ($arg) = @_;
    $arg =~ s/([\x22\x5c\n\r\t\f\b])/$esc{$1}/g;
    #$arg =~ s/\//\\\//g;
    $arg =~ s/([\x00-\x08\x0b\x0e-\x1f])/'\\u00' . unpack('H2', $1)/eg;
    utf8::encode($arg);
    return $arg;
}

my @json_array_entries;
foreach my $entry (@emit_list) {
    my $entry_json;

    $entry_json .= '{';
    $entry_json .= '"type":"'.$entry->{type}.'",';
    $entry_json .= '"ref":'.$entry->{ref};

    if($entry->{type} eq "text") {
        $entry_json .= ',"text":"' . escape_string($entry->{text}) . '"';
    }
    $entry_json .= "}";
    push @json_array_entries, $entry_json;
}

print("[" . join(",\n", @json_array_entries) . "]\n");
