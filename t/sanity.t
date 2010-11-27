# vi:ft=perl

use strict;
use warnings;

use Test::Base 'no_plan';
use IPC::Run3;
use Cwd;
use Test::LongString;

run {
    #print $json_xs->pretty->encode(\@new_rows);
    #my $res = #print $json_xs->pretty->encode($res);
    my $block = shift;
    my $name = $block->name;

    my $lua = $block->lua or
        die "No --- lua specified for test $name\n";

    if (defined $block->in) {
        my $in = $block->in;
        $in =~ s/'/\\'/g;
        $lua =~ s/<<in>>/$in/;
    }

    open my $fh, ">test_case.lua";
    print $fh $lua;
    close $fh;

    my ($res, $err);

    my @cmd;

    if ($ENV{TEST_LUA_USE_VALGRIND}) {
        @cmd =  ('valgrind', '-q', '--leak-check=full', 'lua', 'test_case.lua');
    } else {
        @cmd =  ('lua', 'test_case.lua');
    }

    run3 \@cmd, undef, \$res, \$err;

    if (defined $block->chomp_got) {
        chomp $res;
    }

    print "res:$res\nerr:$err\n";

    if (defined $block->err) {
        $err =~ /.*:.*:.*: (.*\s)?/;
        $err = $1;
        is $err, $block->err, "$name - err expected";
    } elsif ($?) {
        die "Failed to execute --- lua for test $name: $err\n";
    } else {
        is $res, $block->out, "$name - output ok";
    }
    unlink 'test_case.lua' or warn "could not delete \'test_case.lua\':$!";
}

__DATA__

=== TEST 1: encrypt test
--- in chomp
abc
--- lua
m = require("mcrypt")
k = "abcdefgx"
iv = "529b57ba"
print(m.bf_cfb_en(k, iv, '<<in>>'))
--- chomp_got
--- out chomp base64_decode
zJYV


=== TEST 2: decrypt test
--- in chomp base64_decode
zJYV
--- lua
m = require("mcrypt")
k = "abcdefgx"
iv = "529b57ba"
print(m.bf_cfb_de(k, iv, '<<in>>'))
--- chomp_got
--- out chomp
abc


=== TEST 3: encrypt test error iv len
--- lua
m = require("mcrypt")
k = "abcdefgx"
iv = "529b57b"
print(m.bf_cfb_de(k, iv, ''))
--- chomp_got
--- err
error iv len


=== TEST 4: decrypt with short k <8-128>
--- lua
m = require("mcrypt")
k = 'abc'
iv = "529b57b"
print(m.bf_cfb_de(k, iv, ''))
--- chomp_got
--- err
error k len


=== TEST 4: decrypt with nil k
--- lua
m = require("mcrypt")
k = nil
iv = "529b57b"
print(m.bf_cfb_de(k, iv, ''))
--- chomp_got
--- err
bad argument #1 to 'bf_cfb_de' (string expected, got nil)


=== TEST 4: decrypt with nil iv
--- lua
m = require("mcrypt")
k = "abcdefgx"
iv = nil
print(m.bf_cfb_de(k, iv, ''))
--- chomp_got
--- err
bad argument #2 to 'bf_cfb_de' (string expected, got nil)


=== TEST 4: decrypt with nil value
--- lua
m = require("mcrypt")
k = "abcdefgx"
iv = "529b57ba"
print(m.bf_cfb_de(k, iv, nil))
--- chomp_got
--- err
bad argument #3 to 'bf_cfb_de' (string expected, got nil)


=== TEST 4: decrypt with empty string value
--- lua
m = require("mcrypt")
k = "abcdefgx"
iv = "529b57ba"
print('[' .. m.bf_cfb_de(k, iv, '') .. ']')
--- chomp_got
--- out chomp
[]
