#!/usr/bin/env perl
# 20200222 Kirby

use Algorithm::LUHN qw/check_digit is_valid/;
use strict;

# https://baymard.com/checkout-usability/credit-card-patterns

open(FD,"<","/var/log/suricata/eve.json.fifo");
while(<FD>) {
    my $foundluhn = 0;
    next unless ( $_ =~ /Possible card number detected in clear text/ );
    my $line = $_;
    my $blob;
    my @blobs;
    #@blobs = ( $line =~ m/([\D\s]|^)([2-9]\d{3}-\d{4}-\d{4}-\d{4}-\d{3}|
    @blobs = ( $line =~ m/([2-9]\d{3}-\d{4}-\d{4}-\d{4}-\d{3}|
        [2-9]\d{3}-\d{4}-\d{4}-\d{4}|
        [2-9]\d{3}-\d{4}-\d{5}|
        [2-9]\d{3}-\d{5}-\d{6}|
        [2-9]\d{3}-\d{6}-\d{4}|
        [2-9]\d{3}-\d{6}-\d{5}|
        [2-9]\d{3}-\d{7}-\d{4}|
        [2-9]\d{3}\s\d{4}\s\d{4}\s\d{4}|
        [2-9]\d{3}\s\d{4}\s\d{4}\s\d{4}\s\d{3}|
        [2-9]\d{3}\s\d{4}\s\d{5}|
        [2-9]\d{3}\s\d{5}\s\d{6}|
        [2-9]\d{3}\s\d{6}\s\d{4}|
        [2-9]\d{3}\s\d{6}\s\d{5}|
        [2-9]\d{3}\s\d{7}\s\d{4}|
        [2-9]\d{5}-\d{13}|
        [2-9]\d{5}\s\d{13}|
        [2-9]\d{14,18})([\D\s\Z\z]|$)/xg );
        
    foreach $blob ( @blobs ) {
        #print "FOUND MATCHED LINE: $line\n";
        next if not ( $blob =~ m/\d/g );
        if ( $line =~ m/[\d\.]${blob}/g ) {
            #print "skipping $blob\n";
            next;
        }
        my $match = $blob;
        my $strippedmatch = $match;
        $strippedmatch =~ s/(\s|-)//g;
        #print "testing $match $strippedmatch\n";
        if ( is_valid("$strippedmatch")) {
            #print "THIS IS A CARD $strippedmatch\n";
            #$line =~ s/$match/LUHN_ALGORITHM_${strippedmatch}_MATCHED/g;
            $line =~ s/$match/LUHN_ALGORITHM_MATCHED/g;
            $foundluhn = 1;
        }
        #print "blob " . $blob . "\n";
    }
    if ( $foundluhn == 1 ) {
        $line =~ s/"payload":"[^"]+"/"payload":""/g;
        $line =~ s/"packet":"[^"]+"/"packet":""/g;
        open(EJ,">>","/var/log/suricata/eve.json");
        print EJ $line;
        close(EJ);
    }
}
close(FD);


