#!/usr/bin/env perl
# 20200223 Kirby

use Algorithm::LUHN qw/check_digit is_valid/;
use strict;

# https://baymard.com/checkout-usability/credit-card-patterns

$|++;

open(FD,"<","/var/log/suricata/eve.json.fifo");
while(<FD>) {
    if ( $_ !~ /Possible card number detected in clear text/ ) {
        open(EJ,">>","/var/log/suricata/eve.json");
        print EJ $_;
        close(EJ);
        next;
    }
    my $foundluhn = 0;
    my $blob;
    my @blobs;
    @blobs = ( $_ =~ m/([2-9]\d{3}-\d{4}-\d{4}-\d{4}-\d{3}|
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
        #print "FOUND MATCHED LINE: $_\n";
        next if not ( $blob =~ m/\d/g );
        if ( $_ =~ m/[\d\.]${blob}/g ) {
            #print "skipping $blob\n";
            next;
        }
        if ( $_ =~ m/flow_id":$blob/g ) {
            #print "skipping $blob\n";
            next;
        }
        my $match = $blob;
        my $strippedmatch = $match;
        $strippedmatch =~ s/(\s|-)//g;
        #print "testing $match $strippedmatch\n";
        if ( is_valid("$strippedmatch")) {
            #print "THIS IS A CARD $strippedmatch\n";
            $_ =~ s/$match/LUHN_ALGORITHM_MATCHED/g;
            $foundluhn = 1;
        }
    }
    if ( $foundluhn eq 1 ) {
        $_ =~ s/"payload":"[^"]+"/"payload":""/g;
        $_ =~ s/"packet":"[^"]+"/"packet":""/g;
        open(EJ,">>","/var/log/suricata/eve.json");
        print EJ $_;
        close(EJ);
    }
}
close(FD);


