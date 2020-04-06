#!/usr/bin/env perl
# 20200402 Kirby

use Algorithm::LUHN qw/check_digit is_valid/;
use Sys::Syslog qw(:standard :macros setlogsock);
use strict;

# https://baymard.com/checkout-usability/credit-card-patterns

$|++;
fork && exit;

my %sh;

my $file=$ARGV[0];
my $syslog=$ARGV[1];
my $syslogport=$ARGV[2];

my $program='suricata';

openlog('luhnmask.pl', "ndelay,pid", "daemon");
setlogsock({ type => "udp", host => "$syslog", port => "$syslogport" });
syslog('info', "luhnmask.pl starting up");
closelog();

open(FD,"<","$file");
while(<FD>) {
    if ( $_ !~ /Possible card number detected in clear text/ ) {
        openlog($program, "ndelay,pid", "daemon");
        setlogsock({ type => "udp", host => "$syslog", port => "$syslogport" });
        syslog('info', "$_");
        closelog();
        next;
    }
    my $src_ip = $1 if ( $_ =~ m|"src_ip":"([^"]+)"| );
    my $dest_ip = $1 if ( $_ =~ m|"dest_ip":"([^"]+)"| );
    my $hash = $src_ip . '-' . $dest_ip;
    my $oldhash;
    my $line;
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
        next if ( $_ =~ m/flow_id":$blob/ig );
        next if ( $_ =~ m/etag: \S+$blob/ig );
        next if ( $_ =~ m/etag: $blob/ig );
        next if ( $_ =~ m/cookie":" [^:]+$blob/ig );
        next if ( $_ =~ m/Cookie: \S+$blob/ig );
        next if ( $_ =~ m/Location: \S+$blob/ig );
        next if ( $_ =~ m/[\d\.%-;A-Za-z]$blob/ig );
        next if ( $_ =~ m/$blob[-:;\/A-Za-z]/ig );

        my $stripblob = $blob;
        $stripblob =~ s/(\s|-)//g;

        # skip if a digit repeats 5 or more times
        next if ( $stripblob =~ m/0{6}/g );
        next if ( $stripblob =~ m/1{6}/g );
        next if ( $stripblob =~ m/2{6}/g );
        next if ( $stripblob =~ m/3{6}/g );
        next if ( $stripblob =~ m/4{6}/g );
        next if ( $stripblob =~ m/5{6}/g );
        next if ( $stripblob =~ m/6{6}/g );
        next if ( $stripblob =~ m/7{6}/g );
        next if ( $stripblob =~ m/8{6}/g );
        next if ( $stripblob =~ m/9{6}/g );

        # skip test cards
        next if ( $stripblob =~ m/4444222233331111/g );
        next if ( $stripblob =~ m/4242424242424242/g );
        next if ( $stripblob =~ m/5555555555554444/g );
        next if ( $stripblob =~ m/378282246310005/g );

        # skip dates
        next if ( $stripblob =~ m/20[0-2][0-9][01][0-9][0-3]\d+/g );


        if ( is_valid("$stripblob")) {
            #print "THIS IS A CARD $stripblob\n";
            $_ =~ s/$blob/LUHN_ALGORITHM_MATCHED/g;
            $foundluhn++;
        }
    }

    if ( $foundluhn >= 1 ) {
        #print "foundluhn count is $foundluhn\n";

        $sh{$hash}{count} += $foundluhn;
        $sh{$hash}{time} = time;

        $_ =~ s/"payload":"[^"]+"/"payload":""/g;
        $_ =~ s/"packet":"[^"]+"/"packet":""/g;

        push( @{ $sh{$hash}{lines} }, $_);

        # threshold to alert
        if ( $sh{$hash}{count} >= 10 ) {
            foreach $line (@{ $sh{$hash}{lines} }) {
                openlog($program, "ndelay,pid", "daemon");
                setlogsock({ type => "udp", host => "$syslog", port => "$syslogport" });
                syslog('info', "$_");
                closelog();
            }
            delete $sh{$hash};
        }
    }

    # delete old hashes
    foreach my $oldhash ( keys %sh ) {
        if ( $sh{$oldhash}{time} < time - 60 ) {
            #print "deleting $oldhash time $sh{$oldhash}{time}\n";
            delete $sh{$oldhash};
        }
    }

}
close(FD);


