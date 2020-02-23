#!/usr/local/bin/bash
# 20200223 Kirby


# CHANGE SYSLOGSERVER TO YOUR SYSLOG SERVER

# make sure you cpan install Algorithm::LUHN
# Enable EVE JSON Log with output type FILE
# Enable EVE Log Alerts with PRINTABLE

export PATH=$PATH:/usr/local/bin:/usr/local/sbin

find /var/log/suricata -name 'eve.json.*' -type f -exec rm {} \;

if find /var/log/suricata -name 'eve.json' -type f |grep -q 'eve.json' \
|| ! pgrep -f luhnmask.pl >/dev/null 2>&1
then
    logger "$_ restarting processes for suricata and luhnmask.pl" 
    pkill luhnmask.pl 

    for file in $(find /var/log/suricata -name 'eve.json' -type f)
    do
        rm -f "$file"
        mkfifo "$file"
    done
    for fifo in $(find /var/log/suricata -name 'eve.json' -type p)
    do
        nohup /root/luhnmask.pl "$fifo" SYSLOGSERVER 514 &
        disown
    done

    for pid in $(ps aux|grep -v awk |awk '/suricata/ {print $2}')
    do 
        kill -HUP $pid
    done
fi

date > /tmp/mydate
