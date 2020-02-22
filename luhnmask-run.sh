#!/bin/bash
# 20200222 Kirby

if egrep -q "eve.json$" /etc/suricata/*.yaml \
|| ! pgrep -f luhnmask.pl >/dev/null 2>&1
then
    logger "$_ restarting processes for suricata and luhnmask.pl" 
    systemctl stop suricata 
    sleep 5
    rm -f /var/run/suricata.pid 
    pkill luhnmask.pl 
    perl -pi -e 's/eve.json$/eve.json.fifo/g' /etc/suricata/*.yaml
    rm -f /var/log/suricata/eve.json 
    mkfifo /var/log/suricata/eve.json.fifo 
    chown logstash:logstash /var/log/suricata/eve.json.fifo 
    touch /var/log/suricata/eve.json 
    chown logstash:logstash /var/log/suricata/eve.json 
    nohup /root/luhnmask.pl 
    disown
    systemctl restart suricata
fi
