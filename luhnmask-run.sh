#!/bin/bash
# 20200222 Kirby

if egrep -q "eve.json$" /etc/suricata/*.yaml \
|| ! pgrep -f luhnmask.pl >/dev/null 2>&1
then
    systemctl stop suricata
    sleep 5
    rm -f /var/run/suricata.pid >/dev/null 2>&1
    pkill luhnmask.pl >/dev/null 2>&1
    perl -pi -e 's/eve.json$/eve.json.fifo/g' /etc/suricata/*.yaml
    rm -f /var/log/suricata/eve.json >/dev/null 2>&1
    mkfifo /var/log/suricata/eve.json.fifo >/dev/null 2>&1
    chown logstash:logstash /var/log/suricata/eve.json.fifo >/dev/null 2>&1
    touch /var/log/suricata/eve.json >/dev/null 2>&1
    chown logstash:logstash /var/log/suricata/eve.json >/dev/null 2>&1
    nohup /root/luhnmask.pl >/dev/null 2>&1 &
    disown
    systemctl restart suricata
fi
