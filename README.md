# suricata-luhnmask

This will mask numbers found by Suricata that may be read credit cards.

Add this custom rule to /etc/suricata/rules/custom.rules:

alert tcp any any <> any any ( msg:"Possible card number detected in clear text"; sid: 9000001; rev: 1; pcre: "/([2-9]\d{3}-\d{4}-\d{4}-\d{4}-\d{3}|[2-9]\d{3}-\d{4}-\d{4}-\d{4}|[2-9]\d{3}-\d{4}-\d{5}|[2-9]\d{3}-\d{5}-\d{6}|[2-9]\d{3}-\d{6}-\d{4}|[2-9]\d{3}-\d{6}-\d{5}|[2-9]\d{3}-\d{7}-\d{4}|[2-9]\d{3}\s\d{4}\s\d{4}\s\d{4}|[2-9]\d{3}\s\d{4}\s\d{4}\s\d{4}\s\d{3}|[2-9]\d{3}\s\d{4}\s\d{5}|[2-9]\d{3}\s\d{5}\s\d{6}|[2-9]\d{3}\s\d{6}\s\d{4}|[2-9]\d{3}\s\d{6}\s\d{5}|[2-9]\d{3}\s\d{7}\s\d{4}|[2-9]\d{5}-\d{13}|[2-9]\d{5}\s\d{13}|[2-9]\d{14,18})([\s\D]|$)/"; )

alert tcp any any <> any any ( msg:"Possible card number detected in clear text"; sid: 9000001; rev: 1; pcre: "/([2-9]\d{3}\s?-?\d{4}\s?-?\d{4}\s?-?\d{4}\s?-?\d{3}|[2-9]\d{3}\s?-?\d{4}\s?-?\d{4}\s?-?\d{4}|[2-9]\d{3}\s?-?\d{4}\s?-?\d{5}|[2-9]\d{3}\s?-?\d{5}\s?-?\d{6}|[2-9]\d{3}\s?-?\d{6}\s?-?\d{4}|[2-9]\d{3}\s?-?\d{6}\s?-?\d{5}|[2-9]\d{3}\s?-?\d{7}\s?-?\d{4}|[2-9]\d{5}\s?-?\d{13}|[2-9]\d{14,18})([\s\D]|$)/"; )

alert udp any any <> any any ( msg:"Possible card number detected in clear text"; sid: 9000002; rev: 1; pcre: "/([2-9]\d{3}-\d{4}-\d{4}-\d{4}-\d{3}|[2-9]\d{3}-\d{4}-\d{4}-\d{4}|[2-9]\d{3}-\d{4}-\d{5}|[2-9]\d{3}-\d{5}-\d{6}|[2-9]\d{3}-\d{6}-\d{4}|[2-9]\d{3}-\d{6}-\d{5}|[2-9]\d{3}-\d{7}-\d{4}|[2-9]\d{3}\s\d{4}\s\d{4}\s\d{4}|[2-9]\d{3}\s\d{4}\s\d{4}\s\d{4}\s\d{3}|[2-9]\d{3}\s\d{4}\s\d{5}|[2-9]\d{3}\s\d{5}\s\d{6}|[2-9]\d{3}\s\d{6}\s\d{4}|[2-9]\d{3}\s\d{6}\s\d{5}|[2-9]\d{3}\s\d{7}\s\d{4}|[2-9]\d{5}-\d{13}|[2-9]\d{5}\s\d{13}|[2-9]\d{14,18})([\s\D]|$)/"; )





Make sure you are including the custom.rules in /etc/suricata/suricata.yaml and selks5-addin.yaml

Put luhnmask-run.sh and luhnmask.pl in /root

Run "/root/luhnmask-run.sh >/dev/null 2>&1" every minute in cron.

