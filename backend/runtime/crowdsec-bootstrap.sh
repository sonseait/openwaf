#!/bin/sh
# Offline local LAPI provisioning only. Never put a generated credential in argv/logs.
set -eu
umask 077
config=/etc/crowdsec/config.yaml
credentials=/etc/crowdsec/local_api_credentials.yaml
key=/etc/crowdsec/bouncer.key
if [ -f /etc/crowdsec/.provisioned ]; then
    if [ ! -s "$credentials" ] || [ ! -s "$key" ] || [ ! -s /var/lib/crowdsec/data/crowdsec.db ]; then
        echo 'CrowdSec persisted credential/database missing; restore original state.' >&2
        exit 1
    fi
    exit 0
fi
trap 'rm -f /etc/crowdsec/.machine-new /etc/crowdsec/.bouncer-new /etc/crowdsec/.bouncer-raw' EXIT
trap 'exit 1' HUP INT TERM
if [ ! -s "$credentials" ]; then
    if ! cscli -c "$config" machines add openwaf-vps --auto --url http://127.0.0.1:8085 --file /etc/crowdsec/.machine-new >/dev/null 2>&1; then
        echo 'CrowdSec machine provisioning failed; reconcile local database before retry.' >&2
        exit 1
    fi
    mv /etc/crowdsec/.machine-new "$credentials"
fi
if [ ! -s "$key" ]; then
    if ! cscli -c "$config" bouncers add openwaf-vps -o raw > /etc/crowdsec/.bouncer-raw 2>/dev/null; then
        echo 'CrowdSec bouncer provisioning failed; reconcile local database before retry.' >&2
        exit 1
    fi
    tr -d '\r\n' < /etc/crowdsec/.bouncer-raw > /etc/crowdsec/.bouncer-new
    test -s /etc/crowdsec/.bouncer-new
    mv /etc/crowdsec/.bouncer-new "$key"
fi
printf '1\n' > /etc/crowdsec/.provisioned
printf 'CrowdSec local machine and bouncer ready.\n'
