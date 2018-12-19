# dnart

DNART (DoS Network Analysis in Real Time) is a fairly simple Java application which pulls alerts from a Suricata server with the following rulesets applied:

```
pass ip any any -> fe80::/10 any (msg: "Ignore local IPv6 traffic"; sid: 10004; rev:1)
alert ip !$HOME_NET any -> $HOME_NET any (msg: "pkt_smp"; flow:to_server, not_established, no_frag; threshold: type threshold, track by_dst, count 40, seconds 40; sid:10003; rev:1;)
```

Suricata has a feature via EVE that allows you to export alerts in JSON format to Redis, which DNART uses to retrieve sample packets from in pub/sub mode.  Configuring Suricata to do this is as easy as,

```
...

outputs:
  - fast:
      enabled: no

  - eve-log:
      enabled: yes
      type: redis
      redis:
        server: 192.168.2.55
        port: 6379
        mode: publish
        key: "suricata"
      filename: eve.json
      identity: "suricata"
      facility: local1
      level: info
      types:
        - alert:
            payload: yes           # enable dumping payload in Base64
            payload-printable: no # enable dumping payload in printable (lossy) format
            packet: yes            # enable dumping of packet (without stream segments)
            http: no              # enable dumping of http fields
            tls: no               # enable dumping of tls fields
            ssh: no               # enable dumping of ssh fields
            smtp: no              # enable dumping of smtp fields
            dnp3: no              # enable dumping of DNP3 fields
            tagged-packets: yes    # enable logging of tagged packets
...
```

# Visual Overview

<p align="center"><img src="https://i.imgur.com/sZu9swg.png" /></p>
<br/><br/>
<p align="center"><img src="https://i.imgur.com/HUBOQNR.png" /></p>
<br/><br/>
<p align="center"><img src="https://i.imgur.com/YNW0EU2.png" /></p>
<br/><br/>
<p align="center"><img src="https://i.imgur.com/yeywzQo.pngg" /></p>
<br/><br/>
<p align="center"><img src="https://i.imgur.com/FNEncIx.png" /></p>
<br/><br/>
