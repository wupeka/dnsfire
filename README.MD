# Proof-of-concept for a DNS Firewall Enforcer, using BIND9 and ipset (or any other CLI-controllable firewall).


## What is a DNS Firewall Enforcer

### What is a DNS Firewall
DNS Firewall is a solution that prevents users and systems from connecting
to mailicious services by filtering DNS queries - and not returning the IP
addresses of known mailicious services to user.

### The problem
Filtering DNS queries is easy - DNS runs on port 53, it's unencrypted, the
traffic to outside (unfiltered) resolvers can easily be blocked. The same
works with DNS over TLS - it's using a well-known port 953, which can easily
be firewalled.

The problem arises with DNS over HTTPS - from a regular firewall standpoint
the protocol is indistinguishable from regular HTTPS traffic - so it cannot
be properly filtered (unless one strips TLS and does deep packet
inspection).

### The solution
In most cases a client needs to resolve a domain name to IP address to
connect to any service - so a client connecting to an IP address that wasn't
resolved by a local DNS is suspicious. DNSFIRE solves the problem by either
logging or blocking completely connections to IP addresses that were not
resolved using a local, safe, and secure DNS service.

## How does it work
### BIND9
Apply bind9-dnsfire.patch to bind 9.14/9.15 source tree and rebuild it.
Then add:
```
 dnsfire <key> <ip> port <port>;
```
somewhere in your options {} section; for example:
```
 dnsfire 01234567890123456789012345678901 192.168.1.1 port 15353
```
Key is a 128-bit SipHash-2-4 key used to authenticate requests to the router, just pick a
random 32-character hex string.

### Router running Linux with iptables and ipset
dnsfire-ipsetd is a daemon that adds timeoutable rules to provided ipsets -
one for ipv4, and one for ipv6.

To use it first create two ipsets with timeout support:
```
ipset create table4 hash:ip family inet timeout 0
ipset create table6 hash:ip family inet6 timeout 0
```
Then launch dnsfire-ipsetd:
```
./dnsfire-ipsetd -4 table4 -6 table6 -k 01234567890123456789012345678901 -b 192.168.1.1 -p 15353
```

If everything is configured correctly you should see IPs being added by looking at output of
```
ipset list
```
Currently dnsfire-ipsetd uses command 'ipset' and a system() call to set up
new rules, this will be rewritten to use libipset sometime.

Then you can e.g. add a rule to iptables to log traffic to addresses that were
not resolved using system resolver:
```
iptables -I FORWARD -s 192.168.1.0/24 \! -d 192.168.0.0/16 -m conntrack --ctstate NEW -m set \! --match-set table4 dst -j LOG
```

### Any other router
If your router has a CLI command to add and remove allowed IPs use:
```
./dnsfire-cmdd -4 "echo add_ipv4_to_fw ip=%s" -5 "echo del_ipv4_from_fw ip=%s" -6 "echo add_ipv6_to_fw ip=%s" -7 "echo del_ipv6_from_fw ip=%s"
```
"%s" is replaced with IP address to be added/deleted. The rest of command line options are the same as with dnsfire-ipsetd. 
