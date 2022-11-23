# dnsfilter

Filters unsecure DNS requests over UDP port 53 using netfilter userspace packet hook (NFQUEUE). It supports remote content classifying and ACLs to block/allow certain queries. Only A queries support ATM.
