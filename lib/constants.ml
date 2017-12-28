let iana_protocols = (* see /etc/protocols *)
  [ "ip",      0 ;
    "icmp",    1 ;
    "igmp",    2 ;
    "ipencap", 4 ;
    "tcp",     6 ;
    "udp",    17 ;
    "dccp",   33 ;
    "ipv6",   41 ;
    "ipv6-route", 43 ;
    "ipv6-frag",  44 ;
    "gre",    47 ;
    "esp",    50 ;
    "ah",     51 ;
    "ipv6-icmp",  58 ;
    "ipv6-nonxt", 59 ;
    "ipv6-opts",  60 ;
    "ipip",   94 ;
    "l2tp",  115 ;
    "sctp",  132 ;
    "carp",  112 ; (* CARP vrrp # Common Address Redundancy Protocol *)
    "pfsync",240 ;

  ]

let iana_icmp_types = (* see `man icmp` *)
  [ "echorep", 0; (*Echo reply     *)
    "unreach", 3; (*Destination unreachable     *)
    "squench", 4; (*Packet loss, slow down   *)
    "redir", 5; (*Shorter route exists    *)
    "althost", 6; (*Alternate host address    *)
    "echoreq", 8; (*Echo request     *)
    "routeradv", 9; (*Router advertisement     *)
    "routersol", 10; (*Router solicitation     *)
    "timex", 11; (*Time exceeded     *)
    "paramprob", 12; (*Invalid IP header    *)
    "timereq", 13; (*Timestamp request     *)
    "timerep", 14; (*Timestamp reply     *)
    "inforeq", 15; (*Information request     *)
    "inforep", 16; (*Information reply     *)
    "maskreq", 17; (*Address mask request    *)
    "maskrep", 18; (*Address mask reply    *)
    "trace", 30; (*Traceroute      *)
    "dataconv", 31; (*Data conversion problem    *)
    "mobredir", 32; (*Mobile host redirection    *)
    "ipv6-where", 33; (*IPv6 where-are-you     *)
    "ipv6-here", 34; (*IPv6 i-am-here     *)
    "mobregreq", 35; (*Mobile registration request    *)
    "mobregrep", 36; (*Mobile registration reply    *)
    "skip", 39; (*SKIP      *)
    "photuris", 40; (*Photuris      *)
  ]

let iana_icmp_codes = (* see `man icmp` *)
  [ "net-unr", 0; (*unreach :  Network unreachable    *)
    "host-unr", 1; (*unreach :  Host unreachable    *)
    "proto-unr", 2; (*unreach :  Protocol unreachable    *)
    "port-unr", 3; (*unreach :  Port unreachable    *)
    "needfrag", 4; (*unreach :  Fragmentation needed but DF bit set *)
    "srcfail", 5; (*unreach :  Source routing failed   *)
    "net-unk", 6; (*unreach :  Network unknown    *)
    "host-unk", 7; (*unreach :  Host unknown    *)
    "isolate", 8; (*unreach :  Host isolated    *)
    "net-prohib", 9; (*unreach :  Network administratively prohibited *)
    "host-prohib", 10; (*unreach :  Host administratively prohibited *)
    "net-tos", 11; (*unreach :  Invalid TOS for network  *)
    "host-tos", 12; (*unreach :  Invalid TOS for host  *)
    "filter-prohib", 13; (*unreach :  Prohibited access    *)
    "host-preced", 14; (*unreach :  Precedence violation    *)
    "cutoff-preced", 15; (*unreach :  Precedence cutoff    *)
    "redir-net", 0; (*redir :  Shorter route for network  *)
    "redir-host", 1; (*redir :  Shorter route for host  *)
    "redir-tos-net", 2; (*redir :  Shorter route for TOS and network*)
    "redir-tos-host", 3; (*redir :  Shorter route for TOS and host*)
    "normal-adv", 0; (*routeradv :  Normal advertisement    *)
    "common-adv", 16; (*routeradv :  Selective advertisement    *)
    "transit", 0; (*timex :  Time exceeded in transit  *)
    "reassemb", 1; (*timex :  Time exceeded in reassembly  *)
    "badhead", 0; (*paramprob :  Invalid option pointer   *)
    "optmiss", 1; (*paramprob :  Missing option    *)
    "badlen", 2; (*paramprob :  Invalid length    *)
    "unknown-ind", 1; (*photuris :  Unknown security index   *)
    "auth-fail", 2; (*photuris :  Authentication failed    *)
    "decrypt-fail", 3; (*photuris :  Decryption failed    *)
  ]

let iana_services = (* see /etc/services *)
  ("spamd"):: (* SpamAssassin, port 783 *)
  Uri_services_full.known_tcp_services
