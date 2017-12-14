open Angstrom

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
  ]

let iana_icmp_types =
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

let iana_icmp_codes =
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

let a_negated : bool t = option false (char '!' *> return true)

let is_whitespace = function ' ' | '\t' -> true | _ -> false
let is_quote = function '"' -> true | _ -> false
let not_whitespace c = not (is_whitespace c)

let a_whitespace_unit : unit t =
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let a_ign_whitespace = skip_many a_whitespace_unit

let a_whitespace = skip_many1 a_whitespace_unit

let encapsulated start fini body =
  a_ign_whitespace *> char start *> a_ign_whitespace *>
  body
  <* a_ign_whitespace <* char fini

let encapsulated_opt default start fini body =
  a_ign_whitespace *> option default (encapsulated start fini body)

let a_optional_comma =
  skip_many1 (char ',' *> return () <|> a_whitespace)

let a_match_or_list sep predicate =
  let left, right = match sep with
    | '{' -> '{', '}'
    | '(' -> '(', ')'
    | _ -> failwith (Fmt.strf "Invalid match_or_list char: %C" sep)
  in
  (encapsulated left right (sep_by a_optional_comma predicate))
  <|> (predicate >>| fun p -> [p])

let a_number =
  take_while1 (function '0'..'9' -> true | _ -> false) >>= fun str ->
  match int_of_string str with
  | i -> return i
  | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_string =
  choice [
    encapsulated '"' '"' (take_till is_quote)
  (*; take_while1 (function | '$'|'a'..'z'|'A'..'Z'|'0'..'9'|'_' -> true
                          | _ -> false) (* TODO put this predicate somewhere *)
    TODO this breaks parsing for some reason:
    pass in on $wifi_if from $abc3 to any port { = 2 }
  *)
  ] <?> "during STRING parsing"

let a_include =
  (string "include"
   *> a_string
  ) <?> "INCLUDE"

let a_ipv4_dotted_quad =
  take_while1 (function '0'..'9' |'.' -> true | _ -> false) >>= fun ip ->
  match Ipaddr.V4.of_string ip with
    | None -> fail (Fmt.strf "Invalid IPv4: %S" ip)
    | Some ip -> return ip

let a_ipv6_coloned_hex =
  take_while1 (function '0'..'9' | ':' | 'a'..'f' | 'A'..'F' -> true
                                 | _ -> false) >>= fun ip ->
  match Ipaddr.V6.of_string ip with
  | None -> fail (Fmt.strf "Invalid IPv6: %S" ip)
  | Some ip -> return ip

let a_bandwidth_spec =
  a_number >>= fun n ->
  a_ign_whitespace *>
  choice [ string "b"  *> return (`b n) ;
           string "Kb" *> return (`Kb n) ;
           string "Mb" *> return (`Mb n) ;
           string "Gb" *> return (`Gb n) ;
           string "%"  *> return (`Percentage n) ;
         ]

type pf_name_or_macro = String of string
                      | Macro of string

let a_name_or_macro ~candidates : pf_name_or_macro t =
  a_ign_whitespace *>
  (peek_char_fail >>= function
    | '$' -> char '$' *>
      peek_char_fail >>= begin function
        | 'a'..'z' -> return true
        | _ -> fail "name macro must start with [a-z]"
      end
    | 'a'..'z' -> return false
    | _ -> fail "name must start with [a-z]"
  ) >>= fun is_macro ->
  take_while (function | 'a'..'z' | '_' | '0'..'9' | 'A'..'Z' -> true
                       | _ -> false ) >>= fun str ->
  match is_macro, candidates with
  | true , _ -> return (Macro str)
  | false , None -> return (String str)
  | false , Some valid when List.mem str valid -> return @@ String str
  | false , Some valid -> fail (Fmt.strf "name %S must be one of %a" str
                                  Fmt.(list string) valid )


let a_interface_name = a_name_or_macro ~candidates:None

type pf_ifspec = If_list of (bool * pf_name_or_macro) list
(* negated, name or macro*)

let a_ifspec : pf_ifspec t =
  a_ign_whitespace *>
  a_match_or_list '{'
    ( a_negated >>= fun neg ->
      a_interface_name >>| fun ifn -> (neg, ifn)
    ) >>| fun ifl -> If_list ifl

type pf_flag_set = {f: bool; s: bool; r: bool; p: bool;
                    a: bool; u: bool; e: bool; w: bool}

type pf_flags =
  | Flags_any
  | Flag_set of pf_flag_set * pf_flag_set

let a_flags : pf_flags t =
  (* <a> /<b> | /<b> | "any" *)
  let a_flag = choice [ char 'F' *> return `F ;
                        char 'S' *> return `S ;
                        char 'R' *> return `R ;
                        char 'P' *> return `P ;
                        char 'A' *> return `A ;
                        char 'U' *> return `U ;
                        char 'E' *> return `E ;
                        char 'W' *> return `W ; ] <?> "Invalid flag"
  in
  let flag_map lst =
    List.fold_left (fun acc -> function
        | `F -> {acc with f = true; }
        | `S -> {acc with s = true; }
        | `R -> {acc with r = true; }
        | `P -> {acc with p = true; }
        | `A -> {acc with a = true; }
        | `U -> {acc with u = true; }
        | `E -> {acc with e = true; }
        | `W -> {acc with w = true; }
      ) {f = false; s = false; r = false; p = false;
         a = false; u = false; e = false; w = false} lst
  in
  (string "any" *> return Flags_any)
  <|>
  ( sep_by a_ign_whitespace a_flag >>| flag_map >>= fun fst ->
    a_ign_whitespace *> char '/' *> a_ign_whitespace *>
    sep_by1 a_ign_whitespace a_flag >>| flag_map >>| fun snd ->
    Flag_set (fst,snd))

type pf_fragmentation = | Reassemble
                        | Crop
                        | Drop_ovl

let a_fragmentation : pf_fragmentation t =
  string "fragment" *> a_whitespace *>
  choice [ string "reassemble" *> return Reassemble ;
           string "crop" *> return Crop ;
           string "drop-ovl" *> return Drop_ovl ]

type pf_address = | IP of Ipaddr.t
                  | Dynamic_addr of pf_name_or_macro
                  | Fixed_addr of pf_name_or_macro

let a_ip : Ipaddr.t t =
  (a_ipv4_dotted_quad >>| fun ip -> Ipaddr.V4 ip)
  <|> (a_ipv6_coloned_hex >>| fun ip -> Ipaddr.V6 ip)

let a_address =
  (* interface-name | interface-group |
     "(" ( interface-name | interface-group ) ")" |
     hostname | ipv4-dotted-quad | ipv6-coloned-hex *)
  choice [
    (encapsulated '(' ')' a_interface_name >>| fun name -> Dynamic_addr name);
    (a_ip >>| fun ip -> IP ip);
    (a_interface_name >>| fun name -> Fixed_addr name);
    (* TODO handle difference between interface-name and interface-group*)
  ]

let some t = t >>| fun applied -> Some applied

let a_number_range min' max' =
  a_number >>= function | n when n <= max' && min' <= n -> return n
                        | n -> fail (Fmt.strf "Number out of range: %d" n)

let a_mask_bits = a_number_range 0 128

type pf_name_or_number = | Name of pf_name_or_macro
                         | Number of int

let a_name_or_number ~candidates : pf_name_or_number t =
  (a_number >>| fun n -> Number n)
  <|>
  (a_name_or_macro ~candidates >>| fun n_m -> Name n_m)

type pf_unary_op = | Unary_eq of pf_name_or_number
                   | Unary_not_eq of pf_name_or_number
                   | Unary_lt of pf_name_or_number
                   | Unary_lt_eq of pf_name_or_number
                   | Unary_gt of pf_name_or_number
                   | Unary_gt_eq of pf_name_or_number

let a_unary_op ~candidates : pf_unary_op t =
  let a_next = a_ign_whitespace *> a_name_or_number ~candidates in
  choice [ (string "<=" *> a_next >>| fun n -> Unary_lt_eq n);
           (string ">=" *> a_next >>| fun n -> Unary_gt_eq n);
           (char '<' *> a_next >>| fun n -> Unary_lt n);
           (char '>' *> a_next >>| fun n -> Unary_gt n);
           (string "!=" *> a_next >>| fun n -> Unary_not_eq n);
           (char '=' *> a_next >>| fun n -> Unary_eq n);
           (a_next >>| fun n -> Unary_eq n); (* default to '=' *)
         ]

type pf_binary_op = (* TODO name "pf_range_op" ? *)
  | Range_inclusive of int * int (* 1:4 -> 1,2,3,4 *)
  | Range_exclusive of int * int (* 1><4 -> 2,3 *)
  | Range_except  of int * int   (* 1<>4 -> 0,5,6 [, ..] *)

let a_binary_op : pf_binary_op t =
  a_number >>= fun fst ->
  choice [ string ":" *> return `incl ;
           string "><" *> return `excl ;
           string "<>" *> return `except ] >>= fun mode ->
  a_ign_whitespace *>
  a_number >>| fun snd ->
  match mode with
  | `incl -> Range_inclusive (fst, snd)
  | `excl -> Range_exclusive (fst, snd)
  | `except -> Range_except (fst, snd)

type pf_op = | Binary of pf_binary_op
             | Unary of pf_unary_op

let a_op ~candidates : pf_op t =
  (a_binary_op >>| fun op -> Binary op)
  <|> (a_unary_op ~candidates >>| fun op -> Unary op)

type pf_port = pf_op list

let a_port : pf_port t =
  string "port" *> a_whitespace *>
  a_match_or_list '{'
    ( a_op ~candidates:(Some Uri_services_full.known_tcp_services))
  (* Note that we use the IANA policy (like FreeBSD) of not caring
       whether it is a UDP or TCP service, as opposed to what Debian
        puts in /etc/services, where they for example
        do not have 80/udp assigned to "http".
      TL;DR: Don't pay attention to the use of "known_*TCP*_services" above. *)

type if_or_cidr = | Dynamic_if of pf_name_or_macro
                  | Fixed_if of pf_name_or_macro
                  | CIDR of Ipaddr.Prefix.t

let a_if_or_cidr : if_or_cidr t =
  a_address >>= function
  | Dynamic_addr x -> return @@ Dynamic_if x
  | Fixed_addr x ->   return @@ Fixed_if x
  | IP ip ->
    option None (a_ign_whitespace *> char '/' *> some a_mask_bits)
    >>= (function
        | Some mask ->
          begin match (Ipaddr.to_string ip) ^ "/" ^ (string_of_int mask)
                      |> Ipaddr.Prefix.of_string
            with
            | None -> fail "invalid CIDR"
            | Some cidr -> return (CIDR cidr)
          end
        | None ->
          CIDR Ipaddr.(
            begin match ip with
              | V4 ip -> (V4.to_string ip) ^ "/32"
              | V6 ip -> (V6.to_string ip) ^ "/128"
            end
            |> Prefix.of_string_exn ) |> return
      )

let a_redirhost = a_if_or_cidr

type pf_host =
  | Table_name of bool * string (* negated, name *)
  | Host_addr of { negated : bool ;
                   if_or_cidr : if_or_cidr ; }


let a_host : pf_host t =
  (* [ "!" ] ( address [ "/" mask-bits ] | "<" string ">" )
     string == table name *)
  a_negated >>= fun negated ->
  a_ign_whitespace *>
  (    a_if_or_cidr >>| fun if_or_cidr ->
       Host_addr {negated; if_or_cidr}
  ) <|> ( encapsulated '<' '>' a_string >>| fun table ->
          Table_name (negated, table))

let a_host_list : pf_host list t =
  sep_by (a_optional_comma <|> a_whitespace) a_host

type pf_hosts =
  | All
  | From_to of {from_host : [`any | `no_route | `urpf_failed | `self
                            | `host of pf_host | `host_list of pf_host list ] ;
                from_port : pf_port option ;
                from_os : string option ;
                to_host : [`any | `no_route | `self | `host of pf_host
                          | `host_list of pf_host list ] ;
                to_port : pf_port option ;
               }

let a_hosts : pf_hosts t =
  string "all" *> return All
  <|>
  ( string "from" *> a_whitespace *>
    choice [ string "any" *> return `any ;
             string "no-route" *> return `no_route ;
             string "urpf-failed" *> return `urpf_failed ;
             string "self" *> return `self ;
             (a_host >>| fun host -> `host host) ;
             (encapsulated '{' '}' a_host_list >>| fun lst -> `host_list lst);
           ] >>= fun from_host ->
    let()=Printf.eprintf "past from\n%!"in
    option None (a_whitespace *> some a_port) >>= fun from_port ->
    let()=Printf.eprintf "past opt src port\n%!"in
    option None (a_whitespace *> some a_string) >>= fun from_os ->
    let()=Printf.eprintf "past opt src OS: %s\n%!"
        Fmt.(strf "%a" (option string) from_os) in
    a_whitespace *> string "to" *> a_whitespace >>= fun () ->
    let()=Printf.eprintf "past to keyword\n%!"in
    choice
      [ string "any" *> return `any ;
        string "no-route" *> return `no_route ;
        string "self" *> return `self ;
        (a_host >>| fun host -> `host host) ;
        (encapsulated '{' '}' a_host_list >>| fun lst -> `host_list lst);
      ] >>= fun to_host ->
    let()=Printf.eprintf "past to value\n%!"in
    option None (a_whitespace *> some a_port) >>| fun to_port ->
    let()=Printf.eprintf "past opt dst port\n%!"in
    From_to {from_host ; from_port; from_os ; to_host ; to_port }
  )

type pf_return =
  | Drop
  | Return
  | Return_rst  of int option (* ttl *)
  | Return_icmp of int option * int option (* v4 code , v6 code *)
  | Return_icmp6 of int option

let a_return : pf_return t =
  (* "drop" | "return"
   | "return-rst" [ "( ttl" number ")" ] |
     "return-icmp" [ "(" icmpcode [ [ "," ] icmp6code ] ")" ] |
     "return-icmp6" [ "(" icmp6code ")" ] *)
  choice
    [ string "drop" *> return Drop ;
      string "return" *> return Return ;
      ( string "return-rst" *>
        encapsulated_opt None '(' ')' ( string "ttl" *> some a_number)
        >>| fun ttl -> Return_rst ttl
      ) ;
      ( string "return-icmp" *>
        encapsulated_opt (None,None) '(' ')'
          ( some a_number >>= fun icmpcode ->
            option (icmpcode, None)
              (char ',' *> some a_number >>| fun icmp6code ->
               icmpcode, icmp6code)
          ) >>| fun (v4,v6) -> Return_icmp (v4,v6));
      string "return-icmp6" *> encapsulated_opt None '(' ')' (some a_number)
      >>| fun code -> Return_icmp6 code;
  ]

type pf_action = Pass | Block of pf_return option | Scrub (*TODO "no" *)

let a_action : pf_action t =
  (* "pass" | "block" [ return ] | [ "no" ] "scrub" *)
  choice [ string "pass" *> return Pass ;
           ( string "block" *>
             option None (some a_return) >>| fun ret -> Block ret);
           string "scrub" *> return Scrub;
         ]

let a_proto_name =
  let names, _ = List.split iana_protocols in
  a_name_or_macro ~candidates:(Some names)

let a_proto_number =
  let _, proto_num = List.split iana_protocols in
  choice (List.map (fun i -> string @@ string_of_int i) proto_num)

let a_proto_name_or_number : pf_name_or_number t =
  (* like a_name_or_number, but whitelist against [iana_protocols] *)
  (a_proto_name >>| fun name -> Name name)
  <|> (a_proto_number >>| fun number -> Number (int_of_string number))

type pf_protospec = Proto_list of pf_name_or_number list

let a_protospec : pf_protospec t =
  (* "proto" ( proto-name | proto-number |
               "{" proto-list "}" ) *)
  string "proto" *> a_whitespace *>
  a_match_or_list '{' a_proto_name_or_number >>| fun lst -> Proto_list lst

type pf_logopt = | All
                 | User
                 | To of pf_name_or_macro

let a_logopt : pf_logopt t =
  choice [ string "all" *> return All ;
           string "user" *> return User ;
           ( string "to" *> a_interface_name >>| fun to_if -> To to_if) ]

type pf_routehost = pf_name_or_macro * (pf_address * int option) option
(* why pf doesn't use pf_host here (allowing negation) is beyond me...
   block from $ext ! 1.2.3.4/32
   seems pretty useful to me
*)

let a_routehost : pf_routehost t =
  encapsulated '(' ')'
    (a_interface_name >>= fun name ->
     (option None
        ( a_address >>= fun addr ->
          option None (a_ign_whitespace *> char '/' *>
                       some a_mask_bits) >>| fun mask ->
          Some (addr, mask)
        )
     ) >>| fun addr_and_mask -> name, addr_and_mask
    )

let a_routehost_list : pf_routehost list t =
  sep_by (a_optional_comma <|> a_whitespace) a_routehost

type pf_pooltype = Pooltype_TODO

let a_pooltype : pf_pooltype t =
  choice
    [ string "bitmask" ;
      string "random" ;
      string "source-hash" ;
      string "round-robin" ;
    ] (*TODO*) *>
  return Pooltype_TODO

type pf_route =
  | Fastroute
  | Route of
      { verb : [`route_to | `reply_to | `dup_to ] ;
        routehosts : pf_routehost list ;
        pooltype : pf_pooltype option ;
      }

let a_route : pf_route t =
  choice [string "route-to" *> return `route_to ;
          string "reply-to" *> return `reply_to ;
          string "dup-to"   *> return `dup_to   ;] >>= fun verb ->
  choice [(a_routehost >>| fun rh -> [rh]); a_routehost_list] >>= fun rhosts ->
  option None (a_whitespace *> some a_pooltype) >>|fun pooltype ->
  Route {verb ; routehosts = rhosts ; pooltype }

type pf_icmp_type_code = { icmp_type : pf_name_or_number ;
                           icmp_code : pf_name_or_number option ;
                         }

let a_icmp_type_code : pf_icmp_type_code t =
  (* ( icmp-type-name | icmp-type-number )
     [ "code" ( icmp-code-name | icmp-code-number ) ] *)
  let icmp_type_names = Some (List.map fst iana_icmp_types) in
  let icmp_code_names = Some (List.map fst iana_icmp_codes) in
  (* TODO I guess we should also validate the numbers... *)
  a_name_or_number ~candidates:icmp_type_names >>= fun icmp_type ->
  option None ( a_whitespace *> string "code" *> a_whitespace *>
                some (a_name_or_number ~candidates:icmp_code_names)
              ) >>| fun icmp_code ->
  { icmp_type ; icmp_code }

let a_icmp_list : pf_icmp_type_code list t =
  a_match_or_list '{' a_icmp_type_code

type pf_icmp_type = Icmp_type of pf_icmp_type_code list

let a_icmp_type : pf_icmp_type t =
  (* "icmp-type" ( icmp-type-code | "{" icmp-list "}" ) *)
  string "icmp-type" *> a_whitespace *>
  a_icmp_list >>| fun lst -> Icmp_type lst

type pf_icmp6_type = Icmp6_type of pf_icmp_type_code list

let a_icmp6_type =
  (* "icmp6-type" ( icmp-type-code | "{" icmp-list "}" ) *)
  string "icmp6-type" *> a_whitespace *>
  a_icmp_list >>| fun lst -> Icmp6_type lst

type pf_tos = | Lowdelay
              | Throughput
              | Reliability
              | Tos_number of int

let a_tos : pf_tos t =
  choice [ string "lowdelay"    *> return Lowdelay ;
           string "throughput"  *> return Throughput ;
           string "reliability" *> return Reliability ;
           string "0x" *> fail "TODO TOS: hex-decoding not implemented" ;
           a_number >>| fun i -> Tos_number i ;
         ]

let a_user =
  (* "user" ( unary-op | binary-op | "{" op-list "}" ) *)
  string "user" *> a_whitespace *> a_match_or_list '{' (a_op ~candidates:None)

let a_group =
  (* "group" ( unary-op | binary-op | "{" op-list "}" ) *)
  string "group" *> a_whitespace *> a_match_or_list '{' (a_op ~candidates:None)

type pf_timeout = string * int (* TODO *)

let a_timeout : pf_timeout t =
  (* ( "tcp.first" | "tcp.opening" | "tcp.established" |
       "tcp.closing" | "tcp.finwait" | "tcp.closed" |
       "udp.first" | "udp.single" | "udp.multiple" |
       "icmp.first" | "icmp.error" |
       "other.first" | "other.single" | "other.multiple" |
       "frag" | "interval" | "src.track" |
      "adaptive.start" | "adaptive.end" ) number *)
  a_string >>= fun qualifier -> a_whitespace *> a_number >>| fun time ->
  (qualifier, time)

type pf_state_opt =
  | Max of int
  | No_sync
  | Timeout of pf_timeout
  | Sloppy
  | Pflow
  | Source_track of [`rule | `global] option
  | Max_src_nodes of int
  | Max_src_states of int
  | Max_src_conn of int
  | Max_src_conn_rate of int * int
  | Overload of {table: string; flush: bool}
  | If_bound
  | Floating

let a_state_opt : pf_state_opt t =
  (* ( "max" number | "no-sync" | timeout | "sloppy" | "pflow" |
       "source-track" [ ( "rule" | "global" ) ] |
       "max-src-nodes" number | "max-src-states" number |
       "max-src-conn" number |
       "max-src-conn-rate" number "/" number |
       "overload" "<" string ">" [ "flush" ] |
       "if-bound" | "floating" ) *)
  choice
    [ (string "max" *> a_whitespace *> a_number >>| fun n -> Max n);
      string "no-sync" *> return No_sync ;
      (a_timeout >>| fun tout -> Timeout tout ) ;
      string "sloppy" *> return Sloppy ;
      string "pflow" *> return Pflow ;
      string "source-track" *>
      ( option None ( a_whitespace *>
                      some ( string "rule" *> return `rule
                             <|> string "global" *> return `global )
                    ) >>| fun mode -> Source_track mode) ;
      string "max-src-nodes" *> a_whitespace *>
      ( a_number >>| fun n -> Max_src_nodes n) ;
      string "max-src-states" *> a_whitespace *>
      ( a_number >>| fun n -> Max_src_states n) ;
      ( string "max-src-conn-rate" *> a_whitespace *> a_number >>= fun fst ->
        a_ign_whitespace *> char '/' *> a_ign_whitespace *> a_number
        >>| fun snd -> Max_src_conn_rate (fst, snd)) ;
      string "overload" *> a_ign_whitespace *> char '<' *>
      ( a_string >>= fun table -> char '>' *>
                                  option false (a_ign_whitespace *>
                                                string "flush" *> return true
                                               ) >>| fun flush ->
        Overload {table ; flush } ) ;
      string "if-bound" *> return If_bound ;
      string "floating" *> return Floating ;
    ]

let a_state_opts = sep_by (a_optional_comma <|> a_whitespace) a_state_opt

type pf_filteropt =
  | Filteropt_users of pf_op list
  | Filteropt_groups of pf_op list
  | Flags of pf_flags
  | Filteropt_icmp_type of pf_icmp_type
  | Filteropt_icmp6_type of pf_icmp6_type
  | Tos of pf_tos
  | State of {predicate: [`no | `keep | `modulate | `synproxy ] ;
              state_opts : pf_state_opt list option }
  | Fragment
  | Allow_opts
  | Fragmentation of pf_fragmentation
  | No_df
  | Min_ttl of int
  | Max_mss of int
  | Random_id
  | Reassemble_tcp
  | Label of string
  | Tag of string
  | Tagged of bool * string (* negated , ... *)
  | Queue of string list
  | Rtable of int
  | Probability of int (* match n% of the time *)

let a_filteropt : pf_filteropt t =
  choice
    [ ( a_user >>| fun users -> Filteropt_users users ) ;
      ( a_group >>| fun groups -> Filteropt_groups groups ) ;
      ( a_flags >>| fun flag_set -> Flags flag_set) ;
      ( a_icmp_type >>| fun ty -> Filteropt_icmp_type ty) ;
      ( a_icmp6_type >>| fun ty -> Filteropt_icmp6_type ty) ;
      string "tos" *> a_whitespace *> (a_tos >>| fun tos -> Tos tos);
      (choice [ string "no" *> return `no ;
               string "keep" *> return `keep ;
               string "modulate" *> return `modulate ;
               string "synproxy" *> return `synproxy ;
             ] >>= fun predicate ->
       a_whitespace *> string "state" *>
       encapsulated_opt None '(' ')' (some a_state_opts) >>| fun state_opts ->
       State {predicate ; state_opts} ) ;
      string "fragment" *> (let()=Printf.eprintf "got a fragment\n%!"in return Fragment) ;
      string "no-df" *> return No_df ;
      ( string "min-ttl" *> a_whitespace *> a_number >>| fun n -> Min_ttl n ) ;
      string "set-tos" *> a_whitespace *> ( a_tos >>| fun tos -> Tos tos ) ;
      string "max-mss" *> a_whitespace *> ( a_number >>| fun n -> Max_mss n ) ;
      string "random-id" *> return Random_id;
      string "reassemble tcp" *> return Reassemble_tcp;
      (a_fragmentation >>| fun frag -> Fragmentation frag) ;
      string "allow-opts" *> return Allow_opts ;
      string "label" *> a_whitespace *> (a_string >>| fun lbl -> Label lbl ) ;
      string "tag" *> a_whitespace *> (a_string >>| fun tag -> Tag tag ) ;
      ( a_negated >>= fun negated ->
        string "tagged" *> a_whitespace *> a_string >>| fun tag ->
        Tagged (negated ,tag)) ;
      string "queue" *> a_whitespace *> ( a_match_or_list '(' a_string
                                          >>| fun entries -> Queue entries) ;
      ( string "rtable" *> a_whitespace *> a_number >>| fun num -> Rtable num) ;
      ( string "probability" *> a_whitespace *> a_number_range 0 100 <* char '%'
        >>| fun num -> Probability num) ;
    ]

type direction = Incoming | Outgoing | Both_directions
(*  in or out
    This rule applies to incoming or outgoing packets.  If neither in nor
    out are specified, the rule will match packets in both directions.*)

type pf_af = Inet | Inet6
let a_af : pf_af t =
  (string "inet" *> return Inet) <|> (string "inet6" *> return Inet6)

type pf_rule =
  { action : pf_action ;
    direction : direction ;
    logopts : pf_logopt list option ; (* "log" *)
    quick : bool ;
    ifspec : pf_ifspec option ; (* "on" *)
    route : pf_route option ;
    af : pf_af option ;
    protospec : pf_protospec option ;
    hosts : pf_hosts ;
    filteropts : pf_filteropt list ;
  }

let a_pf_rule : pf_rule t =
  a_action >>= fun action ->
  option Both_directions
    ( a_whitespace *>
      (string "in" *> return Incoming) <|> (string "out" *> return Outgoing)
    ) >>= fun direction ->
  option None (a_whitespace *> string "log" *>
               encapsulated_opt None '(' ')'(some(a_match_or_list '{' a_logopt))
              ) >>= fun logopts ->
  option false (a_whitespace *> string "quick" *> return true) >>= fun quick ->
  option None (a_whitespace *> string "on" *> some a_ifspec) >>= fun ifspec ->
  option None (a_whitespace *>
               some (string "fastroute" *> return Fastroute <|> a_route)
              ) >>= fun route ->
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (a_whitespace *> some a_protospec) >>= fun protospec ->
  let()=Printf.eprintf "past protospec\n%!"in
  a_whitespace *> a_hosts >>= fun hosts ->
  let()=Printf.eprintf "past hosts\n%!"in
  option [] (a_whitespace *> sep_by a_whitespace a_filteropt)
  >>| fun filteropts ->
  let()=Printf.eprintf "past filteropt\n%!"in
  { action ; direction; logopts ; quick ; ifspec ; route ; af ; protospec ;
    hosts ; filteropts}

module PF_set =
struct
  type debug_level = Debug_none | Debug_urgent | Debug_misc | Debug_loud
  type set_t = Debug of debug_level
             | Hostid of int (* TODO 32-bits *)
             | State_policy of string
             | Block_policy of string
  let a_set =
    a_ign_whitespace *> string "set" *>
    a_whitespace *>
    choice
      [ ( string "debug" *> a_whitespace *>
          choice [ string "none" *> return Debug_none ;
                   string "urgent" *> return Debug_urgent ;
                   string "misc" *> return Debug_misc ;
                   string "loud" *> return Debug_loud ;
                 ] >>| fun lvl -> Debug lvl ) ;
        ( string "hostid" *> a_whitespace *> a_number >>| fun n -> Hostid n );
        ( string "state-policy" *> a_whitespace *>
          ( string "if-bound" <|> string "floating")
          >>| fun x -> State_policy x
        ) ;
        ( string "block-policy" *> a_whitespace *>
          (string "drop" <|> string "return")
          >>| fun pol -> Block_policy pol) ;
      ]
end

type pf_portspec =
  pf_name_or_number * [`any | `port of pf_name_or_number ] option

let a_portspec : pf_portspec t =
  (*see a_port for note about known_tcp_service: *)
  let a_raw_port_number =
    a_name_or_number ~candidates:(Some Uri_services_full.known_tcp_services)
  in
  string "port" *> a_whitespace *>
  a_raw_port_number >>= fun start ->
  option None ( a_ign_whitespace *> char ':' *> a_ign_whitespace *>
                some ( (char '*' *> return `any)
                       <|> (a_raw_port_number >>| fun p -> `port p))
              ) >>| fun finish -> (start , finish)


type pf_rdr_rule =
  { no : bool ;
    pass: pf_logopt list option option ; (*pass:Some (log:Some logopts )*)
    on : pf_ifspec option ;
    af : pf_af option ;
    proto : pf_protospec option ;
    hosts : pf_hosts ;
    tag : string option ;
    tagged : string option ;
    redirhosts : (if_or_cidr list  *
                 pf_portspec option * pf_pooltype option) option ;
  }

let a_rdr_rule : pf_rdr_rule t =
    let()=Printf.eprintf "parsing rdr\n%!" in
  option false (a_ign_whitespace *> string "no" *> return true <* a_whitespace)
  >>= fun no ->
    let()=Printf.eprintf "past no\n%!" in
  a_ign_whitespace *> string "rdr" *>
  option None ( a_whitespace *> string "pass" *>
                option None ( a_whitespace *> string "log" *>
                              some (a_match_or_list '(' a_logopt)
                            ) >>| fun log ->
                Some log
              ) >>= fun pass ->
  let()=Printf.eprintf "past pass\n%!" in
  option None ( a_whitespace *> string "on" *> a_whitespace *>
                some a_ifspec ) >>= fun on ->
  let()=Printf.eprintf "past on\n%!" in
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (a_whitespace *> some a_protospec) >>= fun proto ->
  a_whitespace *> a_hosts >>= fun hosts ->
  let()=Printf.eprintf "past HOSTS\n%!" in
  option None (a_whitespace *> string "tag" *> some a_string) >>= fun tag ->
  let()=Printf.eprintf "past opt tag\n%!" in
  option None ( a_whitespace *> string "tagged" *>
                some a_string) >>= fun tagged ->
  option None ( a_whitespace *> string "->" *> a_ign_whitespace *>
                a_match_or_list '{' a_redirhost >>= fun redirhosts ->
                option None (a_whitespace *> some a_portspec)>>= fun portspec ->
                let()=Printf.eprintf "past opt portspec\n%!" in
                option None (a_whitespace *> some a_pooltype)>>| fun pooltype ->
                Some (redirhosts, portspec, pooltype)
              ) >>= fun redirhosts ->
  take_till (fun _ -> false ) >>| fun yo ->
  let()=Printf.eprintf "past opt pooltype, returning %S\n%!" yo in
  {no ; pass ; on ; af; proto ; hosts ; tag; tagged ; redirhosts }

type pf_macro_definition = {name : string; definition : string ; }

let a_macro_definition : pf_macro_definition t =
  (* TODO we don't handle macro expansion inside macro definitions yet *)
  a_ign_whitespace *>
  a_name_or_macro ~candidates:None >>= function
  | String name ->
    a_ign_whitespace *> char '=' *> a_ign_whitespace *>
    a_string >>| fun definition ->
    { name ; definition }
  | Macro _ -> fail "macro definition: name should not be prefixed with $-sign"

type line = Include of string
          | Macro_definition of pf_macro_definition
          | Pf_rule of pf_rule
          | Rdr_rule of pf_rdr_rule
          | Set of PF_set.set_t
let a_line =
  (* option | pf-rule | nat-rule | binat-rule | rdr-rule |
     antispoof-rule | altq-rule | queue-rule | trans-anchors |
     anchor-rule | anchor-close | load-anchor | table-rule |
     include *)
  a_ign_whitespace *>
  Angstrom.choice
    [ (a_include >>| fun filename -> Include filename) ;
      (a_macro_definition >>| fun macro -> Macro_definition macro) ;
      (a_rdr_rule >>| fun rule -> Rdr_rule rule) ;
      (a_pf_rule >>| fun rule -> Pf_rule rule) ;
      (PF_set.a_set >>| fun set -> Set set) ;
    ]
  <* a_ign_whitespace <* end_of_input (* make sure we parsed it all *)

let into_lines config_str =
  let a_line_split =
    fix (fun a_unescaped ->
        take_while (function '\n'|'\\' -> false | _ -> true) >>= fun s ->
        choice
          [ (string "\\\n" *> ((^) (s^" ") <$> a_unescaped));
            (end_of_line <|> end_of_input) *> return s ;
          ]
      )
  in
  config_str |> parse_string
  @@ fix (fun recurse ->
      a_ign_whitespace *> a_line_split <* a_ign_whitespace >>= fun line ->
      commit *>
      match parse_string a_line line with
      | Error msg -> fail ("failed to parse a line: " ^ msg ^": " ^ line)
      | Ok parsed_line ->
        (     (a_ign_whitespace *> end_of_input *> return [parsed_line])
              <|> (recurse >>| fun lst -> (List.cons parsed_line lst))
        )
    )
