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

type negation = Not | Yes
let a_negation = option Yes (char '!' *> return Not)

let is_whitespace = function ' ' | '\t' -> true | _ -> false
let is_quote = function '"' -> true | _ -> false
let not_whitespace c = not (is_whitespace c)

let a_whitespace_unit : unit t =
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let a_ign_whitespace = skip_many a_whitespace_unit

let a_whitespace = skip_many1 a_whitespace_unit

let encapsulated start fini body =
  a_ign_whitespace *> char start *> body <* char fini <* a_ign_whitespace

let encapsulated_opt default start fini body =
  a_ign_whitespace *> option default (encapsulated start fini body)
  <* a_ign_whitespace

let a_optional_comma =
  a_ign_whitespace *>
  skip (function ',' -> true | _ -> false) *>
  a_ign_whitespace

let a_match_or_list predicate =
  (encapsulated '{' '}' (sep_by a_optional_comma predicate))
  <|> (predicate >>| fun p -> [p])

let a_number =
  take_while1 (function '0'..'9' -> true | _ -> false) >>= fun str ->
  match int_of_string str with
  | i -> return i
  | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_string =
  choice [
    encapsulated '"' '"' (take_till is_quote)
     <?> "QUOTED STRING" ;
    take_while1 not_whitespace
  ]

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

let a_interface_name =
  a_ign_whitespace *>
  (peek_char_fail >>= function
    | 'a'..'z' as c -> return (String.make 1 c)
    | _ -> fail "interface name must start with [a-z]"
  ) >>= fun first_c ->
  take_till is_whitespace >>| fun tl ->
  (first_c ^ tl)

type pf_ifspec = If_list of (negation * string) list

let a_ifspec : pf_ifspec t =
  a_ign_whitespace *>
  a_match_or_list
    ( a_negation >>= fun neg ->
      a_interface_name >>| fun ifn -> (neg, ifn)
    ) >>| fun ifl -> If_list ifl

type flag_set = {f: bool; s: bool; r: bool; p: bool;
                 a: bool; u: bool; e: bool; w: bool}

let a_fragmentation =
  string "fragment" *> a_whitespace *>
  choice [string "reassemble" ; string "crop" ; string "drop-ovl"]

type pf_address = IPv4 of Ipaddr.V4.t
                | IPv6 of Ipaddr.V6.t
                | Dynamic_addr of string
                | Fixed_addr of string

let a_address =
  (* interface-name | interface-group |
     "(" ( interface-name | interface-group ) ")" |
     hostname | ipv4-dotted-quad | ipv6-coloned-hex *)
  choice [
    (encapsulated '(' ')' a_interface_name >>| fun name -> Dynamic_addr name);
    (a_ipv4_dotted_quad >>| fun ip -> IPv4 ip) ;
    (a_ipv6_coloned_hex >>| fun ip -> IPv6 ip) ;
    (a_interface_name >>| fun name -> Fixed_addr name);
    (* TODO handle difference between interface-name and interface-group*)
  ]

let some t = t >>| fun applied -> Some applied

let a_mask_bits = a_number >>=
  function | mask when mask <= 128 && 0 <= mask -> return mask
           | invalid_mask -> fail (Fmt.strf "Invalid mask: %d" invalid_mask)

type pf_host =
  | Table_name of negation * string
  | Host_addr of negation * pf_address * int option

let a_host : pf_host t =
  (* [ "!" ] ( address [ "/" mask-bits ] | "<" string ">" )
     string == table name *)
  a_negation >>= fun neg ->
  a_ign_whitespace *>
  (    (a_address >>= fun addr ->
        option None (a_ign_whitespace *> char '/' *>
                     some a_mask_bits
                    ) >>| fun mask_bits ->
        Host_addr (neg, addr, mask_bits))
   <|> (encapsulated '<' '>' a_string >>| fun table -> Table_name (neg,table)))

let a_host_list : pf_host list t =
  sep_by (a_optional_comma <|> a_whitespace) a_host

type pf_hosts =
  | All
  | From_to of {from_host : [`any | `no_route | `urpf_failed | `self
                            | `host of pf_host | `host_list of pf_host list ] ;
                from_port : int option ;
                from_os : string option ;
                to_host : [`any | `no_route | `self | `host of pf_host
                          | `host_list of pf_host list ] ;
                to_port : int option ;
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
    option None (a_whitespace *> some a_number) >>= fun from_port ->
    option None (a_whitespace *> some a_string) >>= fun from_os ->
    a_whitespace *> string "to" *> a_whitespace *>
    choice
      [ string "any" *> return `any ;
        string "no-route" *> return `no_route ;
        string "self" *> return `self ;
        (a_host >>| fun host -> `host host) ;
        (encapsulated '{' '}' a_host_list >>| fun lst -> `host_list lst);
      ] >>= fun to_host ->
    option None (a_whitespace *> some a_number) >>= fun to_port ->
    return @@ From_to {from_host ; from_port; from_os ; to_host ; to_port }
  )

type pf_return = Drop
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
  choice (List.map string names)

let a_proto_number =
  let _, proto_num = List.split iana_protocols in
  choice (List.map (fun i -> string @@ string_of_int i) proto_num)

type pf_name_or_number = | Name of string
                         | Number of int

let a_name_or_number : pf_name_or_number t =
  (a_number >>| fun n -> Number n) <|> (a_string >>| fun n -> Name n)

let a_proto_name_or_number : pf_name_or_number t =
  (* like a_name_or_number, but whitelist against [iana_protocols] *)
  (a_proto_name >>| fun name -> Name name)
  <|> (a_proto_number >>| fun number -> Number (int_of_string number))

type pf_protospec = Proto_list of pf_name_or_number list

let a_protospec : pf_protospec t =
  (* "proto" ( proto-name | proto-number |
               "{" proto-list "}" ) *)
  string "proto" *> a_whitespace *>
  a_match_or_list a_proto_name_or_number >>| fun lst -> Proto_list lst

type pf_logopt = | All
                 | User
                 | To of string

let a_logopt : pf_logopt t =
  choice [ string "all" *> return All ;
           string "user" *> return User ;
           ( string "to" *> a_interface_name >>| fun to_if -> To to_if) ]

let a_logopts : pf_logopt list t = a_match_or_list a_logopt

type pf_routehost = string * (pf_address * int option) option

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
  a_name_or_number >>= fun icmp_type ->
  option None (a_whitespace *> string "code" *> a_whitespace *>
               some a_name_or_number) >>| fun icmp_code ->
  { icmp_type ; icmp_code }

let a_icmp_list : pf_icmp_type_code list t = a_match_or_list a_icmp_type_code

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

type pf_unary_op = | Unary_eq of pf_name_or_number
                   | Unary_not_eq of pf_name_or_number
                   | Unary_lt of pf_name_or_number
                   | Unary_lt_eq of pf_name_or_number
                   | Unary_gt of pf_name_or_number
                   | Unary_gt_eq of pf_name_or_number

let a_unary_op : pf_unary_op t =
  let a_next = a_whitespace *> a_name_or_number in
  choice [ (char '=' *> a_next >>| fun n -> Unary_eq n);
           (char '<' *> a_next >>| fun n -> Unary_lt n);
           (char '>' *> a_next >>| fun n -> Unary_gt n);
           (string "!=" *> a_next >>| fun n -> Unary_not_eq n);
           (string "<=" *> a_next >>| fun n -> Unary_lt_eq n);
           (string ">=" *> a_next >>| fun n -> Unary_gt_eq n);
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
  a_number >>| fun snd ->
  match mode with
  | `incl -> Range_inclusive (fst, snd)
  | `excl -> Range_exclusive (fst, snd)
  | `except -> Range_except (fst, snd)

type pf_op = | Binary of pf_binary_op
             | Unary of pf_unary_op

let a_op : pf_op t =
  (a_binary_op >>| fun op -> Binary op)
  <|> (a_unary_op >>| fun op -> Unary op)

let a_user =
  (* "user" ( unary-op | binary-op | "{" op-list "}" ) *)
  string "user" *> a_match_or_list a_op

let a_group =
  (* "group" ( unary-op | binary-op | "{" op-list "}" ) *)
  string "group" *> a_match_or_list a_op

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
  | Filteropt_icmp_type of pf_icmp_type
  | Filteropt_icmp6_type of pf_icmp6_type
  | Tos of pf_tos
  | State of {predicate: [`no | `keep | `modulate | `synproxy ] ;
              state_opts : pf_state_opt list option }
  | Fragment
  | No_df
  | Min_ttl of int
  | Max_mss of int
  | Random_id
  | Reassemble_tcp
  | Label of string
  | Tag of string

let a_filteropt : pf_filteropt t =
  choice
    [ ( a_user >>| fun users -> Filteropt_users users ) ;
      ( a_group >>| fun groups -> Filteropt_groups groups ) ;
      a_flags ;
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
      string "fragment" *> return Fragment ;
      string "no-df" *> return No_df ;
      ( string "min-ttl" *> a_whitespace *> a_number >>| fun n -> Min_ttl n ) ;
      string "set-tos" *> a_whitespace *> ( a_tos >>| fun tos -> Tos tos ) ;
      string "max-mss" *> a_whitespace *> ( a_number >>| fun n -> Max_mss n ) ;
      string "random-id" *> return Random_id;
      string "reassemble tcp" *> return Reassemble_tcp;
      a_fragmentation ;
      string "allow-opts" ;
      string "label" *> a_whitespace *> (a_string >>| fun lbl -> Label lbl ) ;
      string "tag" *> a_whitespace *> (a_string >>| fun tag -> Tag tag ) ;
      ( option Not a_negate >>= fun neg ->
        string "tagged" *> a_whitespace *> a_string >>| fun tag ->
        (neg,tag)) ;
      string "queue" *> a_whitespace *>
      ( choice
          [ encapsulated '(' ')'
              ( a_string >>= fun fst ->
                option None ( skip (function "," -> true | _ -> false) *>
                              a_ign_whitespace *> a_string
                  )
              );
            a_string ;
          ]
      ) ;
      string "rtable" *> a_whitespace *> a_number ;
      string "probability" *> a_whitespace *> a_number <* char '%' ;
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
    filteropts : pf_filteropt list option ;
  }

let a_pf_rule : pf_rule t =
  a_action >>= fun action ->
  option Both_directions
    ( a_whitespace *>
      (string "in" *> return Incoming) <|> (string "out" *> return Outgoing)
    ) >>= fun direction ->
  option None (a_whitespace *> string "log" *>
               encapsulated_opt None '(' ')' (some a_logopts)
              ) >>= fun logopts ->
  option false (a_whitespace *> string "quick" *> return true) >>= fun quick ->
  option None (a_whitespace *> string "on" *> some a_ifspec)
  >>= fun ifspec ->
  option None (a_whitespace *>
               some (string "fastroute" *> return Fastroute <|> a_route)
              ) >>= fun route ->
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (some a_protospec) >>= fun protospec ->
  a_hosts >>= fun hosts ->
  option None (some a_filteropt_list) >>| fun filteropts ->
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

type line = Include of string
          | Pf_rule of string
          | Set of PF_set.set_t
let a_line =
  (* option | pf-rule | nat-rule | binat-rule | rdr-rule |
     antispoof-rule | altq-rule | queue-rule | trans-anchors |
     anchor-rule | anchor-close | load-anchor | table-rule |
     include *)
  Angstrom.choice
    [ (a_include >>| fun filename -> Include filename) ;
      (a_pf_rule >>| fun rule -> Pf_rule rule) ;
      (PF_set.a_set >>| fun set -> Set set) ;
    ]
  (* end_of_input *)

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
      a_line_split >>= fun line ->
      commit *>
      (     (end_of_input *> return [line])
        <|> (recurse >>| fun lst -> (List.cons line lst))
      )
    )
