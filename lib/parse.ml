open Angstrom

let a_comment : unit t = (char '#' *> available >>= advance) (* eat the rest *)

let a_negated : bool t = option false (char '!' *> return true)

let is_whitespace = function ' ' | '\t' -> true | _ -> false
let is_quote = function '"' -> true | _ -> false
let not_whitespace c = not (is_whitespace c)

let a_whitespace_unit : unit t =
  a_comment <|> (* TODO have to hook for comments somewhere *)
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
  skip_many1 ( (a_ign_whitespace *> char ',' *> a_ign_whitespace)
              <|> a_whitespace)

let a_match_or_list sep predicate =
  (* will ignore whitespace for {}, will mandate before predicate *)
  let left, right = match sep with
    | '{' -> '{', '}'
    | '(' -> '(', ')'
    | '<' -> '<', '>'
    | _ -> failwith (Fmt.strf "Invalid match_or_list char: %C" sep)
  in
  (encapsulated left right (sep_by a_optional_comma predicate))
  <|> (a_ign_whitespace *> predicate >>| fun p -> [p])

let a_number =
  take_while1 (function '0'..'9' -> true | _ -> false) >>= fun str ->
  match int_of_string str with
  | i -> return i
  | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_number_range min' max' =
  a_number >>= function | n when n <= max' && min' <= n -> return n
                        | n -> fail (Fmt.strf "Number out of range: %d" n)

let a_unquoted_string =
  (peek_char_fail >>= function
    | 'a'..'z' -> return ()
    | _ -> fail "unquoted strings must start with [a-z]"
  ) *>
  take_while (function | 'a'..'z' | '_' | '0'..'9' | 'A'..'Z' -> true
                       | _ -> false )

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

type pf_bandwidth_spec =
  | B of int
  | Kb of int
  | Mb of int
  | Gb of int
  | Percentage of int

let a_bandwidth_spec : pf_bandwidth_spec t =
  ( a_number >>= fun n ->
    a_ign_whitespace *>
    choice [ string "b" *> return (B n) ;
             string "Kb" *> return (Kb n) ;
             string "Mb" *> return (Mb n) ;
             string "Gb" *> return (Gb n) ;
           ]
  ) <|> ( a_number_range 0 100 <* a_ign_whitespace <* string "%"
          >>| fun n -> (Percentage n))

type pf_name_or_macro = String of string
                      | Macro of string

let pp_pf_name_or_macro fmt = function
  | String str -> Fmt.pf fmt "%S" str
  | Macro str  -> Fmt.pf fmt "$%s" str

let a_name_or_macro ~candidates : pf_name_or_macro t =
  a_ign_whitespace *>
  (peek_char_fail >>= function
    | '$' -> char '$' *> return true
    | 'a'..'z' -> return false
    | _ -> fail "name must start with [a-z]"
  ) >>= fun is_macro ->
  a_unquoted_string >>= fun str ->
  match is_macro, candidates with
  | true , _ -> return (Macro str)
  | false , None -> return (String str)
  | false , Some valid when List.mem str valid -> return @@ String str
  | false , Some valid -> fail (Fmt.strf "name %S must be one of %a" str
                                  Fmt.(list ~sep:(unit ", ") string) valid )

let a_interface_name = a_name_or_macro ~candidates:None

let pp_negation fmt = function
  | true -> Fmt.pf fmt "NOT "
  | false -> Fmt.pf fmt ""

type pf_ifspec = If_list of (bool * pf_name_or_macro) list
(* negated, name or macro*)

let pp_pf_ifspec fmt = function
  | If_list lst -> (*TODO this bool is a negation, should print "NOT" *)
    Fmt.pf fmt "%a" Fmt.(list ~sep:(unit ", ")
                         @@ pair ~sep:(unit "") pp_negation pp_pf_name_or_macro
                        ) lst

let a_ifspec : pf_ifspec t =
  a_match_or_list '{'
    ( a_negated >>= fun neg ->
      a_ign_whitespace *>
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
  string "flags" *> a_whitespace >>= fun () ->
  (string "any" *> return Flags_any)
  <|>
  ( sep_by a_ign_whitespace a_flag >>| flag_map >>= fun fst ->
    a_ign_whitespace *> char '/' *> a_ign_whitespace *>
    sep_by1 a_ign_whitespace a_flag >>| flag_map >>| fun snd ->
    Flag_set (fst,snd))

type pf_fragmentation = | Reassemble
                        | Crop
                        | Drop_ovl

let pp_pf_fragmentation fmt = function
  | Reassemble -> Fmt.pf fmt "reassemble"
  | Crop -> Fmt.pf fmt "crop"
  | Drop_ovl -> Fmt.pf fmt "drop-ovl"

let a_fragmentation : pf_fragmentation t =
  string "fragment" *> a_whitespace *>
  choice [ string "reassemble" *> return Reassemble ;
           string "crop" *> return Crop ;
           string "drop-ovl" *> return Drop_ovl ]

type pf_address = | IP of Ipaddr.t
                  | Dynamic_addr of pf_name_or_macro
                  | Fixed_addr of pf_name_or_macro

let pp_pf_address fmt = function
  | IP v -> Ipaddr.pp_hum fmt v
  | Dynamic_addr addr -> Fmt.pf fmt "(%a)" pp_pf_name_or_macro addr
  | Fixed_addr addr -> Fmt.pf fmt "%a" pp_pf_name_or_macro addr

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

let a_mask_bits = a_number_range 0 128

type pf_name_or_number = | Name of pf_name_or_macro
                         | Number of int

let pp_pf_name_or_number fmt = function
  | Name x -> Fmt.pf fmt "%a" pp_pf_name_or_macro x
  | Number x -> Fmt.pf fmt "%d" x

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

let pp_pf_unary_op fmt v =
  Fmt.pf fmt "%a" Fmt.(pair string pp_pf_name_or_number)
  @@ match v with
  | Unary_eq     n -> "= " , n
  | Unary_not_eq n -> "!= ", n
  | Unary_lt     n -> "< " , n
  | Unary_lt_eq  n -> "<= ", n
  | Unary_gt     n -> "> " , n
  | Unary_gt_eq  n -> ">= ", n

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
  | Range_except    of int * int (* 1<>4 -> 0,5,6 [, ..] *)

let pp_pf_binary_op fmt = function
  | Range_inclusive (a,b) -> Fmt.pf fmt "%d:%d" a b
  | Range_exclusive (a,b) -> Fmt.pf fmt "%d><%d" a b
  | Range_except (a,b) -> Fmt.pf fmt "%d<>%d" a b

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

let pp_pf_op fmt = function
  | Binary op -> Fmt.pf fmt "@[%a@]" pp_pf_binary_op op
  | Unary op -> Fmt.pf fmt "@[%a@]" pp_pf_unary_op op

let a_op ~candidates : pf_op t =
  (a_binary_op >>| fun op -> Binary op)
  <|> (a_unary_op ~candidates >>| fun op -> Unary op)

type pf_port = pf_op list

let a_port : pf_port t =
  string "port" *>
  a_match_or_list '{'
    ( a_op ~candidates:(Some Constants.iana_services))
  (* Note that we use the IANA policy (like FreeBSD) of not caring
       whether it is a UDP or TCP service, as opposed to what Debian
        puts in /etc/services, where they for example
        do not have 80/udp assigned to "http".
      TL;DR: Don't pay attention to the use of "known_*TCP*_services" above. *)

type if_or_cidr = | Dynamic_if of pf_name_or_macro
                  | Fixed_if of pf_name_or_macro
                  | CIDR of Ipaddr.Prefix.t

let pp_if_or_cidr fmt (w: if_or_cidr) =
  match w with
  | Dynamic_if v -> Fmt.pf fmt "(Dynamic_if %a)" pp_pf_name_or_macro v
  | Fixed_if   v -> Fmt.pf fmt "(Fixed_if %a)" pp_pf_name_or_macro v
  | CIDR       v -> Fmt.pf fmt "(CIDR %a)" Ipaddr.Prefix.pp_hum v

let a_if_or_cidr : if_or_cidr t =
  let expand_ipv4 prefix =
    let provided_octets = List.length (String.split_on_char '.' prefix) in
    let padding = String.init ((4 - provided_octets)*2)
        (function | i when i mod 2 = 0 -> '.'
                  | _ -> '0')
    in prefix ^ padding
  in
  ((a_address)
   <|> ( take_while1 ( function | '0'..'9' | '.'-> true
                               | _ -> false
     ) >>| expand_ipv4 >>| Ipaddr.V4.of_string >>= function
       | Some x -> return (IP (Ipaddr.V4 x))
       | None -> fail "invalid short ipv4 CIDR"
     )
  ) >>= begin function
  | (Dynamic_addr x) -> return @@ `pass (Dynamic_if x)
  | (Fixed_addr x) ->   return @@ `pass (Fixed_if x)
  | IP ((Ipaddr.V4 _) as ip) -> return (`ip ("/32", ip))
  | IP ((Ipaddr.V6 _) as ip) -> return (`ip ("/128",ip))
  end >>= function
  | `pass ret -> return ret
  | `ip (default_cidr, ip) ->
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
          CIDR Ipaddr.( (to_string ip) ^ default_cidr
                        |> Prefix.of_string_exn ) |> return
      )

let a_redirhost = a_if_or_cidr

type pf_host =
  | Table_name of bool * string (* negated, name *)
  | Host_addr of { negated : bool ;
                   if_or_cidr : if_or_cidr ; }

let pp_pf_host fmt = function
  | Table_name (neg, name) ->
    Fmt.pf fmt "%a%s" pp_negation neg name
  | Host_addr {negated; if_or_cidr } ->
    Fmt.pf fmt "%a%a" pp_negation negated pp_if_or_cidr if_or_cidr

let a_host : pf_host t =
  (* [ "!" ] ( address [ "/" mask-bits ] | "<" string ">" )
     string == table name *)
  a_negated >>= fun negated ->
  a_ign_whitespace >>= fun () ->
  (    a_if_or_cidr >>| fun if_or_cidr ->
       Host_addr {negated; if_or_cidr}
  ) <|> ( encapsulated '<' '>' a_unquoted_string >>| fun table ->
          Table_name (negated, table))

let a_host_list : pf_host list t = sep_by a_optional_comma a_host

type pf_hosts =
  | All_hosts
  | From_to of {from_host : [`any | `no_route | `urpf_failed | `self
                            | `hosts of pf_host list ] ;
                from_port : pf_port ;
                from_os : string list ;
                to_host : [`any | `no_route | `self | `hosts of pf_host list ] ;
                to_port : pf_port ;
               }

let pp_pf_hosts fmt v =
  let pp_host fmt = function
    | `any -> Fmt.pf fmt "any"
    | `no_route -> Fmt.pf fmt "no-route"
    | `urpf_failed -> Fmt.pf fmt "urpf-failed"
    | `self -> Fmt.pf fmt "self"
    | `hosts x -> Fmt.pf fmt "%a" Fmt.(list pp_pf_host) x
  in
  match v with
  | All_hosts -> Fmt.pf fmt "(all hosts)"
  | From_to { from_host ; from_port ; from_os ;
              to_host ; to_port } -> (*TODO*)
    Fmt.pf fmt "@[<v>from hosts: @[<v>%a@]@ from ports: @[<v>%a@]@ \
                     from os: [@[<v>%a@]]@ to hosts: @[<v>%a@]@ \
                     to ports: @[<v>%a@]@]"
      pp_host from_host
      Fmt.(list pp_pf_op) from_port
      Fmt.(list ~sep:(unit ",@ ") string) from_os
      pp_host to_host
      Fmt.(list pp_pf_op) to_port

let a_os =
  string "os" *>
  sep_by1 a_optional_comma (a_string <|> a_ign_whitespace *> a_unquoted_string)

let a_fail_if_string needle (appendix: char -> bool) =
  (* fails if the input contains the string [needle] follow by [appendix]*)
  let len = String.length needle in
  available >>= fun avail ->
  if avail <= len then return ()
  else begin
  peek_string (1 + len) >>= function
  | hay when String.sub hay 0 len = needle && appendix hay.[len] ->
    fail "a_fail_if_string"
  | _ -> return () end

let a_hosts : pf_hosts t =
  (string "all" *> return All_hosts)
  <|>
  ( option All_hosts
      (
        let a_common_host =
          choice [
            string "any" *> return `any ;
            string "no-route" *> return `no_route ;
            string "self" *> return `self ;
            (a_match_or_list '{' a_host >>| fun h -> `hosts h);
          ]
        in
        option (return(), `any, [], [])
          ( string "from" *>
            option `any
              ( a_whitespace *> a_fail_if_string "port" is_whitespace *>
                choice [
                  a_common_host ;
                  string "urpf-failed" *> return `urpf_failed ;
                ]
              ) >>= fun host ->
            option [] (a_whitespace *> a_port) >>= fun port ->
            option [] (a_whitespace *> a_os) >>| fun os ->
            (a_whitespace, host, port, os)
          ) >>= fun (ws, from_host, from_port, from_os) ->
        option (`any, [])
          ( ws *> string "to" *>
            option `any
              ( a_whitespace *> a_fail_if_string "port" is_whitespace *>
                a_common_host >>| fun host -> host
              ) >>= fun host ->
            option [] (a_whitespace *> a_port) >>| fun port ->
            host, port
          ) >>| fun (to_host, to_port) ->
        From_to {from_host ; from_port; from_os ; to_host ; to_port }
      )
  )

type pf_return =
  | Drop
  | Return
  | Return_rst  of int option (* ttl *)
  | Return_icmp of int option * int option (* v4 code , v6 code *)
  | Return_icmp6 of int option

let pp_pf_return fmt = function
  | Drop -> Fmt.pf fmt "drop"
  | Return -> Fmt.pf fmt "return"
  | Return_rst ttl -> Fmt.pf fmt "return-rst(%a)" Fmt.(option int) ttl
  | Return_icmp (v4, v6) -> Fmt.pf fmt "return-icmp(IPv4:%a, IPv6:%a)"
                              Fmt.(option int) v4
                              Fmt.(option int) v6
  | Return_icmp6 code -> Fmt.pf fmt "return-icmp6(%a)" Fmt.(option int) code

let a_return : pf_return t = (* "block" options *)
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

type pf_action = | Pass | Block of pf_return option
                 | Scrub of bool (* false: "no scrub" / true: "scrub" *)

let pp_pf_action fmt = function
  | Pass -> Fmt.pf fmt "(Pass)"
  | Block retopt -> Fmt.pf fmt "(Block, policy: %a)"
                      Fmt.(option ~none:(unit "Default") pp_pf_return)
                      retopt
  | Scrub false -> Fmt.pf fmt "(No-Scrub)"
  | Scrub true -> Fmt.pf fmt "(Scrub)"

let a_action : pf_action t =
  (* "pass" | "block" [ return ] | [ "no" ] "scrub" *)
  choice [ string "pass" *> return Pass ;
           ( string "block" *>
             option None (a_whitespace *> some a_return) >>| fun ret ->
             Block ret);
           ( option true (string "no" *> return true <* a_whitespace
                         ) >>= fun no ->
             string "scrub" *> return (Scrub no) ) ;
         ]

let a_proto_name =
  let names, _ = List.split Constants.iana_protocols in
  a_name_or_macro ~candidates:(Some names)

let a_proto_number =
  let _, proto_num = List.split Constants.iana_protocols in
  choice (List.map (fun i -> string @@ string_of_int i) proto_num)

let a_proto_name_or_number : pf_name_or_number t =
  (* like a_name_or_number, but whitelist against [iana_protocols] *)
  (a_proto_name >>| fun name -> Name name)
  <|> (a_proto_number >>| fun number -> Number (int_of_string number))

type pf_protospec = Proto_list of pf_name_or_number list

let pp_pf_protospec fmt = function
    Proto_list lst -> Fmt.pf fmt "[%a]" Fmt.(list ~sep:(unit ",@ ")
                                             pp_pf_name_or_number) lst

let a_protospec : pf_protospec t =
  (* "proto" ( proto-name | proto-number |
               "{" proto-list "}" ) *)
  string "proto" *>
  a_match_or_list '{' a_proto_name_or_number >>| fun lst -> Proto_list lst

type pf_logopt = | All
                 | User
                 | To of pf_name_or_macro

let pp_pf_logopt fmt = function
  | All -> Fmt.pf fmt "all"
  | User -> Fmt.pf fmt "user"
  | To pfnm -> Fmt.pf fmt "To: %a" pp_pf_name_or_macro pfnm

let pp_pf_logopts = Fmt.list pp_pf_logopt

let a_logopt : pf_logopt t =
  choice [ string "all" *> return All ;
           string "user" *> return User ;
           ( string "to" *> a_interface_name >>| fun to_if -> To to_if) ]

type pf_routehost = pf_name_or_macro * (pf_address * int option) option
(* why pf doesn't use pf_host here (allowing negation) is beyond me...
   block from $ext ! 1.2.3.4/32
   seems pretty useful to me
*)

let pp_pf_routehost fmt (ifn, addrs) =
  Fmt.pf fmt "if: %a %a" pp_pf_name_or_macro ifn
    Fmt.(option @@ pair pp_pf_address (option int)) addrs

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

type pf_pooltype =
  | Bitmask
  | Random
  | Source_hash
  | Round_robin

let pp_pf_pooltype fmt = function
  | Bitmask -> Fmt.pf fmt "Bitmask"
  | Random -> Fmt.pf fmt "Random"
  | Source_hash -> Fmt.pf fmt "Source hash"
  | Round_robin -> Fmt.pf fmt "Round robin"

let a_pooltype : pf_pooltype t =
  choice (*TODO*)
    [ string "bitmask" *> return Bitmask ;
      string "random" *> return Random ;
      string "source-hash" *> return Source_hash ;
      string "round-robin" *> return Round_robin ;
    ]

type pf_route =
  | Fastroute
  | Route of
      { verb : [`route_to | `reply_to | `dup_to ] ;
        routehosts : pf_routehost list ;
        pooltype : pf_pooltype option ;
      }

let pp_pf_route fmt = function
  | Fastroute ->  Fmt.pf fmt "Fastroute"
  | Route {verb ; routehosts; pooltype} ->
    Fmt.pf fmt "Route @[<v>{ %s@ routehost: %a@ pooltype: %a}@]"
      (match verb with |  `route_to -> "route-to"
                       | `reply_to -> "reply-to"
                       | `dup_to -> "dup-to")
      Fmt.(list pp_pf_routehost) routehosts
      Fmt.(option pp_pf_pooltype) pooltype

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

let pp_pf_icmp_type_code fmt {icmp_type; icmp_code} =
  Fmt.pf fmt "icmp type: %a code: %a" pp_pf_name_or_number icmp_type
    Fmt.(option ~none:(unit "Default") pp_pf_name_or_number) icmp_code

let a_icmp_type_code : pf_icmp_type_code t =
  (* ( icmp-type-name | icmp-type-number )
     [ "code" ( icmp-code-name | icmp-code-number ) ] *)
  let icmp_type_names = Some (List.map fst Constants.iana_icmp_types) in
  let icmp_code_names = Some (List.map fst Constants.iana_icmp_codes) in
  (* TODO I guess we should also validate the numbers... *)
  a_name_or_number ~candidates:icmp_type_names >>= fun icmp_type ->
  option None ( a_whitespace *> string "code" *> a_whitespace *>
                some (a_name_or_number ~candidates:icmp_code_names)
              ) >>| fun icmp_code ->
  { icmp_type ; icmp_code }

type pf_icmp_type = Icmp_type of pf_icmp_type_code list

let pp_pf_icmp_type fmt = function
  | Icmp_type lst -> Fmt.pf fmt "ICMP %a" Fmt.(list pp_pf_icmp_type_code) lst
let a_icmp_type : pf_icmp_type t =
  (* "icmp-type" ( icmp-type-code | "{" icmp-list "}" ) *)
  string "icmp-type" *>
  a_match_or_list '{' a_icmp_type_code >>| fun lst -> Icmp_type lst

type pf_icmp6_type = Icmp6_type of pf_icmp_type_code list

let pp_pf_icmp6_type fmt = function
  | Icmp6_type lst -> Fmt.pf fmt "ICMPv6 %a" Fmt.(list pp_pf_icmp_type_code) lst

let a_icmp6_type : pf_icmp6_type t =
  (* "icmp6-type" ( icmp-type-code | "{" icmp-list "}" ) *)
  string "icmp6-type" *>
  a_match_or_list '{' a_icmp_type_code >>| fun lst -> Icmp6_type lst

type pf_tos = | Lowdelay
              | Throughput
              | Reliability
              | Tos_number of int

let a_tos : pf_tos t =
  choice [ string "lowdelay"    *> return Lowdelay ;
           string "throughput"  *> return Throughput ;
           string "reliability" *> return Reliability ;
           ( string "0x" *>
             take_while1 (function | 'a'..'f'|'A'..'F'|'0'..'9' -> true
                                   | _ -> false
               ) >>= fun hex -> match int_of_string ("0x" ^ hex) with
                                | i -> return (Tos_number i)
                                | exception _ -> fail "TOS: hex-decoding failed"
           ) ;
           a_number >>| fun i -> Tos_number i ;
         ]

let a_user =
  (* "user" ( unary-op | binary-op | "{" op-list "}" ) *)
  string "user" *> a_match_or_list '{' (a_op ~candidates:None)

let a_group =
  (* "group" ( unary-op | binary-op | "{" op-list "}" ) *)
  string "group" *> a_whitespace *> a_match_or_list '{' (a_op ~candidates:None)

type pf_timeout = string * int (* TODO *)

let a_timeout : pf_timeout t =
  choice (List.map string (* These lifted from `man pf.conf`: *)
            [ "tcp.first"   ; "tcp.opening" ; "tcp.established" ;
              "tcp.closing" ; "tcp.finwait" ; "tcp.closed" ;
              "udp.first" ; "udp.single" ; "udp.multiple" ;
              "icmp.first" ; "icmp.error" ;
              "other.first" ; "other.single" ; "other.multiple" ;
              "frag" ; "interval" ; "src.track" ;
              "adaptive.start" ; "adaptive.end"
            ]
         ) >>= fun qualifier ->
  a_whitespace *> a_number >>| fun time -> (qualifier, time)

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
  | Overload of {table: string ;
                 flush: [`global | `rule] option ;
                }
  | If_bound
  | Floating

let a_state_opt : pf_state_opt t =
  (* ( "max" number | "no-sync" | timeout | "sloppy" | "pflow" |
       "source-track" [ ( "rule" | "global" ) ] |
       "max-src-nodes" number | "max-src-states" number |
       "max-src-conn" number |
       "max-src-conn-rate" number "/" number |
       "overload" "<" string ">" [ "flush" (*["global"] TODO not in BNF *) ]
       | "if-bound" | "floating" ) *)
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
      string "overload" *>
      ( encapsulated '<' '>' a_unquoted_string >>= fun table ->
        option None (a_ign_whitespace *>
                      string "flush" *>
                      choice [ (a_whitespace *> string "global" *>
                                return (Some `global)) ;
                               return (Some `rule) ;]
                     ) >>| fun flush ->
        Overload {table ; flush } ) ;
      string "if-bound" *> return If_bound ;
      string "floating" *> return Floating ;
    ]

let a_state_opts = sep_by a_optional_comma a_state_opt

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

let pp_pf_filteropt fmt v =
  let sep = Fmt.unit ",@ " in
  match v with
  | Filteropt_users  ops ->
    Fmt.pf fmt "users: @[%a@]" Fmt.(list ~sep pp_pf_op) ops
  | Filteropt_groups ops ->
    Fmt.pf fmt "groups: @[%a@]" Fmt.(list ~sep pp_pf_op) ops
  | Flags _ -> Fmt.pf fmt "TODO-pp_pf_flags"
  | Filteropt_icmp_type icmp -> Fmt.pf fmt "%a" pp_pf_icmp_type icmp
  | Filteropt_icmp6_type icmp6 -> Fmt.pf fmt "%a" pp_pf_icmp6_type icmp6
  | Tos _ -> Fmt.pf fmt "tos"
  | State _ -> Fmt.pf fmt "TODO-pp_pf_state"
  | Fragment -> Fmt.pf fmt "fragment"
  | Allow_opts -> Fmt.pf fmt "allow-opts"
  | Fragmentation frag -> Fmt.pf fmt "%a" pp_pf_fragmentation frag
  | No_df -> Fmt.pf fmt "no-df"
  | Min_ttl n -> Fmt.pf fmt "min-ttl: %d" n
  | Max_mss n -> Fmt.pf fmt "max-mss: %d" n
  | Random_id -> Fmt.pf fmt "random-id"
  | Reassemble_tcp -> Fmt.pf fmt "reassemble-tcp"
  | Label str -> Fmt.pf fmt "(Label: %s)" str
  | Tag str -> Fmt.pf fmt "tag-%a" Fmt.(quote string) str
  | Tagged (neg, s) -> Fmt.pf fmt "%a%s" pp_negation neg s
  | Queue qlst -> Fmt.pf fmt "%a" Fmt.(list string) qlst
  | Rtable n -> Fmt.pf fmt "rtable: %d" n
  | Probability n -> Fmt.pf fmt "probability: %d%%" n

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
      (a_fragmentation >>| fun frag -> Fragmentation frag) ;
      string "fragment" *> return Fragment ;
      string "no-df" *> return No_df ;
      ( string "min-ttl" *> a_whitespace *> a_number >>| fun n -> Min_ttl n ) ;
      string "set-tos" *> a_whitespace *> ( a_tos >>| fun tos -> Tos tos ) ;
      string "max-mss" *> a_whitespace *> ( a_number >>| fun n -> Max_mss n ) ;
      string "random-id" *> return Random_id;
      string "reassemble tcp" *> return Reassemble_tcp;
      string "allow-opts" *> return Allow_opts ;
      string "label" *> a_whitespace *> (a_string >>| fun lbl -> Label lbl ) ;
      string "tag" *> a_whitespace *> (a_string >>| fun tag -> Tag tag ) ;
      ( a_negated >>= fun negated ->
        string "tagged" *> a_whitespace *> a_string >>| fun tag ->
        Tagged (negated ,tag)) ;
      string "queue" *>
      ( a_match_or_list '(' a_unquoted_string
        >>| fun entries -> Queue entries) ;
      ( string "rtable" *> a_whitespace *> a_number >>| fun num -> Rtable num) ;
      ( string "probability" *> a_whitespace *> a_number_range 0 100 <* char '%'
        >>| fun num -> Probability num) ;
    ]

type direction = Incoming | Outgoing | Both_directions
(*  in or out
    This rule applies to incoming or outgoing packets.  If neither in nor
    out are specified, the rule will match packets in both directions.*)

let pp_direction fmt = function
  | Incoming -> Fmt.pf fmt "Incoming"
  | Outgoing -> Fmt.pf fmt "Outgoing"
  | Both_directions -> Fmt.pf fmt "Bidirectional"

type pf_af = Inet | Inet6

let pp_pf_af fmt = function
  | Inet -> Fmt.pf fmt "IPv4"
  | Inet6 -> Fmt.pf fmt "IPv6"

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

let pp_pf_rule fmt { action; direction; logopts; quick; ifspec;
                     route; af; protospec; hosts; filteropts } =
  let default = Fmt.unit "Default" in
  Fmt.pf fmt "@[<v>\
    { @[<v>\
      Action: %a@ \
      Traffic direction: %a@ \
      Log options: %a@ \
      Quick: %b@ \
      Interface: %a@ \
      Route: %a@ \
      Address family: %a@ \
      Protocol spec: %a@ \
      Hosts: %a@ \
      Filter options: @[<v>%a@]@,
    @] }@]"
    pp_pf_action action
    pp_direction direction
    Fmt.(option ~none:default pp_pf_logopts) logopts
    quick
    Fmt.(option ~none:default pp_pf_ifspec) ifspec
    Fmt.(option ~none:default pp_pf_route) route
    Fmt.(option ~none:default pp_pf_af) af
    Fmt.(option ~none:default pp_pf_protospec) protospec
    pp_pf_hosts hosts
    Fmt.(list pp_pf_filteropt) filteropts

let a_pf_rule : pf_rule t =
  a_action >>= fun action ->
  option Both_directions
    ( a_whitespace >>= fun () ->
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
  option All_hosts (a_whitespace *> a_hosts) >>= fun hosts ->
  option [] (a_whitespace *> sep_by a_whitespace a_filteropt)
  >>| fun filteropts ->
  { action ; direction; logopts ; quick ; ifspec ; route ; af ; protospec ;
    hosts ; filteropts}

module PF_set =
struct
  type debug_level = Debug_none | Debug_urgent | Debug_misc | Debug_loud
  type set_t = Debug of debug_level
             | Hostid of int (* TODO 32-bits *)
             | State_policy of string
             | Block_policy of string
             | Skip_on of pf_name_or_macro
             | Timeout of pf_timeout list
             | Limit of (string * int) list
             | Loginterface of pf_name_or_macro option
             | Optimization of string (*TODO*)
             | State_defaults of pf_state_opt list
             | Fingerprints of string (* filename *)

  let a_limit_item =
    choice [ string "states" ;
             string "frags" ;
             string "tables" ; (* TODO this is not documented in `man pf.conf`*)
             string "table-entries" ; (* TODO same *)
             string "src-nodes" ; ] >>= fun item ->
    a_whitespace *> a_number >>| fun num ->
    (item, num)

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
        ( string "skip" *> a_whitespace *> string "on" *>
          a_interface_name >>| fun ifn -> Skip_on ifn
        ) ;
        ( string "timeout" *> a_match_or_list '{' a_timeout
            >>| fun timeout -> Timeout timeout ) ;
        ( string "limit" *>
          a_match_or_list '{' a_limit_item >>| fun lmts -> Limit lmts ) ;
        ( string "loginterface" *> a_whitespace *>
          ( string "none" *> return None
            <|> some a_interface_name) >>| fun ifn -> Loginterface ifn) ;
        ( string "optimization" *> a_whitespace *>
          choice [ string "normal" ;
                   string "high-latency" ;
                   string "satellite" ;
                   string "aggressive" ;
                   string "conservative" ;
                 ] >>| fun optim -> Optimization optim
        ) ;
        ( string "state-defaults" *> a_whitespace *>
          a_state_opts >>| fun opts -> State_defaults opts
        ) ;
        ( string "fingerprints" *> a_whitespace *> a_string >>| fun str ->
          Fingerprints str) ;
      ]
end

type pf_portspec =
  pf_name_or_number * [`any | `port of pf_name_or_number ] option

let a_portspec : pf_portspec t =
  (*see a_port for note about known_tcp_service: *)
  let a_raw_port_number =
    a_name_or_number ~candidates:(Some Constants.iana_services)
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
  option false (a_ign_whitespace *> string "no" *> return true <* a_whitespace)
  >>= fun no ->
  a_ign_whitespace *> string "rdr" *>
  option None ( a_whitespace *> string "pass" *>
                option None ( a_whitespace *> string "log" *>
                              some (a_match_or_list '(' a_logopt)
                            ) >>| fun log ->
                Some log
              ) >>= fun pass ->
  option None ( a_whitespace *> string "on" *> some a_ifspec ) >>= fun on ->
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (a_whitespace *> some a_protospec) >>= fun proto ->
  a_whitespace *> a_hosts >>= fun hosts ->
  option None (a_whitespace *> string "tag" *> some a_string) >>= fun tag ->
  option None ( a_whitespace *> string "tagged" *>
                some a_string) >>= fun tagged ->
  option None ( a_whitespace *> string "->" *>
                a_match_or_list '{' a_redirhost >>= fun redirhosts ->
                option None (a_whitespace *> some a_portspec)>>= fun portspec ->
                option None (a_whitespace *> some a_pooltype)>>| fun pooltype ->
                Some (redirhosts, portspec, pooltype)
              ) >>| fun redirhosts ->
  {no ; pass ; on ; af; proto ; hosts ; tag; tagged ; redirhosts }

type nat_redirhosts =
  { targets : if_or_cidr list ;
    portspec : pf_portspec option ;
    pooltype : pf_pooltype option ;
    static_port : bool ;
  }

type pf_nat_rule =
  { no : bool ;
    pass : pf_logopt list option option ;
    on : pf_ifspec option ;
    af : pf_af option ;
    proto : pf_protospec option ;
    hosts : pf_hosts ;
    tag : string option ;
    tagged : string option ;
    redirhosts: nat_redirhosts option ;
  }

let a_nat_rule =
  (* TODO this is mostly code-cloned from a_rdr_rule *)
  option false (a_ign_whitespace *> string "no" *> return true <* a_whitespace)
  >>= fun no ->
  a_ign_whitespace *> string "nat" *>
    option None ( a_whitespace *> string "pass" *>
                option None ( a_whitespace *> string "log" *>
                              some (a_match_or_list '(' a_logopt)
                            ) >>| fun log ->
                Some log
                ) >>= fun pass ->
  option None ( a_whitespace *> string "on" *> some a_ifspec ) >>= fun on ->
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (a_whitespace *> some a_protospec) >>= fun proto ->
  a_whitespace *> a_hosts >>= fun hosts ->
  option None (a_whitespace *> string "tag" *> some a_string) >>= fun tag ->
  option None ( a_whitespace *> string "tagged" *>
                some a_string) >>= fun tagged ->
  option None ( a_whitespace *> string "->" *>
                a_match_or_list '{' a_redirhost >>= fun targets ->
                option None (a_whitespace *> some a_portspec)>>= fun portspec ->
                option None (a_whitespace *> some a_pooltype)>>= fun pooltype ->
                option false (a_whitespace *> string "static-port" *>
                              return true ) >>| fun static_port ->
                Some {targets; portspec ; pooltype ; static_port}
              ) >>| fun redirhosts ->
  {no ; pass; on; af; proto; hosts; tag; tagged; redirhosts}

type pf_macro_definition = { name : string ;
                             definition : pf_name_or_macro list ; }

let a_macro_definition : pf_macro_definition t =
  (* TODO we don't handle macro expansion inside macro definitions yet *)
  a_ign_whitespace *>
  a_name_or_macro ~candidates:None >>= function
  | String name ->
    a_ign_whitespace *> char '=' *>
    sep_by (a_whitespace) (    (a_string >>| fun str -> String str)
                            <|> a_name_or_macro ~candidates:None
                          ) >>| fun definition ->
   { name ; definition }
  | Macro _ -> fail "macro definition: name should not be prefixed with $-sign"

type pf_tableaddr =
  | Table_hostname of string
  | Table_if_or_cidr of if_or_cidr
  | Self

let a_tableaddr =
  choice [ string "self" *> return Self;
           (a_unquoted_string >>| fun host -> Table_hostname host) ; (*TODO*)
           (a_if_or_cidr >>| fun ifcidr -> Table_if_or_cidr ifcidr) ;
  ]

type pf_table_opts = | Persist
                     | Const
                     | Counters
                     | File of string
                     | Tableaddr of pf_tableaddr list

let a_table_opts =
  choice [ string "persist" *> return Persist ;
           string "const" *> return Const ;
           string "counters" *> return Counters ;
           string "file" *> a_whitespace *> (a_string >>| fun str -> File str) ;
           (a_match_or_list '{' a_tableaddr >>| fun lst -> Tableaddr lst ) ;
           (* TODO this should be a_tableaddr_spec, including negations
                   and bitmasks for CIDR notation. *)
         ]

type pf_table_rule = { name : string ;
                       table_opts : pf_table_opts list ; }

let a_table_rule : pf_table_rule t =
  string "table" *> encapsulated '<' '>' a_unquoted_string >>= fun name ->
  option [] (a_ign_whitespace *> sep_by a_optional_comma a_table_opts
              ) >>| fun table_opts ->
  {name ; table_opts }

type pf_sc =
  | Sc_bw_spec of pf_bandwidth_spec
  | Sc_TODO_spec of pf_bandwidth_spec * int * pf_bandwidth_spec

type pf_hfsc_def =
  | Hfsc_default
  | Hfsc_red
  | Hfsc_ecn
  | Hfsc_rio
  | Linkshare_sc of pf_sc
  | Realtime_sc of pf_sc
  | Upperlimit_sc of pf_sc

type pf_scheduler =
  | Cbq_def of (string * string option) option
  | Priq_def of (string * string option) option
  | Hfsc_def of (pf_hfsc_def * pf_hfsc_def option) option

let a_schedulers : pf_scheduler t =
  let a_one_or_two a_opt =
    option None (encapsulated '(' ')'
                   ( a_opt >>= fun fst ->
                     option None (a_optional_comma *> some a_opt
                                 ) >>| fun snd -> Some (fst,snd)
                   ))
  in
  let a_cbq_def =
    let a_cbq_opt =
      choice @@ List.map string ["default";"borrow";"red";"ecn";"rio"] in
    string "cbq" *> a_one_or_two a_cbq_opt >>| fun opts -> Cbq_def opts
  in
  let a_priq_def =
    let a_priq_opt =
      choice @@ List.map string ["default";"red";"ecn";"rio"] in
    string "priq" *> a_one_or_two a_priq_opt >>| fun opts -> Priq_def opts
  in
  let a_hfsc_def =
    let a_sc_spec =
      encapsulated '(' ')' ( a_bandwidth_spec >>= fun fst ->
                             a_whitespace *> a_number >>= fun snd ->
                             a_whitespace *> a_bandwidth_spec
                             <* a_ign_whitespace >>| fun thrd ->
                             Sc_TODO_spec (fst,snd,thrd)
                           )
      <|> (a_whitespace *> a_bandwidth_spec >>| fun sp -> Sc_bw_spec sp)
    in
    let a_hfsc_opt =
      choice [ string "default" *> return Hfsc_default ;
               string "red"     *> return Hfsc_red ;
               string "ecn"     *> return Hfsc_ecn ;
               string "rio"     *> return Hfsc_rio ;
               (string "linkshare" *> a_sc_spec >>| fun sc -> Linkshare_sc sc) ;
               (string "realtime" *> a_sc_spec >>| fun sc ->  Realtime_sc sc) ;
               (string "upperlimit" *> a_sc_spec >>| fun sc ->Upperlimit_sc sc);
             ]
    in
    string "hfsc" *> a_one_or_two a_hfsc_opt >>| fun opts -> Hfsc_def opts
  in
  choice [ a_cbq_def ; a_priq_def ; a_hfsc_def ]

type pf_queueopt =
  | Bandwidth of pf_bandwidth_spec
  | Qlimit of int
  | Tbrsize of int
  | Priority of int
  | Schedulers of pf_scheduler

let a_queueopt : pf_queueopt t =
  choice [ ( string "bandwidth" *> a_whitespace *> a_bandwidth_spec
             >>| fun bw -> Bandwidth bw);
           (string "qlimit" *> a_whitespace *> a_number >>| fun n -> Qlimit n) ;
           ( string "tbrsize" *> a_whitespace *> a_number >>| fun n ->
             Tbrsize n) ;
           ( string "priority" *> a_whitespace *> a_number >>| fun n ->
             Priority n) ;
           (a_schedulers >>| fun sc -> Schedulers sc);
  ]

type pf_queue_rule = { name : string ;
                       on : pf_name_or_macro option ;
                       queueopts : pf_queueopt list ;
                       subqueues : string list ;
                     }

let a_queue_rule =
  string "queue" *> a_whitespace *> a_unquoted_string >>= fun name ->
  option None (a_whitespace *> string "on" *> a_whitespace *>
               some a_interface_name ) >>= fun on ->
  a_whitespace *>
  sep_by a_whitespace a_queueopt >>= fun queueopts ->
  option [] (a_match_or_list '{' a_unquoted_string)  >>| fun subqueues ->
  { name ; on ; queueopts ; subqueues }

type line = Include of string
          | Macro_definition of pf_macro_definition
          | Pf_rule of pf_rule
          | Rdr_rule of pf_rdr_rule
          | NAT_rule of pf_nat_rule
          | Set of PF_set.set_t
          | Table_rule of pf_table_rule
          | Queue_rule of pf_queue_rule
          | Empty_line

let pp_line fmt = function
  | Include  str -> Fmt.pf fmt "include %S" str
  | Macro_definition { name; definition } ->
    Fmt.pf fmt "%s = %a" name
      Fmt.(list ~sep:(unit " ") pp_pf_name_or_macro) definition
  | Pf_rule rule -> Fmt.pf fmt "%a" pp_pf_rule rule
  | Empty_line -> Fmt.pf fmt ""
  | Rdr_rule _ -> Fmt.pf fmt "TODO sorry cannot pretty-print [rdr]"
  | NAT_rule _ -> Fmt.pf fmt "TODO sorry cannot pretty-print [NAT]"
  | Set _ -> Fmt.pf fmt "TODO sorry cannot pretty-print [set]"
  | Table_rule _ -> Fmt.pf fmt "TODO sorry cannot pretty-print [table]"
  | Queue_rule _ -> Fmt.pf fmt "TODO sorry cannot pretty-print [queue]"

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
      (a_nat_rule >>| fun rule -> NAT_rule rule) ;
      (a_queue_rule >>| fun rule -> Queue_rule rule) ;
      (PF_set.a_set >>| fun set -> Set set) ;
      (a_ign_whitespace *> end_of_input *> return Empty_line) ;
      (a_ign_whitespace *> a_table_rule >>| fun rule -> Table_rule rule) ;
    ]
  <* a_ign_whitespace <* end_of_input (* make sure we parsed it all *)

let into_lines config_str =
  let a_line_split =
    fix (fun a_unescaped ->
        take_while (function '\n'|'\\' -> false | _ -> true) >>= fun s ->
        choice
          [ (string "\\\n" *> ((^) (s^" ") <$> a_unescaped));
            ((char '\n' *> return ()) <|> end_of_input) *> return s ;
          ]
      )
  in
  (* we can't use a_ign_whitespace here because comments should not terminate
     the entire file: TODO: *)
  let a_ign_ws = skip_many (skip @@ function ' ' | '\t' -> true | _ -> false) in
  config_str |> parse_string
  @@ fix (fun recurse ->
      a_ign_ws *> a_line_split <* a_ign_ws >>= fun line ->
      commit *>
        begin match parse_string a_line line with
          | Error msg -> fail ("failed to parse a line: " ^ msg ^": " ^ line)
          | Ok parsed_line ->
            (a_ign_ws *> end_of_input *> return [parsed_line])
            <|>
            (List.cons parsed_line <$> recurse)
        end
    )
