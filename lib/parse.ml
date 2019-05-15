open Angstrom

let pp_iff_condition printer pp condition fmt data =
  match condition data with
  | Some data ->
    printer (Fmt.pf fmt) pp data
  | None -> ()

let pp_skip_empty printer pp =
  pp_iff_condition printer
    Fmt.(list ~sep:(unit",@ ") pp)
    (function [] -> None | x -> Some x)

let pp_skip_none printer pp =
  pp_iff_condition printer pp (fun x -> x)

let pp_skip_false printer =
  pp_iff_condition printer Fmt.bool
    (function true -> Some true | false -> None)

let a_comment : unit t = (char '#' *> available >>= advance) (* eat the rest *)

let a_negated : bool t = option false (char '!' *> return true)

let is_whitespace = function ' ' | '\t' -> true | _ -> false
let is_quote = function '"' -> true | _ -> false
let not_whitespace c = not (is_whitespace c)

let a_whitespace_unit : unit t =
  a_comment <|> (* TODO have to hook for comments somewhere *)
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let some t = t >>| fun applied -> Some applied

let a_ign_whitespace = skip_many a_whitespace_unit

let a_whitespace = skip_many1 a_whitespace_unit

let encapsulated start fini body =
  a_ign_whitespace *> char start *> a_ign_whitespace *>
  body
  <* a_ign_whitespace <* char fini

let encapsulated_opt default start fini body =
  option default (encapsulated start fini body)

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
  (* Lifted from https://github.com/freebsd/freebsd/blob/35326d3159b53afb3e64a9926a953b32e27852c9/sbin/pfctl/parse.y#L5823-L5827
     where they have this macro:
   #define allowed_in_string(x) \
     (isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
     x != '{' && x != '}' && x != '<' && x != '>' && \
     x != '!' && x != '=' && x != '/' && x != '#' && \
     x != ','))
     from the freebsd libc manpages we see that alnum() is [a-zA-Z0-9]
     and that ispunct() accepts:
     041 ``!''     042 ``"''     043 ``#''     044 ``$''     045 ``%''
     046 ``&''     047 ``'''     050 ``(''     051 ``)''     052 ``*''
     053 ``+''     054 ``,''     055 ``-''     056 ``.''     057 ``/''
     072 ``:''     073 ``;''     074 ``<''     075 ``=''     076 ``>''
     077 ``?''     100 ``@''     133 ``[''     134 ``\''     135 ``]''
     136 ``^''     137 ``_''     140 ```''     173 ``{''     174 ``|''
     175 ``}''     176 ``~''
    " $ % & ' * + - . : ; ? @ [ \ ] ^ _ ` | ~
*)
  (peek_char_fail >>= function
    | 'a'..'z' | 'A'..'Z' -> return ()
    | _ -> fail "unquoted strings must start with [a-zA-Z]"
  ) *>
  take_while (function | 'a'..'z' | '_' | '0'..'9' | 'A'..'Z'
                       | '-' (*TODO this is not valid in all contexts*) -> true
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

let a_fail_if_string (needles: string list) (appendix: char -> bool) =
  (* fails if the input contains the string [needle] follow by [appendix]*)
  let fail_if f b = if f b then fail "a_fail_if_string" else return () in
  if needles = [] then return () else
  List.fold_left
    ( fun acc needle ->
        acc >>= fun () ->
        let len = String.length needle in
        available >>= function
          | avail when avail < len  -> return () (*it cannot match*)
          | avail when avail > len ->
              peek_string (1+len) >>=
              fail_if (fun hay ->
                  String.sub hay 0 len = needle && appendix hay.[len])
          | _ -> peek_string len >>= fail_if ((=) needle)
    ) ( return () ) needles

let a_string_not stop_strings =
  (* handle unquoted strings, optionally blacklist [stop_strings] *)
  (a_string <|>
   a_fail_if_string stop_strings (is_whitespace) *> a_unquoted_string)

let a_include =
  (string "include"
   *> a_string
  ) <?> "INCLUDE"

let a_ipv4_dotted_quad =
  take_while1 (function '0'..'9' |'.' -> true | _ -> false) >>= fun ip ->
  match Ipaddr.V4.of_string ip with
    | Error `Msg x -> fail (Fmt.strf "Invalid IPv4: %S: %s" ip x)
    | Ok ip -> return ip

let a_ipv6_coloned_hex =
  take_while1 (function '0'..'9' | ':' | 'a'..'f' | 'A'..'F' -> true
                                 | _ -> false) >>= fun ip ->
  match Ipaddr.V6.of_string ip with
  | Error `Msg x -> fail (Fmt.strf "Invalid IPv6: %S: %s" ip x)
  | Ok ip -> return ip

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

let a_interface_name =
  a_name_or_macro ~candidates:None >>= fun ifn ->
  (* Interface names and interface group names can have modifiers appended:
     :network    Translates to the network(s) attached to the interface.
     :broadcast  Translates to the interface's broadcast address(es).
         :peer  Translates to the point-to-point interface's peer address(es).
         :0     Do not include interface aliases.*)
  option None (some @@ choice [ string ":network" *> return `network ;
                        string ":broadcast" *> return `broadcast ;
                        string ":peer" *> return `peer ;
                                string ":0" *> return `no_aliases ; ]
              ) >>| fun modfer -> ifn, modfer

let pp_negation fmt = function
  | true -> Fmt.pf fmt "NOT "
  | false -> Fmt.pf fmt ""

type pf_interface = (*TODO move modifier to a_host*)
  { negated : bool ;
    if_name : pf_name_or_macro ;
    modifier : [`network | `broadcast | `peer | `no_aliases ] option
  }
let pp_pf_interface fmt {negated ; if_name ; modifier } =
  Fmt.pf fmt "%a%a:%s" pp_negation negated
    pp_pf_name_or_macro if_name
    (match modifier with
     | None -> ""
     | Some `network -> "network"
     | Some `broadcast -> "broadcast"
     | Some `peer -> "peer"
     | Some `no_aliases -> ":0(no_aliases)")

type pf_ifspec = If_list of pf_interface list

let pp_pf_ifspec fmt = function
  | If_list lst ->
    Fmt.pf fmt "%a" Fmt.(list ~sep:(unit ", ") pp_pf_interface) lst

let a_ifspec : pf_ifspec t =
  a_match_or_list '{'
    ( a_negated >>= fun negated ->
      a_ign_whitespace *>
      a_interface_name >>| fun (if_name, modifier) ->
      {negated ; if_name ; modifier }
    ) >>| fun ifl -> If_list ifl

type pf_flag_set = {f: bool; s: bool; r: bool; p: bool;
                    a: bool; u: bool; e: bool; w: bool}

let string_of_flag_set v =
  [ "F", v.f ; "S", v.s ; "R", v.r ; "P", v.p ;
    "A", v.a ; "U", v.u ; "E", v.e ; "W", v.w ;
  ] |> List.filter snd |> List.split |> fst |> String.concat ""

type pf_flags =
  | Flags_any
  | Flag_set of pf_flag_set * pf_flag_set

let pp_pf_flags fmt = function
  | Flags_any -> Fmt.pf fmt "any"
  | Flag_set (set, not_set) ->
    Fmt.pf fmt "%s%s"
      (string_of_flag_set set)
      (match (string_of_flag_set not_set) with
       | "" -> ""
       | flags -> "/" ^ flags)

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
  | Reassemble -> Fmt.pf fmt "fragment reassemble"
  | Crop -> Fmt.pf fmt "fragment crop"
  | Drop_ovl -> Fmt.pf fmt "fragment drop-ovl"

let a_fragmentation : pf_fragmentation t =
  string "fragment" *> a_whitespace *>
  choice [ string "reassemble" *> return Reassemble ;
           string "crop" *> return Crop ;
           string "drop-ovl" *> return Drop_ovl ]

type pf_address = | IP of Ipaddr.t
                  | Dynamic_addr of pf_name_or_macro
                  | Fixed_addr of pf_name_or_macro

let pp_pf_address fmt = function
  | IP v -> Ipaddr.pp fmt v
  | Dynamic_addr addr -> Fmt.pf fmt "(%a)" pp_pf_name_or_macro addr
  | Fixed_addr addr -> Fmt.pf fmt "%a" pp_pf_name_or_macro addr

let a_ip : Ipaddr.t t =
  (a_ipv4_dotted_quad >>| fun ip -> Ipaddr.V4 ip)
  <|> (a_ipv6_coloned_hex >>| fun ip -> Ipaddr.V6 ip)

let a_address : pf_address t =
  (* interface-name | interface-group |
     "(" ( interface-name | interface-group ) ")" |
     hostname | ipv4-dotted-quad | ipv6-coloned-hex *)
  choice [
    (encapsulated '(' ')' a_interface_name >>| fun (name,_TODO_if_decoration) ->
       Dynamic_addr name);
    (a_ip >>| fun ip -> IP ip);
    (a_interface_name >>| fun (name,_unhandled_TODO_colons) -> Fixed_addr name);
    (* TODO handle difference between interface-name and interface-group*)
  ]

type pf_af = Inet | Inet6

let a_mask_bits ~af = a_number_range 0 (match af with | Inet -> 32
                                                      | Inet6 -> 128)

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
  | CIDR       v -> Fmt.pf fmt "(CIDR %a)" Ipaddr.Prefix.pp v

let a_cidr : Ipaddr.Prefix.t t =
  let expand_ipv4 prefix =
    let provided_octets = List.length (String.split_on_char '.' prefix) in
    if provided_octets < 1 || provided_octets > 4 then
      commit *> fail "invalid IPv4 CIDR"
    else
      let padding = String.init ((4 - provided_octets)*2)
          (function | i when i mod 2 = 0 -> '.'
                    | _ -> '0')
      in return (prefix ^ padding)
  in
  let a_and_mask ip =
    let af = match ip with Ipaddr.V4 _ -> Inet
                         | V6 _ -> Inet6 in
    option None (a_ign_whitespace *> char '/' *> some (a_mask_bits ~af))
    >>| begin function
      | None -> begin match af with Inet -> 32 | Inet6 -> 128 end
      | Some mask -> mask
    end >>= fun mask ->
    begin match (Ipaddr.to_string ip) ^ "/" ^ (string_of_int mask)
                |> Ipaddr.Prefix.of_string
      with
      | Error _ -> fail "invalid CIDR"
      | Ok cidr -> return cidr
    end
  in
  ( ( ( take_while1 ( function | '0'..'9' | '.'-> true
                               | _ -> false
      ) >>= (fun octets -> peek_char >>=
              begin function (* TODO hack to make ipv6 work: *)
                | Some (':'|'a'..'f'|'A'..'F') -> fail "not ipv4"
                | _ -> return octets end
            ) >>= expand_ipv4 >>| Ipaddr.V4.of_string >>= function
        | Ok x -> a_and_mask (Ipaddr.V4 x)
        | Error _ -> fail "invalid short ipv4 CIDR"
      )
      ) <|> (
      (take_while1 ( function | '0'..'9' | 'a'..'f' | 'A'..'F' | ':' -> true
                              | _ -> false
         ) (* TODO expand_ipv6 *)
       >>| Ipaddr.V6.of_string >>= (function
           | Error _ -> fail "invalid ipv6 CIDR"
           | Ok x -> a_and_mask (Ipaddr.V6 x)
         )
      )
    )
  )

let a_if_or_cidr : if_or_cidr t =
  (a_cidr >>| fun ip -> (CIDR ip))
  <|>
  ( (a_address)
    >>= begin function
      | (Dynamic_addr x) -> return (Dynamic_if x)
      | (Fixed_addr x) ->   return (Fixed_if x)
      | IP _ -> fail "TODO a_if_or_cidr: a_cidr didn't catch IP"
    end )

let a_redirhost = a_if_or_cidr

type pf_host =
  | Table_name of bool * string (* negated, name *)
  | Host_addr of { negated : bool ;
                   if_or_cidr : if_or_cidr ; }

let pp_pf_host fmt = function
  | Table_name (neg, name) ->
    Fmt.pf fmt "%a<%s>" pp_negation neg name
  | Host_addr {negated; if_or_cidr } ->
    Fmt.pf fmt "%a%a" pp_negation negated pp_if_or_cidr if_or_cidr

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
    | `hosts x -> Fmt.pf fmt "[%a]" Fmt.(list pp_pf_host) x
  in
  match v with
  | All_hosts -> Fmt.pf fmt "(all hosts)"
  | From_to { from_host ; from_port ; from_os ;
              to_host ; to_port } -> (*TODO*)
    Fmt.pf fmt "@[<v>%a%a%a%a%a@]"
      (pp_iff_condition (fun m -> m "from hosts: @[<v>%a@]")
         pp_host (function `any -> None | x -> Some x)) from_host
      (pp_skip_empty (fun m -> m "@ from ports: @[<v>%a@]") pp_pf_op) from_port
      (pp_skip_empty (fun m -> m "@ from os: [@[<v>%a@]]") Fmt.string) from_os
      (pp_iff_condition (fun m -> m "@ to hosts: @[<v>%a@]")
         pp_host (function `any -> None | x -> Some x)) to_host
      (pp_skip_empty (fun m -> m "@ to ports: @[<v>%a@]") pp_pf_op) to_port

let a_os =
  string "os" *>
  a_match_or_list '{' (a_string_not [])

let a_host : pf_host t =
  (* [ "!" ] ( address [ "/" mask-bits ] | "<" string ">" )
     string == table name *)
  (* TODO note that host can have :0 appended, and that these can be ranges ('-') *)
  a_negated >>= fun negated ->
  a_ign_whitespace >>= fun () ->
  (    a_if_or_cidr >>| fun if_or_cidr ->
       Host_addr {negated; if_or_cidr}
  ) <|> ( encapsulated '<' '>' a_unquoted_string >>| fun table ->
          Table_name (negated, table))

let a_hosts : pf_hosts t =
  (* requires preceding whitespace (which will be eaten) since hosts qualifier
     is entirely optional. you should NOT use a_whitespace *> before a_hosts *)
  (a_whitespace *> string "all" *> return All_hosts)
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
        option (`any, [], [])
          ( a_whitespace *> string "from" *>
            option `any
              ( a_whitespace *> a_fail_if_string ["port";"os"] is_whitespace *>
                choice [
                  a_common_host ;
                  string "urpf-failed" *> return `urpf_failed ;
                ]
              ) >>= fun host ->
            option [] (a_whitespace *> a_port) >>= fun port ->
            option [] (a_whitespace *> a_os) >>| fun os ->
            (host, port, os)
          ) >>= fun (from_host, from_port, from_os) ->
        option (`any, [])
          ( a_whitespace *> string "to" *>
            option `any
              ( a_whitespace *> a_fail_if_string ["port"] is_whitespace *>
                a_common_host >>| fun host -> host
              ) >>= fun host ->
            option [] (a_whitespace *> a_port) >>| fun port ->
            host, port
          ) >>| fun (to_host, to_port) ->
        if    from_host = `any && from_port = [] && from_os = []
           && to_host   = `any && to_port   = [] then All_hosts else
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
    Proto_list lst -> Fmt.pf fmt "[@[%a@]]" Fmt.(list ~sep:(unit ",@ ")
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
           ( string "to" *> a_interface_name >>| fun (to_if,_TODOCOLONS) -> To to_if) ]

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
    (a_interface_name >>= fun (name,_TODO_COLONS) ->
     (option None
        ( a_address >>= fun addr ->
          option None (a_ign_whitespace *> char '/' *>
                       some (a_mask_bits ~af:Inet6)) >>| fun mask ->
          Some (addr, mask)
        )
     ) >>| fun addr_and_mask -> name, addr_and_mask
    )

let a_routehost_list : pf_routehost list t =
  sep_by (a_optional_comma <|> a_whitespace) a_routehost

type pf_pooltype =
  | Bitmask
  | Random of bool (* sticky_address: true=present / false=not-present*)
  | Source_hash
  | Round_robin of bool (* sticky_address *)

let pp_pf_pooltype fmt = function
  | Bitmask -> Fmt.pf fmt "Bitmask"
  | Random sticky -> Fmt.pf fmt "Random (sticky-addr: %b)" sticky
  | Source_hash -> Fmt.pf fmt "Source hash"
  | Round_robin sticky -> Fmt.pf fmt "Round robin (sticky-addr: %b)" sticky

let a_pooltype : pf_pooltype t =
  let a_sticky_addr : bool t =
    (a_whitespace *> string "sticky-address" *> return true)
     <|> return false
  in
  choice (*TODO*)
    [ string "bitmask" *> return Bitmask ;
      string "random" *> a_sticky_addr >>|
      (fun sticky_addr -> Random sticky_addr);
      string "source-hash" *> return Source_hash ;
      string "round-robin" *> a_sticky_addr >>|
      (fun sticky_addr -> Round_robin sticky_addr) ;
      (* TODO When more than one redirection address is specified, round-robin is the only permitted pool type.*)
    ]
(*  *)

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

let pp_pf_tos fmt = function
  | Lowdelay -> Fmt.pf fmt "lowdelay"
  | Throughput -> Fmt.pf fmt "throughput"
  | Reliability -> Fmt.pf fmt "reliability"
  | Tos_number n -> Fmt.pf fmt "tos number: %d" n

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

let pp_pf_timeout fmt (name, seconds) =
  Fmt.pf fmt "(%S: %ds)" name seconds

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

let pp_pf_state_opt fmt =
  let rule_or_global_option = function
    | None -> ""
    | Some `rule -> " rule"
    | Some `global -> " global"
  in
  function
  | Max n -> Fmt.pf fmt "max: %d" n
  | No_sync -> Fmt.pf fmt "no-sync"
  | Timeout pf_to -> Fmt.pf fmt "timeout: %a" pp_pf_timeout pf_to
  | Sloppy -> Fmt.pf fmt "sloppy"
  | Pflow -> Fmt.pf fmt "pflow"
  | Source_track x -> Fmt.pf fmt "source-track%s" (rule_or_global_option x)
  | Max_src_nodes n -> Fmt.pf fmt "max-src-nodes: %d" n
  | Max_src_states n -> Fmt.pf fmt "max-src-states: %d" n

  | Max_src_conn n -> Fmt.pf fmt "max-src-conn: %d" n

  | Max_src_conn_rate (n,n2) -> Fmt.pf fmt "max-src-conn-rate: %d / %d" n n2
  | Overload {table ; flush} ->
    Fmt.pf fmt "overload: <%s>: flush%s" table (rule_or_global_option flush)
  | If_bound -> Fmt.pf fmt "if-bound"
  | Floating -> Fmt.pf fmt "floating"

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
  | Flags v -> Fmt.pf fmt "Flags: %a" pp_pf_flags v
  | Filteropt_icmp_type icmp -> Fmt.pf fmt "%a" pp_pf_icmp_type icmp
  | Filteropt_icmp6_type icmp6 -> Fmt.pf fmt "%a" pp_pf_icmp6_type icmp6
  | Tos tos -> Fmt.pf fmt "tos: %a" pp_pf_tos tos
  | State {predicate; state_opts} ->
    Fmt.pf fmt "@[<v>%s%a@]"
      (match predicate with
       | `no -> "NOT"
       | `keep -> "keep"
       | `modulate -> "modulate"
       | `synproxy -> "synproxy")
      (fun fmt -> function
         | None -> Fmt.pf fmt ""
         | Some state ->
           Fmt.pf fmt " state:(@[<v>%a@])" (Fmt.list pp_pf_state_opt) state)
      state_opts
  | Fragment -> Fmt.pf fmt "fragment"
  | Allow_opts -> Fmt.pf fmt "allow-opts"
  | Fragmentation frag -> Fmt.pf fmt "%a" pp_pf_fragmentation frag
  | No_df -> Fmt.pf fmt "no-df"
  | Min_ttl n -> Fmt.pf fmt "min-ttl: %d" n
  | Max_mss n -> Fmt.pf fmt "max-mss: %d" n
  | Random_id -> Fmt.pf fmt "random-id"
  | Reassemble_tcp -> Fmt.pf fmt "reassemble-tcp"
  | Label str -> Fmt.pf fmt "Label: %s" str
  | Tag str -> Fmt.pf fmt "Tag: %a" Fmt.(quote string) str
  | Tagged (neg, s) -> Fmt.pf fmt "Tagged: %a%s" pp_negation neg s
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
      string "label" *>a_whitespace *>(a_string_not [] >>| fun lbl ->Label lbl);
      string "tag" *> a_whitespace *> (a_string_not [] >>| fun tag -> Tag tag );
      ( a_negated >>= fun negated ->
        string "tagged" *> a_whitespace *> a_string_not [] >>| fun tag ->
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

let empty_pf_rule =
  { action = Block None ;
    direction = Both_directions ;
    logopts = None ;
    quick = false ;
    ifspec = None ;
    route = None ;
    af = None;
    protospec = None ;
    hosts = All_hosts ;
    filteropts = [] ;
  }

let pp_pf_rule fmt { action; direction; logopts; quick; ifspec;
                     route; af; protospec; hosts; filteropts } =
  Fmt.pf fmt "@[<v>\
    { @[<v>\
      Action: %a ;@ \
      Traffic direction: %a ;\
      %a\
      %a\
      %a\
      %a\
      %a\
      %a\
      %a\
      %a@] }@]"
    pp_pf_action action
    pp_direction direction
    (pp_skip_none (fun m -> m "@ Log options: %a ;") pp_pf_logopts) logopts
    (pp_skip_false (fun m -> m "@ Quick: %a;")) quick
    (pp_skip_none (fun m -> m "@ Interface: %a ;") pp_pf_ifspec) ifspec
    (pp_skip_none (fun m -> m "@ Route: %a ;") pp_pf_route) route
    (pp_skip_none (fun m -> m "@ Address family: %a ;") pp_pf_af) af
    (pp_skip_none (fun m -> m "@ Protocol spec: %a ;") pp_pf_protospec
    ) protospec
    (pp_iff_condition (fun m -> m "@ Hosts: %a ;") pp_pf_hosts
       (function All_hosts -> None | x -> Some x)
    ) hosts
    (pp_skip_empty (fun m -> m"@ Filter opts: @[<v>%a@]")
       pp_pf_filteropt) filteropts

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
  option All_hosts a_hosts >>= fun hosts ->
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

  let pp_debug_level fmt lvl =
    Fmt.pf fmt "(Debug level: %s)" (match lvl with
        | Debug_none -> "None"
        | Debug_urgent -> "Urgent"
        | Debug_misc -> "Misc"
        | Debug_loud -> "Loud")

  let pp fmt =
    let sep = Fmt.unit "; " in
    let none = Fmt.unit "none" in
    function
    | Debug lvl -> pp_debug_level fmt lvl
    | Hostid id -> Fmt.pf fmt "(Hostid %d)" id
    | State_policy pol -> Fmt.pf fmt "(State policy: %S)" pol
    | Block_policy pol -> Fmt.pf fmt "(Block policy: %S)" pol
    | Skip_on name ->
      Fmt.pf fmt "(Skip on: %a)" pp_pf_name_or_macro name
    | Timeout lst ->
      Fmt.pf fmt "(Timeout: @[<v>%a@])" Fmt.(list ~sep pp_pf_timeout) lst
    | Limit lst ->
      Fmt.pf fmt "(Limit %a)"
        Fmt.(list ~sep @@ pair ~sep:(unit": ") string int) lst
    | Loginterface name ->
      Fmt.pf fmt "(Loginterface %a)"
        Fmt.(option ~none pp_pf_name_or_macro) name
    | Optimization str ->
      Fmt.pf fmt "(Optimization: %S)" str
    | State_defaults lst ->
      Fmt.pf fmt "(State-defaults %a)" Fmt.(list ~sep pp_pf_state_opt) lst
    | Fingerprints fp_str ->
      Fmt.pf fmt "(Fingerprints %S)" fp_str

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
          a_interface_name >>| fun (ifn, _unhandled_TODO_colons) -> Skip_on ifn
        ) ;
        ( string "timeout" *> a_match_or_list '{' a_timeout
            >>| fun timeout -> Timeout timeout ) ;
        ( string "limit" *>
          a_match_or_list '{' a_limit_item >>| fun lmts -> Limit lmts ) ;
        ( string "loginterface" *> a_whitespace *>
          ( string "none" *> return None
            <|> some a_interface_name) >>| (function
                   | Some (ifn, _unhandled_TODO_colons) -> Some ifn
                   | None -> None) >>| fun ifn -> Loginterface ifn) ;
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

let pp_pf_portspec fmt (portspec:pf_portspec) =
  let name_or_num , portopt = portspec in
  Fmt.pf fmt "%a%a"
    pp_pf_name_or_number name_or_num
    Fmt.(option (fun fmt -> function
       | `any -> Fmt.pf fmt ":any"
       | `port num -> Fmt.pf fmt ":%a" pp_pf_name_or_number num
    )) portopt

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

type nat_redirhosts =
  { targets : if_or_cidr list ;
    portspec : pf_portspec option ;
    pooltype : pf_pooltype option ;
    static_port : bool ;
  }

let pp_nat_redirhosts fmt {targets; portspec; pooltype; static_port}=
  Fmt.pf fmt "%a %a %a %s"
    Fmt.(list pp_if_or_cidr) targets
    Fmt.(option pp_pf_portspec) portspec
    Fmt.(option pp_pf_pooltype) pooltype
    (match static_port with true -> "static-port" | false -> "")

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
let pp_a_trans_rule fmt no pass on af proto hosts tag tagged redirhosts =
  Fmt.pf fmt "@[<v>%a%a%aaddr family: %a@ \
              protos: %a@ hosts: %a@ %a%a\
              -> %a@]"
    pp_negation no
    (fun fmt -> function
     | None -> ()
     | Some None -> Fmt.pf fmt "pass "
     | Some (Some p) ->
       Fmt.pf fmt "pass (logopt: %a) " pp_pf_logopts p
    ) pass
    (pp_skip_none (fun m -> m "on: %a@ ") pp_pf_ifspec) on
    Fmt.(option pp_pf_af) af
    Fmt.(option pp_pf_protospec) proto
    pp_pf_hosts hosts
    (pp_skip_none (fun m -> m "tag: %a@ ") Fmt.string) tag
    (pp_skip_none (fun m -> m "tagged: %a@ ") Fmt.string) tagged
    Fmt.(option pp_nat_redirhosts) redirhosts

let pp_pf_rdr_rule fmt r =
  let redirhosts = match r.redirhosts with
    | None -> None
    | Some (targets,portspec,pooltype) ->
      (*only diff between rdr and nat is the "static-port" flag:*)
      Some {targets ; portspec; pooltype; static_port = false}
  in
  pp_a_trans_rule fmt r.no r.pass r.on r.af r.proto
    r.hosts r.tag r.tagged redirhosts

let a_trans_rule (ty:'nat_kind)
  : (bool * 'o2 * 'o3 * pf_af option * 'o5 * 'o6 * 'o7 * 'o8 * 'o9) t=
  option false (string "no" *> return true <* a_whitespace)
  >>= fun no ->
  string begin match ty with | `rdr -> "rdr"
                             | `nat -> "nat"
  end *>
  option None ( a_whitespace *> string "pass" *>
                option None ( a_whitespace *> string "log" *>
                              some (a_match_or_list '(' a_logopt)
                            ) >>| fun log ->
                Some log
              ) >>= fun pass ->
  option None ( a_whitespace *> string "on" *> some a_ifspec ) >>= fun on ->
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (a_whitespace *> some a_protospec) >>= fun proto ->
  a_hosts >>= fun hosts ->
  option None (a_whitespace *> string "tag" *> a_whitespace *>
               some (a_string_not []) ) >>=fun tag ->
  option None ( a_whitespace *> string "tagged" *> a_whitespace *>
                some (a_string_not [])) >>= fun tagged ->
  option None ( a_whitespace *> string "->" *>
                a_match_or_list '{' a_redirhost >>= fun redirhosts ->
                option None (a_whitespace *> some a_portspec)>>= fun portspec ->
                option None (a_whitespace *> some a_pooltype)>>| fun pooltype ->
                Some (redirhosts, portspec, pooltype)
              ) >>| fun redirhosts ->
  no, pass, on, af, proto, hosts, tag, tagged, redirhosts

let a_rdr_rule : pf_rdr_rule t =
  a_trans_rule `rdr >>| fun (no,pass,on,af,proto,hosts,tag,tagged,redirhosts) ->
  {no ; pass ; on ; af; proto ; hosts ; tag; tagged ; redirhosts }

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

let pp_pf_nat_rule fmt x =
  pp_a_trans_rule fmt x.no x.pass x.on x.af x.proto x.hosts
    x.tag x.tagged None ;
  Fmt.(option pp_nat_redirhosts) fmt x.redirhosts

let a_nat_rule : pf_nat_rule t =
  a_trans_rule `nat
  >>= fun (no,pass,on,af,proto,hosts,tag,tagged,x_redirhosts) ->
  begin match x_redirhosts with
    | None -> return None
    | Some (targets, portspec, pooltype) ->
      option false (a_whitespace *> string "static-port" *>
                    return true ) >>| fun static_port ->
      Some {targets; portspec ; pooltype ; static_port}
  end >>| fun redirhosts ->
  {no ; pass ; on ; af; proto ; hosts ; tag; tagged ; redirhosts }

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

let pp_pf_tableaddr fmt = function
  | Table_hostname name -> Fmt.pf fmt "Hostname: %S" name
  | Table_if_or_cidr addr -> Fmt.pf fmt "Addr: %a" pp_if_or_cidr addr
  | Self -> Fmt.pf fmt "Self"

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

let pp_pf_table_opts fmt = function
  | Persist -> Fmt.pf fmt "Persist"
  | Const -> Fmt.pf fmt "Const"
  | Counters -> Fmt.pf fmt "Counters"
  | File name -> Fmt.pf fmt "(File: %S)" name
  | Tableaddr lst ->
    Fmt.pf fmt "Tableaddr: [@[%a@]]"
      Fmt.(list ~sep:(unit "@ ") pp_pf_tableaddr) lst

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

let pp_pf_table_rule fmt {name; table_opts} =
  Fmt.pf fmt "{ @[<v>table: %S options: %a@]}" name
    Fmt.(list ~sep:(unit"@ ") pp_pf_table_opts) table_opts

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
  (* TODO "If bandwidth is not specified, the interface bandwidth
     is used (but take note that some interfaces do not know
     their bandwidth, or can adapt their bandwidth rates)." *)
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
           ( string "priority" *> a_whitespace *> a_number_range 0 15
             >>| fun n ->Priority n) ;
           (a_schedulers >>| fun sc -> Schedulers sc);
  ]

type pf_queue_rule = { name : string ;
                       on : pf_name_or_macro option ;
                       queueopts : pf_queueopt list ;
                       subqueues : string list ;
                     }

let a_queue_rule : pf_queue_rule t =
  string "queue" *> a_whitespace *> a_unquoted_string >>= fun name ->
  option None (a_whitespace *> string "on" *> a_whitespace *>
               some a_interface_name ) >>| (function
                       | Some (on, _unhandled_TODO_colons) -> Some on
                       | None -> None
               ) >>= fun on ->
  a_whitespace *>
  sep_by a_whitespace a_queueopt >>= fun queueopts ->
  option [] (a_match_or_list '{' a_unquoted_string)  >>| fun subqueues ->
  { name ; on ; queueopts ; subqueues }

type pf_altq_rule =
  { on: pf_ifspec ;
    queueopts: pf_queueopt list ;
    subqueues: string list ;
  }

let pp_pf_altq_rule fmt {on ; queueopts = _ ; subqueues} =
  Fmt.pf fmt "@[<v>{ @[<v>on: %a@ queueopts: %a@ \
              subqueues: {@[<v>%a@]}@]}@]"
    pp_pf_ifspec on
    Fmt.string "TODO queueopts"
    Fmt.(list ~sep:(unit ", ") @@ suffix (unit ">")
         @@ prefix (unit "<") string) subqueues

let a_altq_rule =
  string "altq on" *> a_whitespace *> a_ifspec >>= fun on ->
  a_whitespace *> sep_by a_whitespace a_queueopt >>= fun queueopts ->
  (if queueopts = [] then a_ign_whitespace else a_ign_whitespace) *>
  string "queue" *> a_whitespace *>
  option [] (a_match_or_list '{' a_unquoted_string) >>| fun subqueues ->
  {on ; queueopts ; subqueues }

type pf_load_anchor = { anchor_name : string ; filename : string }

let pp_pf_load_anchor fmt v =
  Fmt.pf fmt "Anchor %S (file %S)" v.anchor_name v.filename

let a_load_anchor =
  string "load anchor" *> a_whitespace *>
  a_unquoted_string <* a_whitespace >>= fun anchor_name ->
  string "from" *> a_string >>| fun filename -> {anchor_name ; filename }

type 'a pf_trans_anchor =
  (* this is called [trans-anchors] in the pf BNF grammar *)
  { ty: 'a;
    name : string ;
    on : pf_ifspec ;
    af : pf_af option ;
    proto : pf_protospec option ;
    hosts: pf_hosts ;
  } constraint 'a = [< `nat | `rdr | `binat]

let pp_pf_trans_anchor fmt x =
  Fmt.pf fmt "{ @[<v>%s-anchor: %S@ on: %a@ addr family: %a@ protos: %a@ \
              hosts: %a @]}"
    (match x.ty with | `nat -> "nat"
                     | `rdr -> "rdr"
                     | `binat -> "binat")
    x.name
    pp_pf_ifspec x.on
    Fmt.(option pp_pf_af) x.af
    Fmt.(option pp_pf_protospec) x.proto
    pp_pf_hosts x.hosts

let a_trans_anchor (ty:'nat_kind) : 'nat_kind pf_trans_anchor t =
  begin match ty with
    | `nat -> string "nat-anchor"
    | `rdr -> string "rdr-anchor"
    | `binat -> string "binat-anchor"
  end *>
  a_whitespace *> a_string >>= fun name ->
  option (If_list []) (a_whitespace *> a_ifspec) >>= fun on ->
  option None (a_whitespace *> some a_af) >>= fun af ->
  option None (a_whitespace *> some a_protospec) >>= fun proto ->
  option All_hosts a_hosts >>= fun hosts ->
  return { ty; name; on; af; proto ; hosts}

type line = Include of string
          | Macro_definition of pf_macro_definition
          | Pf_rule of pf_rule
          | Rdr_rule of pf_rdr_rule
          | NAT_rule of pf_nat_rule
          | Set of PF_set.set_t
          | Table_rule of pf_table_rule
          | Queue_rule of pf_queue_rule
          | Altq_rule of pf_altq_rule
          | Load_anchor of pf_load_anchor
          | Empty_line
          | Nat_anchor of [`nat] pf_trans_anchor
          | Rdr_anchor of [`rdr] pf_trans_anchor
          | Binat_anchor of [`binat] pf_trans_anchor

let pp_line fmt = function
  | Include  str -> Fmt.pf fmt "include %S" str
  | Macro_definition { name; definition } ->
    Fmt.pf fmt "macro %S = %a" name
      Fmt.(list ~sep:(unit " ") pp_pf_name_or_macro) definition
  | Pf_rule rule -> Fmt.pf fmt "rule: %a" pp_pf_rule rule
  | Empty_line -> Fmt.pf fmt ""
  | Rdr_rule v -> Fmt.pf fmt "rdr-rule: %a" pp_pf_rdr_rule v
  | NAT_rule v -> Fmt.pf fmt "nat-rule: %a" pp_pf_nat_rule v
  | Set set -> Fmt.pf fmt "set: @[<v>%a@]" PF_set.pp set
  | Table_rule table_rule ->
    Fmt.pf fmt "table: @[<v>%a@]" pp_pf_table_rule table_rule
  | Queue_rule _ -> Fmt.pf fmt "TODO sorry cannot pretty-print [queue]"
  | Altq_rule altq -> Fmt.pf fmt "altq: %a" pp_pf_altq_rule altq
  | Load_anchor anchor -> Fmt.pf fmt "load-anchor %a" pp_pf_load_anchor anchor
  | Nat_anchor x -> Fmt.pf fmt "nat: %a" pp_pf_trans_anchor x
  | Rdr_anchor x -> Fmt.pf fmt "rdr: %a" pp_pf_trans_anchor x
  | Binat_anchor x -> Fmt.pf fmt "binat: %a" pp_pf_trans_anchor x

      let a_line =
  (* option | pf-rule | nat-rule | binat-rule | rdr-rule |
     antispoof-rule | altq-rule | queue-rule | trans-anchors |
     anchor-rule | anchor-close | load-anchor | table-rule |
     include *)
  a_ign_whitespace *>
  Angstrom.choice
    [ (a_ign_whitespace *> end_of_input *> return Empty_line) ;
      (a_pf_rule >>| fun rule -> Pf_rule rule) ;
      (a_include >>| fun filename -> Include filename) ;
      (a_trans_anchor `nat >>| fun anch -> Nat_anchor anch) ;
      (a_trans_anchor `rdr >>| fun anch -> Rdr_anchor anch) ;
      (a_trans_anchor `binat >>| fun anch -> Binat_anchor anch) ;
      (a_rdr_rule >>| fun rule -> Rdr_rule rule) ;
      (a_nat_rule >>| fun rule -> NAT_rule rule) ;
      (a_queue_rule >>| fun rule -> Queue_rule rule) ;
      (a_altq_rule >>| fun rule -> Altq_rule rule) ;
      (PF_set.a_set >>| fun set -> Set set) ;
      (a_table_rule >>| fun rule -> Table_rule rule) ;
      (a_load_anchor >>| fun rule -> Load_anchor rule) ;
      (a_macro_definition >>| fun macro -> Macro_definition macro) ;
    ]
  <* a_ign_whitespace <*
  ( available >>= peek_string >>= fun left ->
    (end_of_input (* make sure we parsed it all *)
    <?> "Leftover at end:" ^ left)
  )

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
