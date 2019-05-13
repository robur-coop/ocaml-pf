(* see https://www.qubes-os.org/doc/vm-interface/#firewall-rules-in-4x *)

(* it's not overly specified; for instance:
  - it's not clear if dst4, dst6, dstname can be specified in the same rule
*)
(* MCP: this is now specified: they can't *)

open Angstrom

type action = | Accept | Drop

let pp_action f = function | Accept -> Fmt.string f "accept" | Drop -> Fmt.string f "drop"

type family = | Inet | Inet6

let a_whitespace_unit : unit t =
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let a_whitespace = skip_many1 a_whitespace_unit

let a_ign_whitespace = skip_many a_whitespace_unit

let some t = t >>| fun applied -> Some applied

let a_number =
  take_while1 (function '0'..'9' -> true | _ -> false) >>= fun str ->
  match int_of_string str with
    | i -> return i
    | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_number_range min' max' =
  a_number >>= function | n when n <= max' && min' <= n -> return n
                        | n -> fail (Fmt.strf "Number out of range: %d" n)

let a_mask_bits ~af = a_number_range 0 (match af with | Inet -> 32
                                                      | Inet6 -> 128)

let a_cidr : Ipaddr.Prefix.t t =
  let expand_ipv4 prefix =
    let provided_octets = List.length (String.split_on_char '.' prefix) in
    let padding = String.init ((4 - provided_octets)*2)
        (function | i when i mod 2 = 0 -> '.'
                  | _ -> '0')
    in prefix ^ padding
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
            ) >>| expand_ipv4 >>| Ipaddr.V4.of_string >>= function
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

let q_action =
  (string "drop" *> return Drop)
  <|>
  (string "accept" *> return Accept)

let a_dst4 : (family * Ipaddr.V4.Prefix.t) t =
  a_cidr >>= function
  | V4 x -> return (Inet, x)
  | V6 _ -> fail "dst4 contains IPv6 CIDR"

let a_dst6 : (family * Ipaddr.V6.Prefix.t) t =
  a_cidr >>= function
  | V6 x -> return (Inet6, x)
  | V4 _ -> fail "dst6 contains IPv4 CIDR"

let a_proto =
  choice [ string "tcp" *> return `tcp ;
           string "udp" *> return `udp ;
           string "icmp" *> return `icmp ;
         ]

let a_specialtarget =
  choice [ string "dns" *> return `dns ;
         ]

type range = Range_inclusive of (int * int)

let pp_range f (Range_inclusive (a, b)) = Fmt.pf f "[%d - %d]" a b

let a_dstports : range list t = (* NB only valid with tcp|udp *)
  (* should use a_binary_op *)
  a_number_range 0 0xFFFF >>= fun low ->
  char '-' *>
  (* only accept ports that are >= 'low' and < 65336: *)
  a_number_range low 0xFFFF >>| fun high ->
  [ (Range_inclusive (low, high)) ]

let a_icmptype = a_number_range 0 1000 (* TODO look up max *)

let a_dpi = string "NO" (* TODO this is not very well specified *)

type proto = [ `udp | `tcp | `icmp ]
let pp_proto f = function
  | `udp -> Fmt.string f "udp"
  | `tcp -> Fmt.string f "tcp"
  | `icmp -> Fmt.string f "icmp"

type rule =
  { 
    action : action;
    proto : proto option;
    specialtarget : [ `dns ] option;
    dst : [ `any
          | `hosts of Ipaddr.Prefix.t ]; (* TODO: ipv6, dsthosts *)
    dstports : range list;
    icmp_type : int option;
    number : int; (* do we need this? *)
  }

let pp_specialtarget f _ = Fmt.string f "dns"
let pp_dst f = function
  | `any -> Fmt.string f "any"
  | `hosts prefix -> Ipaddr.Prefix.pp f prefix

let pp_rule fmt {action; proto; specialtarget; dst; dstports; icmp_type; number} =
  Fmt.pf fmt "@[<v>%d %a %a %a %a %a %a@]"
    number
    (Fmt.option pp_proto) proto
    (Fmt.option pp_specialtarget) specialtarget
    pp_dst dst
    (Fmt.list pp_range) dstports
    Fmt.(option int) icmp_type
    pp_action action

let a_qubes_v4 ~source_ip:_ ~number =
  string "action=" *> q_action >>= fun action ->
  option (None, `any)
    ( (a_ign_whitespace *> string "dstname=" *>
       fail "not handled: dnsname= [TODO how should this work?]" )
      <|>
      (a_whitespace *> choice [
          (string "dst4=" *> a_dst4 >>| fun (af,x) -> af, Ipaddr.V4 x) ;
          (string "dst6=" *> a_dst6 >>| fun (af,x) -> af, Ipaddr.V6 x) ;
        ] >>| fun (af,cidr) ->
       (Some af), `hosts cidr)
    ) >>= fun (_af, dst) ->
  (* TODO note that it's not specified if multiple of these can be there*)
  option None (a_whitespace *> string "proto=" *> some a_proto) >>= fun proto ->
  option None (a_whitespace *> string "specialtarget=" *>
               some a_specialtarget) >>= fun specialtarget ->
  begin match proto with
  | Some (`udp | `tcp) ->
    option [] (a_whitespace *> string "dstports=" *> a_dstports)
  | None | Some `icmp -> return []
  end >>= fun dstports ->

  begin match proto with
    | Some `icmp ->
      option None (a_whitespace *> string "icmptype=" *> some a_icmptype)
    | None | Some (`tcp | `udp) -> return None
  end >>= fun icmptype ->
  option None (a_whitespace *> string "dpi=" *> some a_dpi) >>= fun _dpi ->
  end_of_input >>| fun () ->
    { action ;
      proto;
      specialtarget;
      dst;
      dstports;
      icmp_type = icmptype;
      number;
    }

let parse_qubes_v4 ~source_ip ~number entry : (rule, string) result =
  parse_string (a_qubes_v4 ~source_ip ~number) entry
