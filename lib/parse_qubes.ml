(* see https://www.qubes-os.org/doc/vm-interface/#firewall-rules-in-4x *)

(* it's not overly specified; for instance:
  - it's not clear if dst4, dst6, dstname can be specified in the same rule
*)

open Angstrom
open Parse

let q_action =
  (string "drop" *> return (Block None))
  <|>
  (string "accept" *> return Pass)

let a_dst4 : (pf_af * Ipaddr.V4.Prefix.t) t =
  a_cidr >>= function
  | Ipaddr.V4 x -> return (Inet, x)
  | Ipaddr.V6 _ -> fail "dst4 contains IPv6 CIDR"

let a_dst6 : (pf_af * Ipaddr.V6.Prefix.t) t =
  a_cidr >>= function
  | Ipaddr.V6 x -> return (Inet6, x)
  | Ipaddr.V4 _ -> fail "dst6 contains IPv4 CIDR"

let a_proto =
  choice [ string "tcp" *> return `tcp ;
           string "udp" *> return `udp ;
           string "icmp" *> return `icmp ;
         ]

let a_specialtarget =
  choice [ string "dns" *> return `dns ;
         ]

let a_dstports : Parse.pf_op list t = (* NB only valid with tcp|udp *)
  (* should use a_binary_op *)
  a_number_range 0 0xFFFF >>= fun low ->
  char '-' *>
  (* only accept ports that are >= 'low' and < 65336: *)
  a_number_range low 0xFFFF >>| fun high ->
  [ Parse.Binary (Range_inclusive (low, high)) ]

let a_icmptype = a_number_range 0 1000 (* TODO look up max *)

let a_dpi = string "NO" (* TODO this is not very well specified *)

type qubes_rule =
  { rule : Parse.pf_rule ;
    source_ip : Ipaddr.t ;
    number : int ;
  }

let pp_rule fmt {rule; source_ip; number} =
  Fmt.pf fmt "@[<v>SOURCE_IP=%a %04d@,    %a@]"
    Ipaddr.pp source_ip
    number
    Parse.pp_pf_rule rule

let a_qubes_v4 ~source_ip ~number =
  string "action=" *> q_action >>= fun action ->
  option (None, `any)
    ( (a_ign_whitespace *> string "dstname=" *>
       fail "not handled: dnsname= [TODO how should this work?]" )
      <|>
      (a_whitespace *> choice [
          (string "dst4=" *> a_dst4 >>| fun (af,x) -> af, Ipaddr.V4 x) ;
          (string "dst6=" *> a_dst6 >>| fun (af,x) -> af, Ipaddr.V6 x) ;
        ] >>| fun (af,cidr) ->
       (Some af), `hosts [ Host_addr { negated = false ;
                            if_or_cidr = CIDR cidr ;
                          }] )
    ) >>= fun (af, dst) ->
  (* TODO note that it's not specified if multiple of these can be there*)
  option None (a_whitespace *> string "proto=" *> some a_proto) >>= fun proto ->
  option None (a_whitespace *> string "specialtarget=" *>
               some a_specialtarget) >>= fun _specialtarget ->
  begin match proto with
  | Some (`udp | `tcp) ->
    option [] (a_whitespace *> string "dstports=" *> a_dstports)
  | None | Some `icmp -> return []
  end >>= fun dstports ->

  begin match proto with
    | Some `icmp ->
      option None (a_whitespace *> string "icmptype=" *> some a_icmptype)
    | None | Some (`tcp | `udp) -> return None
  end >>= fun _icmptype ->
  option None (a_whitespace *> string "dpi=" *> some a_dpi) >>= fun _dpi ->
  end_of_input >>| fun () ->
  let rule =
    { action ;
      direction = Both_directions ; (* TODO *)
      logopts = None ;
      quick = true ;
      ifspec = None ; (* TODO presumably on a NIC attached to the VM *)
      route = None ;
      af ;
      protospec = (begin match proto with
          | None -> None
          | Some `udp -> Some (Proto_list [Name (String "udp")])
          | Some `tcp -> Some (Proto_list [Name (String "tcp")])
          | Some `icmp -> Some (Proto_list [Name (String "icmp")])
        end ) ;
      hosts =
        From_to { from_host =
                    `hosts [
                      Host_addr
                        { negated = false ;
                          if_or_cidr = CIDR (Ipaddr.Prefix.of_addr source_ip) ;
                        } ] ;
                  from_port = [] ;
                  from_os = [] ;
                  to_host = dst ;
                  to_port = dstports;
                } ;
      filteropts = [] ;
    } in
  { rule ; source_ip ; number ; }

let parse_qubes_v4 ~source_ip ~number entry : (qubes_rule, string) result =
  parse_string (a_qubes_v4 ~source_ip ~number) entry
