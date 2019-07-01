open Rresult

let () =
  Printexc.record_backtrace true ;
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter () ;
  Logs.(set_level @@ Some Debug)

open Pf_qubes.Parse_qubes

let alc_qubes = Alcotest_unix.testable Pf_qubes.Parse_qubes.pp_rule (fun a b -> a = b)

let parse_full a s = Angstrom.(parse_string (a <* end_of_input) s)


let qubes str = parse_qubes ~number:0 str

let test_qubes_empty () =
  Alcotest_unix.(check @@ result reject string) "empty fails"
    (Error ": not enough input") (qubes "")

let test_qubes_only_action () =
  Alcotest_unix.(check @@ result alc_qubes string) "action=accept"
    (Ok { number = 0 ;
          action = Accept;
          proto = None;
          specialtarget = None;
          dst = `any;
          dstports = None;
          icmp_type = None;
        }
    )
    (qubes "action=accept")

let test_qubes_dns () =
  Alcotest_unix.(check @@ result alc_qubes string) "action=accept dst4=8.8.8.8 proto=udp dstports=53-53"
    (Ok { number = 0 ;
          action = Accept;
          proto = Some `udp;
          specialtarget = None;
          dst = `hosts (Ipaddr.Prefix.of_string_exn "8.8.8.8/32");
          dstports = Some (Range_inclusive (53, 53));
          icmp_type = None;
        }
    )
    (qubes "action=accept dst4=8.8.8.8 proto=udp dstports=53-53")

let test_qubes_dsthost () =
  Alcotest_unix.(check @@ result alc_qubes string) "action=accept dsthost=cyber.biz"
    (Ok { number = 0 ;
          action = Accept;
          proto = None;
          specialtarget = None;
          dst = `dnsname "cyber.biz";
          dstports = None;
          icmp_type = None;
        }
    )
    (qubes "action=accept dsthost=cyber.biz")

let test_qubes_ipv6 () =
  Alcotest_unix.(check @@ result alc_qubes string)
    "action=drop dst6=2a00:1450:4000::/37 proto=tcp"
    (Ok {
          number = 0 ;
          action = Drop;
          proto = Some `tcp;
          specialtarget = None;
          dst = `hosts (Ipaddr.Prefix.of_string_exn "2a00:1450:4000::/37" );
          dstports = None;
          icmp_type = None;
        }
    )
    (qubes "action=drop dst6=2a00:1450:4000::/37 proto=tcp")

let test_qubes_unimplemented () =
  Alcotest_unix.(check @@ result alc_qubes string)
    "action=accept specialtarget=dns"
    (Ok {
          number = 0 ;
          action = Accept ;
          proto = None;
          specialtarget = Some `dns;
          dst = `any;
          dstports = None;
          icmp_type = None;
        }
    )
    (qubes "action=accept specialtarget=dns") ;

  Alcotest_unix.(check @@ result alc_qubes string)
    "action=drop proto=tcp specialtarget=dns"
    (Ok {
          number = 0 ;
          action = Drop;
          proto = Some `tcp;
          specialtarget = Some `dns;
          dst = `any;
          dstports = None;
          icmp_type = None;
        }
    )
    (qubes "action=drop proto=tcp specialtarget=dns")

let tests =
  [ "parse_qubes [QubesOS v4 firewall format adapter]",
    [ "empty", `Quick, test_qubes_empty ;
      "action=accept", `Quick, test_qubes_only_action ;
      "action=accept dsthost=cyber.biz", `Quick, test_qubes_dsthost ;
      "action=accept dst4=8.8.8.8 proto=udp dstports=53-53", `Quick,
      test_qubes_dns ;
      "Handling of IPv6 rules", `Quick, test_qubes_ipv6;
      "action=accept specialtarget=dns", `Quick, test_qubes_unimplemented
    ] ;
  ]

let () =
  Alcotest_unix.run "ocaml-pf test suite" tests
