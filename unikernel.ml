(* This unikernel is based on tracing documentation:
   https://mirage.io/wiki/profiling
*)

open Lwt.Infix

let target_ip = Ipaddr.V4.of_string_exn "10.0.0.1"

module Main (S: Mirage_types_lwt.STACKV4) = struct
  let buffer = Io_page.get 1 |> Io_page.to_cstruct

  let start s =
    let t = S.tcpv4 s in
    let port = Key_gen.port () in

    S.listen_tcpv4 s ~port (fun flow ->
      let dst, dst_port = S.TCPV4.dst flow in
      Logs.info (fun f -> f "new tcp connection detected from IP %s on port %d" (Ipaddr.V4.to_string dst) dst_port);
      S.TCPV4.read flow >>= function
      | Ok `Eof -> Logs.info (fun f -> f "Closing Connection"); Lwt.return_unit
      | Error e -> Logs.warn (fun f -> f "Error reading from connection %a" S.TCPV4.pp_error e); Lwt.return_unit
      | Ok (`Data b) -> Logs.info (fun f -> f "read %d bytes:\n%s" (Cstruct.len b) (Cstruct.to_string b));
        S.TCPV4.create_connection t (target_ip, 7001) >>= function
        | Error _err -> failwith "Connection failed"
        | Ok flow -> 
          let payload = Cstruct.sub buffer 0 1 in
          Cstruct.set_char payload 0 '!';
          S.TCPV4.write flow payload >>= function
          | Error _ -> assert false
          | Ok () -> S.TCPV4.close flow
      );
    
    (* 
    (S.TCPV4.create_connection t (target_ip, 7001) >>= function
    | Error _err -> failwith "Connection to port 7001 failed"
    | Ok flow ->

    let payload = Cstruct.sub buffer 0 1 in
    Cstruct.set_char payload 0 '!';

    S.TCPV4.write flow payload >>= function
    | Error _ -> assert false
    | Ok () ->

    S.TCPV4.close flow);
    *)
    Logs.info (fun f -> f "logging something %s" Findnonce.foo);
    Logs.info (fun f -> f "logging the start key %s" (Key_gen.start_inx ()));
    S.listen s
end
