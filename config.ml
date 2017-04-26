open Mirage

let port =
  let doc = Key.Arg.info ~doc:"The TCP port on which to list for connections" ["port"] in
  Key.(create "port" Arg.(opt int 8080 doc))

let start_inx =
  let doc = Key.Arg.info ~doc:"The start of range to search for nonces" ["start_inx"] in
  Key.(create "start_inx" Arg.(opt string "00000000" doc))

let main = foreign ~keys:[Key.abstract port; Key.abstract start_inx] "Unikernel.Main" (stackv4 @-> job)
let stack = generic_stackv4 default_network

(* let tracing = mprof_trace ~size:1000000 ()
*)

let packages = [package "sha"; package "num"]

let () =
  register "example" ~packages (*~tracing*) [
    main $ stack
  ]
