(* copied from stack overflow http://stackoverflow.com/questions/235493/is-my-ocaml-implementation-of-sha256-sane *)
let pack64 x = 
  let b = Buffer.create 8 in 
    for i = 0 to 7 do
      let shft = (7-i)*8 in
        Buffer.add_char b (char_of_int (Int64.to_int (Int64.logand (Int64.shift_right x shft) 0xFFL)));
    done;
    b

let pack x n = 
  if (n mod 8) = 0 then
    let n' = n/8 in
    let b = Buffer.create n' in 
      for i = 0 to n'-1 do
        let shft = ((n'-1)-i)*8 in
          Buffer.add_char b (char_of_int (Int32.to_int (Int32.logand (Int32.shift_right x shft) 0xFFl)));
      done;
      b
  else
    raise (Invalid_argument ("pack: " ^ (string_of_int n) ^ " is not a multiple of 8"))

let pack32 x = pack x 32
let pack16 x = pack x 16
let pack8 x = pack x 8


let as_bytes bits =
  match (bits mod 8) with
    | 0 -> (bits / 8)
    | _ -> failwith "as_bytes: bits must be multiple of 8"
let as_bits bytes = bytes * 8
let k = [|
    0x428a2f98l; 0x71374491l; 0xb5c0fbcfl; 0xe9b5dba5l;
    0x3956c25bl; 0x59f111f1l; 0x923f82a4l; 0xab1c5ed5l;
    0xd807aa98l; 0x12835b01l; 0x243185bel; 0x550c7dc3l;
    0x72be5d74l; 0x80deb1fel; 0x9bdc06a7l; 0xc19bf174l;
    0xe49b69c1l; 0xefbe4786l; 0x0fc19dc6l; 0x240ca1ccl;
    0x2de92c6fl; 0x4a7484aal; 0x5cb0a9dcl; 0x76f988dal;
    0x983e5152l; 0xa831c66dl; 0xb00327c8l; 0xbf597fc7l;
    0xc6e00bf3l; 0xd5a79147l; 0x06ca6351l; 0x14292967l;
    0x27b70a85l; 0x2e1b2138l; 0x4d2c6dfcl; 0x53380d13l;
    0x650a7354l; 0x766a0abbl; 0x81c2c92el; 0x92722c85l;
    0xa2bfe8a1l; 0xa81a664bl; 0xc24b8b70l; 0xc76c51a3l;
    0xd192e819l; 0xd6990624l; 0xf40e3585l; 0x106aa070l;
    0x19a4c116l; 0x1e376c08l; 0x2748774cl; 0x34b0bcb5l;
    0x391c0cb3l; 0x4ed8aa4al; 0x5b9cca4fl; 0x682e6ff3l;
    0x748f82eel; 0x78a5636fl; 0x84c87814l; 0x8cc70208l;
    0x90befffal; 0xa4506cebl; 0xbef9a3f7l; 0xc67178f2l
  |]
  let hash s =
    let add_int32 x y = Int32.add x y in

    let left_int32 x n = Int32.shift_left x n in
    let right_int32 x n = Int32.shift_right_logical x n in
    let or_int32 x y = Int32.logor x y in
    let xor_int32 x y = Int32.logxor x y in
    let and_int32 x y = Int32.logand x y in
    let not_int32 x = Int32.lognot x in

    let rotate x n = (or_int32 (right_int32 x n) (left_int32 x (32 - n))) in
    let shift x n = right_int32 x n in
    let ch x y z = xor_int32 (and_int32 x y) (and_int32 (not_int32 x) z) in
    let maj x y z = (xor_int32 (and_int32 x y) (xor_int32 (and_int32 x z) (and_int32 y z))) in
    let sum0 x = (xor_int32 (rotate x  2) (xor_int32 (rotate x 13) (rotate x 22))) in
    let sum1 x = (xor_int32 (rotate x  6) (xor_int32 (rotate x 11) (rotate x 25))) in
    let rh00 x = (xor_int32 (rotate x  7) (xor_int32 (rotate x 18) (shift  x  3))) in
    let rh01 x = (xor_int32 (rotate x 17) (xor_int32 (rotate x 19) (shift  x 10))) in

    let as_bytes bits =
      match (bits mod 8) with
        | 0 -> (bits / 8)
        | _ -> failwith "as_bytes: bits must be multiple of 8"
    in
    let as_bits bytes = bytes * 8 in
    let sha = [|
      0x6a09e667l;
      0xbb67ae85l;
      0x3c6ef372l;
      0xa54ff53al;
      0x510e527fl;
      0x9b05688cl;
      0x1f83d9abl;
      0x5be0cd19l
    |]
    in
    let message = Buffer.create (as_bytes 512) in (* smallest possible buffer is at least 512 bits *)
      begin
        Buffer.add_string message s;
        let original_length = as_bits (Buffer.length message) in 
        Buffer.add_char message '\x80'; (* append '1' bit *)
          let pad_start = as_bits (Buffer.length message) in
          let pad_blocks = if (original_length mod 512) < 448 then 1 else 2 in
          let message_length = ((original_length / 512) + pad_blocks) * 512 in
            begin (* appending k bits of 0 (where message_length-64 is our k) *)
              for i = as_bytes pad_start to (as_bytes (message_length - (as_bytes  64)))-8 do
                Buffer.add_char message '\x00'
              done;
              Buffer.add_buffer message (pack64 (Int64.of_int original_length))
            end
      end;
      let rec process_block i blocks =
        let array_of_block i = 
          let boff = i*(as_bytes 512) in
          let to_int32 x = (Int32.of_int (int_of_char x)) in
          let w = Array.make (as_bytes 512) 0l in
            begin
              for t = 0 to 15 do
                w.(t) <- (or_int32 (left_int32 (to_int32 (Buffer.nth message (boff + (t*4  )))) 24)
                         (or_int32 (left_int32 (to_int32 (Buffer.nth message (boff + (t*4+1)))) 16)
                         (or_int32 (left_int32 (to_int32 (Buffer.nth message (boff + (t*4+2))))  8)
                                               (to_int32 (Buffer.nth message (boff + (t*4+3))))   )));
              done;
              for t = 16 to 63 do
                w.(t) <- add_int32 (add_int32 (rh01 w.(t-2)) w.(t-7)) (add_int32 (rh00 w.(t-15)) w.(t-16))
              done;
              w
            end
        in
          if i = blocks then 
            let sha256 = Buffer.create (as_bytes 256) in
            let rec pack_sha256 i =
              match i with
                | 8 -> Buffer.contents sha256
                | _ ->
                    begin
                      Buffer.add_buffer sha256 (pack32 sha.(i));
                      pack_sha256 (i+1)
                    end
            in pack_sha256 0
          else
            begin
              let w = array_of_block i in
              let tem = [| 0l; 0l |] in
                begin
                  let a = ref sha.(0) in 
                  let b = ref sha.(1) in
                  let c = ref sha.(2) in
                  let d = ref sha.(3) in 
                  let e = ref sha.(4) in
                  let f = ref sha.(5) in
                  let g = ref sha.(6) in
                  let h = ref sha.(7) in
                    for t = 0 to 63 do
                      begin
                        tem.(0) <- add_int32 (add_int32 !h (sum1 !e)) (add_int32 (ch !e !f !g) (add_int32 k.(t) w.(t)));
                        tem.(1) <- add_int32 (sum0 !a) (maj !a !b !c);
                        h := !g;
                        g := !f;
                        f := !e;
                        e := add_int32 !d tem.(0);
                        d := !c;
                        c := !b;
                        b := !a;
                        a := add_int32 tem.(0) tem.(1);
                       end
                    done;
                    sha.(0) <- add_int32 sha.(0) !a;
                    sha.(1) <- add_int32 sha.(1) !b;
                    sha.(2) <- add_int32 sha.(2) !c;
                    sha.(3) <- add_int32 sha.(3) !d;
                    sha.(4) <- add_int32 sha.(4) !e;
                    sha.(5) <- add_int32 sha.(5) !f;
                    sha.(6) <- add_int32 sha.(6) !g;
                    sha.(7) <- add_int32 sha.(7) !h;

                    (* good faith attempt to clear memory *)
                    for i = 0 to 63 do w.(i) <- Int32.of_int 0 done;
                    tem.(0) <- Int32.of_int 0; tem.(1) <- Int32.of_int 0;
                    a :=Int32.of_int 0; b :=Int32.of_int 0; c :=Int32.of_int 0; d :=Int32.of_int 0; e :=Int32.of_int 0; f :=Int32.of_int 0; g :=Int32.of_int 0; h :=Int32.of_int 0;
                end;
            process_block (i+1) blocks
          end
  in process_block 0 ((Buffer.length message) / (as_bytes 512))

  let hexdigits s =
    let rec hexdigits_inner hx i =
      match i with
        | 32 -> hx
        | _ -> hexdigits_inner (hx ^ (Printf.sprintf "%02x" (int_of_char s.[i]))) (i+1)
    in
      hexdigits_inner "" 0


(* end copied code *)

let header_size = 76 (* block header is 76 bytes without nonnce *)
let nonce_size = 4 (* nonce size is 4 bytes *)

let foo = "hello from nonce file"

let rev_string_pairs (s : string) : string =
  let rec help a b = match String.length b with
    | 0 -> a
    | n -> help (String.sub b 0 2 ^ a) (String.sub b 2 (n-2)) in
  help "" s

let hex_decode_char : char -> int option = function
  | '0' -> Some 0
  | '1' -> Some 1
  | '2' -> Some 2
  | '3' -> Some 3
  | '4' -> Some 4
  | '5' -> Some 5
  | '6' -> Some 6
  | '7' -> Some 7
  | '8' -> Some 8
  | '9' -> Some 9
  | 'a' -> Some 10
  | 'b' -> Some 11
  | 'c' -> Some 12
  | 'd' -> Some 13
  | 'e' -> Some 14
  | 'f' -> Some 15
  | _   -> None

let hex_decode_byte (s : string) : int option = match String.length s with
  | 2 -> (match ( hex_decode_char (String.get s 0), 
                 hex_decode_char (String.get s 1)) with
    | Some x, Some y -> Some (16 * x + y)
    | _ -> None)
  | _ -> None

(* Note: padding will be uninitialized *)
let make_bytestring (s : string) (padding : int) =
  let l = (String.length s) / 2 in
  let bytestring = Bigarray.Array1.create 
                    Bigarray.Int8_unsigned
                    Bigarray.c_layout (l + padding) in
  for i = 0 to (l-1) do
    match hex_decode_byte (String.sub s (2*i) 2) with
      | Some x -> bytestring.{i} <- x
      | None -> failwith (String.concat " " ["invalid hex:"; String.sub s (2*i) 2])
  done;
  bytestring

let hex_string_to_int64 s = Int64.of_string ("0x" ^ s)

(*
let double_sha_byte bytestring : string =
  let once = Sha256.buffer bytestring in
  let bytestring2 = make_bytestring (Sha256.to_hex once) 0 in
  rev_string_pairs (Sha256.to_hex (Sha256.buffer bytestring2))
*)

(* let double_sha (s : string) : string =
  let bytestring = make_bytestring s 0 in
  double_sha_byte bytestring
*)

let double_sha (s : string) : string =
  (** s is NOT hex encoded *)
  hexdigits (hash (hash s))

let option_map2 (f : 'a -> 'b -> 'c) (x : 'a option) (y : 'b option) : 'c option =
  match (x,y) with
  | (None, _) -> None
  | (_, None) -> None
  | (Some a, Some b) -> Some (f a b)

let compare_hex (c1 : char) (c2 : char) : int option =
  option_map2 compare (hex_decode_char c1) (hex_decode_char c2)

let rec le_hex_string (s1 : string) (s2 : string) : bool option =
  if String.length s1 != String.length s2 then None else
    match compare_hex (String.get s1 0) (String.get s2 0) with
      | Some 0 -> let l = String.length s1 in
        le_hex_string (String.sub s1 1 (l-1)) (String.sub s2 1 (l-1))
      | Some 1 -> Some false
      | Some (-1) -> Some true
      | _ -> None

let good_enough (s : string) (diff : string) : bool =
  match le_hex_string s diff with
  | Some b -> b
  | None -> Printf.printf "error comparing strings %s %s" s diff; 
    false

let good_enough_nonce s diff =
  good_enough (double_sha s) diff

(* let big_int_rem (p : Big_int.big_int) (q : int) : int =
  Big_int.int_of_big_int (Big_int.mod_big_int p (Big_int.big_int_of_int q)) *)

let pow (b : int64) (e : int) : int64 = 
  let rec help acc e = match e with
    | 0 -> acc
    | n -> help (Int64.mul acc b) (n - 1) in
  help (Int64.of_int 1) e

let int64_to_array n size =
  let i256 : int64 = Int64.of_int 256 in
  let rec help n size digit = match digit with
    | 1 -> let result = Array.make size 0 in
      result.(size - 1) <- Int64.to_int (Int64.rem n i256);
      result
    | k -> let result = help n size (k-1) in
      let rem = Int64.rem (Int64.div n (pow i256 (digit - 1))) i256 in
      result.(size - k) <- Int64.to_int rem;
      result in
  help n size size

let copy_nonce (sref : string ref) (s : string) (nonce : int64 ref) : unit =
  sref := s ^ (Buffer.contents (pack64 !nonce))

let find_nonce (s : string) 
               (diff : string) 
               (range_start : int64)
               (range_end : int64)
               : int array option =
  let nonce = ref range_start in
  let fullstring = ref "" in
  copy_nonce fullstring s nonce;
  while not (good_enough_nonce !fullstring diff) 
    && !nonce < range_end do
    nonce := Int64.succ !nonce;
    copy_nonce fullstring s nonce
  done;
  if (good_enough_nonce !fullstring diff) 
    then Some (int64_to_array !nonce nonce_size)
    else None

let s1 = "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695"
let s2 = "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a"
let s1_nonhex = "\x01\x00\x00\x00\x81\xcd\x02\xab~V\x9e\x8b\xcd\x93\x17\xe2\xfe\x99\xf2\xdeD\xd4\x9a\xb2\xb8\x85\x1b\xa4\xa3\x08\x00\x00\x00\x00\x00\x00\xe3 \xb6\xc2\xff\xfc\x8du\x04#\xdb\x8b\x1e\xb9B\xaeq\x0e\x95\x1e\xd7\x97\xf7\xaf\xfc\x88\x92\xb0\xf1\xfc\x12+\xc7\xf5\xd7M\xf2\xb9D\x1aB\xa1F\x95"
let s2_nonhex = "\x01\x00\x00\x00\x81\xcd\x02\xab~V\x9e\x8b\xcd\x93\x17\xe2\xfe\x99\xf2\xdeD\xd4\x9a\xb2\xb8\x85\x1b\xa4\xa3\x08\x00\x00\x00\x00\x00\x00\xe3 \xb6\xc2\xff\xfc\x8du\x04#\xdb\x8b\x1e\xb9B\xaeq\x0e\x95\x1e\xd7\x97\xf7\xaf\xfc\x88\x92\xb0\xf1\xfc\x12+\xc7\xf5\xd7M\xf2\xb9D\x1a"

let difficulty = "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"
let difficulty2 = "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1c"
let difficulty3 = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
(* let result = find_nonce s2_nonhex difficulty3 (hex_string_to_int64 "00000000") (hex_string_to_int64 "ffffffff")
*)
