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

let hex_string_to_big_int s =
  Big_int.sys_big_int_of_string ("0x" ^ s) 0 (String.length s + 2)

let double_sha_byte bytestring : string =
  let once = Sha256.buffer bytestring in
  let bytestring2 = make_bytestring (Sha256.to_hex once) 0 in
  rev_string_pairs (Sha256.to_hex (Sha256.buffer bytestring2))

let double_sha (s : string) : string =
  let bytestring = make_bytestring s 0 in
  double_sha_byte bytestring 

let good_enough (s : string) (n : Big_int.big_int) : bool =
  Big_int.le_big_int (hex_string_to_big_int s) n

let good_enough_byte b n =
  good_enough (double_sha_byte b) n

let big_int_rem (p : Big_int.big_int) (q : int) : int =
  Big_int.int_of_big_int (Big_int.mod_big_int p (Big_int.big_int_of_int q))

let big_int_to_array n size =
  let rec help n size digit = match digit with
    | 1 -> let result = Array.make size 0 in
      result.(size - 1) <- big_int_rem n 256;
      result
    | k -> let result = help n size (k-1) in
      let rem = big_int_rem (Big_int.div_big_int n (Big_int.power_int_positive_int 256 (digit - 1))) 256 in
      result.(size - k) <- rem;
      result in
  help n size size

let copy_nonce bytestring (nonce : Big_int.big_int ref) l : unit =
    let nonce_bs = big_int_to_array !nonce nonce_size in
    for i = 0 to nonce_size - 1 do
      bytestring.{l + i} <- nonce_bs.(i)
    done

let find_nonce (s : string) (diff : Big_int.big_int) =
  let bytestring = make_bytestring s nonce_size in
  let l = String.length s / 2 in
  let nonce = ref (Big_int.big_int_of_int 0) in
  copy_nonce bytestring nonce l;
  while not (good_enough_byte bytestring diff) do
    nonce := Big_int.succ_big_int !nonce;
    copy_nonce bytestring nonce l
  done;
  big_int_to_array !nonce nonce_size


let s1 = "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a42a14695"
let s2 = "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122bc7f5d74df2b9441a"
let difficulty = hex_string_to_big_int 
  "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"
let difficulty2 = hex_string_to_big_int
  "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1c"
let difficulty3 = hex_string_to_big_int
  "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
let result = find_nonce s2 difficulty3

(* let () =
  Core.Std.printf "%s\n" (double_sha s1);
  Core.Std.printf "%b\n" (good_enough (double_sha s1) difficulty2); *)

