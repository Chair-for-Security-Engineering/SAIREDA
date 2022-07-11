circuit Sbox_andOptimized :
  module Sbox_andOptimized :
    input clock : Clock
    input reset : UInt<1>
    input io_a : UInt<1>
    input io_b : UInt<1>
    input io_c : UInt<1>
    input io_d : UInt<1>
    output io_w : UInt<1>
    output io_x : UInt<1>
    output io_y : UInt<1>
    output io_z : UInt<1>
  
    node q_0 = xor(io_b, io_d) @[Sbox.scala 46:20]
    node _T = not(q_0) @[Sbox.scala 47:15]
    node q_1 = xor(_T, io_c) @[Sbox.scala 47:20]
    node q_2 = xor(io_c, io_d) @[Sbox.scala 48:20]
    node q_8 = xor(io_a, io_b) @[Sbox.scala 49:20]
    node _T_1 = not(q_8) @[Sbox.scala 50:15]
    node q_5 = xor(_T_1, q_2) @[Sbox.scala 50:20]
    node _T_2 = not(io_a) @[Sbox.scala 51:15]
    node q_4 = xor(_T_2, io_d) @[Sbox.scala 51:21]
    node t_0 = and(q_0, q_1) @[Sbox.scala 52:19]
    node _T_3 = xor(q_8, io_c) @[Sbox.scala 53:19]
    node q_3 = xor(_T_3, t_0) @[Sbox.scala 53:26]
    node t_1 = and(q_2, q_3) @[Sbox.scala 54:19]
    node t_2 = and(q_4, q_5) @[Sbox.scala 55:19]
    node q_7 = xor(io_c, t_2) @[Sbox.scala 56:20]
    node _T_4 = not(io_d) @[Sbox.scala 57:16]
    node t_3 = and(_T_4, q_7) @[Sbox.scala 57:23]
    node q_9 = xor(io_a, t_2) @[Sbox.scala 58:20]
    node t_4 = and(q_8, q_9) @[Sbox.scala 59:19]
    node _T_5 = xor(q_4, t_0) @[Sbox.scala 60:20]
    node q_10 = xor(_T_5, t_2) @[Sbox.scala 60:26]
    node q_11 = xor(q_4, io_c) @[Sbox.scala 61:20]
    node t_5 = and(q_10, q_11) @[Sbox.scala 62:20]
    node l_3 = xor(t_1, t_2) @[Sbox.scala 63:19]
    node l_4 = xor(t_3, t_4) @[Sbox.scala 64:19]
    node l_5 = xor(l_3, l_4) @[Sbox.scala 65:19]
    node _T_6 = xor(q_0, t_0) @[Sbox.scala 66:17]
    node _T_7 = xor(_T_6, t_1) @[Sbox.scala 66:23]
    node _T_8 = xor(_T_7, t_3) @[Sbox.scala 66:29]
    node _T_9 = xor(q_0, l_5) @[Sbox.scala 67:17]
    node _T_10 = xor(_T_9, t_5) @[Sbox.scala 67:23]
    node _T_11 = xor(q_0, l_4) @[Sbox.scala 68:17]
    node _T_12 = xor(io_d, t_0) @[Sbox.scala 69:18]
    node _T_13 = xor(_T_12, l_3) @[Sbox.scala 69:24]
    io_w <= _T_8 @[Sbox.scala 66:10]
    io_x <= _T_10 @[Sbox.scala 67:10]
    io_y <= _T_11 @[Sbox.scala 68:10]
    io_z <= _T_13 @[Sbox.scala 69:10]
