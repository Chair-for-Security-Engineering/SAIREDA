circuit Sbox_canright :
  module Sbox_canright :
    input clock : Clock
    input reset : UInt<1>
    input io_i0 : UInt<1>
    input io_i1 : UInt<1>
    input io_i2 : UInt<1>
    input io_i3 : UInt<1>
    input io_i4 : UInt<1>
    input io_i5 : UInt<1>
    input io_i6 : UInt<1>
    input io_i7 : UInt<1>
    output io_o0 : UInt<1>
    output io_o1 : UInt<1>
    output io_o2 : UInt<1>
    output io_o3 : UInt<1>
    output io_o4 : UInt<1>
    output io_o5 : UInt<1>
    output io_o6 : UInt<1>
    output io_o7 : UInt<1>
  
    wire inv_clock : Clock
    wire inv_reset : UInt<1>
    wire inv_io_i0 : UInt<1>
    wire inv_io_i1 : UInt<1>
    wire inv_io_i2 : UInt<1>
    wire inv_io_i3 : UInt<1>
    wire inv_io_i4 : UInt<1>
    wire inv_io_i5 : UInt<1>
    wire inv_io_i6 : UInt<1>
    wire inv_io_i7 : UInt<1>
    wire inv_io_o0 : UInt<1>
    wire inv_io_o1 : UInt<1>
    wire inv_io_o2 : UInt<1>
    wire inv_io_o3 : UInt<1>
    wire inv_io_o4 : UInt<1>
    wire inv_io_o5 : UInt<1>
    wire inv_io_o6 : UInt<1>
    wire inv_io_o7 : UInt<1>
    wire inv_d_inv_clock : Clock
    wire inv_d_inv_reset : UInt<1>
    wire inv_d_inv_io_i0 : UInt<1>
    wire inv_d_inv_io_i1 : UInt<1>
    wire inv_d_inv_io_i2 : UInt<1>
    wire inv_d_inv_io_i3 : UInt<1>
    wire inv_d_inv_io_o0 : UInt<1>
    wire inv_d_inv_io_o1 : UInt<1>
    wire inv_d_inv_io_o2 : UInt<1>
    wire inv_d_inv_io_o3 : UInt<1>
    wire inv_d_inv_d_inv_clock : Clock
    wire inv_d_inv_d_inv_reset : UInt<1>
    wire inv_d_inv_d_inv_io_i0 : UInt<1>
    wire inv_d_inv_d_inv_io_i1 : UInt<1>
    wire inv_d_inv_d_inv_io_o0 : UInt<1>
    wire inv_d_inv_d_inv_io_o1 : UInt<1>
    inv_d_inv_d_inv_io_o0 <= inv_d_inv_d_inv_io_i1 @[Sbox.scala 13:11]
    inv_d_inv_d_inv_io_o1 <= inv_d_inv_d_inv_io_i0 @[Sbox.scala 14:11]
    wire inv_d_inv_p_mul_clock : Clock
    wire inv_d_inv_p_mul_reset : UInt<1>
    wire inv_d_inv_p_mul_io_a0 : UInt<1>
    wire inv_d_inv_p_mul_io_a1 : UInt<1>
    wire inv_d_inv_p_mul_io_ab : UInt<1>
    wire inv_d_inv_p_mul_io_b0 : UInt<1>
    wire inv_d_inv_p_mul_io_b1 : UInt<1>
    wire inv_d_inv_p_mul_io_cd : UInt<1>
    wire inv_d_inv_p_mul_io_o0 : UInt<1>
    wire inv_d_inv_p_mul_io_o1 : UInt<1>
    node inv_d_inv_p_mul__T = and(inv_d_inv_p_mul_io_ab, inv_d_inv_p_mul_io_cd) @[Sbox.scala 52:21]
    node inv_d_inv_p_mul_t = not(inv_d_inv_p_mul__T) @[Sbox.scala 52:13]
    node inv_d_inv_p_mul__T_1 = and(inv_d_inv_p_mul_io_a1, inv_d_inv_p_mul_io_b1) @[Sbox.scala 53:23]
    node inv_d_inv_p_mul__T_2 = not(inv_d_inv_p_mul__T_1) @[Sbox.scala 53:15]
    node inv_d_inv_p_mul__T_3 = xor(inv_d_inv_p_mul__T_2, inv_d_inv_p_mul_t) @[Sbox.scala 53:33]
    node inv_d_inv_p_mul__T_4 = and(inv_d_inv_p_mul_io_a0, inv_d_inv_p_mul_io_b0) @[Sbox.scala 54:23]
    node inv_d_inv_p_mul__T_5 = not(inv_d_inv_p_mul__T_4) @[Sbox.scala 54:15]
    node inv_d_inv_p_mul__T_6 = xor(inv_d_inv_p_mul__T_5, inv_d_inv_p_mul_t) @[Sbox.scala 54:33]
    inv_d_inv_p_mul_io_o0 <= inv_d_inv_p_mul__T_6 @[Sbox.scala 54:11]
    inv_d_inv_p_mul_io_o1 <= inv_d_inv_p_mul__T_3 @[Sbox.scala 53:11]
    wire inv_d_inv_q_mul_clock : Clock
    wire inv_d_inv_q_mul_reset : UInt<1>
    wire inv_d_inv_q_mul_io_a0 : UInt<1>
    wire inv_d_inv_q_mul_io_a1 : UInt<1>
    wire inv_d_inv_q_mul_io_ab : UInt<1>
    wire inv_d_inv_q_mul_io_b0 : UInt<1>
    wire inv_d_inv_q_mul_io_b1 : UInt<1>
    wire inv_d_inv_q_mul_io_cd : UInt<1>
    wire inv_d_inv_q_mul_io_o0 : UInt<1>
    wire inv_d_inv_q_mul_io_o1 : UInt<1>
    node inv_d_inv_q_mul__T = and(inv_d_inv_q_mul_io_ab, inv_d_inv_q_mul_io_cd) @[Sbox.scala 52:21]
    node inv_d_inv_q_mul_t = not(inv_d_inv_q_mul__T) @[Sbox.scala 52:13]
    node inv_d_inv_q_mul__T_1 = and(inv_d_inv_q_mul_io_a1, inv_d_inv_q_mul_io_b1) @[Sbox.scala 53:23]
    node inv_d_inv_q_mul__T_2 = not(inv_d_inv_q_mul__T_1) @[Sbox.scala 53:15]
    node inv_d_inv_q_mul__T_3 = xor(inv_d_inv_q_mul__T_2, inv_d_inv_q_mul_t) @[Sbox.scala 53:33]
    node inv_d_inv_q_mul__T_4 = and(inv_d_inv_q_mul_io_a0, inv_d_inv_q_mul_io_b0) @[Sbox.scala 54:23]
    node inv_d_inv_q_mul__T_5 = not(inv_d_inv_q_mul__T_4) @[Sbox.scala 54:15]
    node inv_d_inv_q_mul__T_6 = xor(inv_d_inv_q_mul__T_5, inv_d_inv_q_mul_t) @[Sbox.scala 54:33]
    inv_d_inv_q_mul_io_o0 <= inv_d_inv_q_mul__T_6 @[Sbox.scala 54:11]
    inv_d_inv_q_mul_io_o1 <= inv_d_inv_q_mul__T_3 @[Sbox.scala 53:11]
    node inv_d_inv_sa = xor(inv_d_inv_io_i3, inv_d_inv_io_i2) @[Sbox.scala 90:17]
    node inv_d_inv_sb = xor(inv_d_inv_io_i1, inv_d_inv_io_i0) @[Sbox.scala 91:17]
    node inv_d_inv__T = or(inv_d_inv_io_i3, inv_d_inv_io_i1) @[Sbox.scala 93:19]
    node inv_d_inv__T_1 = not(inv_d_inv__T) @[Sbox.scala 93:14]
    node inv_d_inv__T_2 = and(inv_d_inv_sa, inv_d_inv_sb) @[Sbox.scala 93:33]
    node inv_d_inv__T_3 = not(inv_d_inv__T_2) @[Sbox.scala 93:28]
    node inv_d_inv_c1 = xor(inv_d_inv__T_1, inv_d_inv__T_3) @[Sbox.scala 93:25]
    node inv_d_inv__T_4 = or(inv_d_inv_sa, inv_d_inv_sb) @[Sbox.scala 94:19]
    node inv_d_inv__T_5 = not(inv_d_inv__T_4) @[Sbox.scala 94:14]
    node inv_d_inv__T_6 = and(inv_d_inv_io_i2, inv_d_inv_io_i0) @[Sbox.scala 94:33]
    node inv_d_inv__T_7 = not(inv_d_inv__T_6) @[Sbox.scala 94:28]
    node inv_d_inv_c0 = xor(inv_d_inv__T_5, inv_d_inv__T_7) @[Sbox.scala 94:25]
    node inv_d_inv_sd = xor(inv_d_inv_d_inv_io_o1, inv_d_inv_d_inv_io_o0) @[Sbox.scala 102:17]
    inv_d_inv_io_o0 <= inv_d_inv_q_mul_io_o0 @[Sbox.scala 124:11]
    inv_d_inv_io_o1 <= inv_d_inv_q_mul_io_o1 @[Sbox.scala 125:11]
    inv_d_inv_io_o2 <= inv_d_inv_p_mul_io_o0 @[Sbox.scala 126:11]
    inv_d_inv_io_o3 <= inv_d_inv_p_mul_io_o1 @[Sbox.scala 127:11]
    inv_d_inv_d_inv_clock <= inv_d_inv_clock
    inv_d_inv_d_inv_reset <= inv_d_inv_reset
    inv_d_inv_d_inv_io_i0 <= inv_d_inv_c0 @[Sbox.scala 97:17]
    inv_d_inv_d_inv_io_i1 <= inv_d_inv_c1 @[Sbox.scala 98:17]
    inv_d_inv_p_mul_clock <= inv_d_inv_clock
    inv_d_inv_p_mul_reset <= inv_d_inv_reset
    inv_d_inv_p_mul_io_a0 <= inv_d_inv_d_inv_io_o0 @[Sbox.scala 105:17]
    inv_d_inv_p_mul_io_a1 <= inv_d_inv_d_inv_io_o1 @[Sbox.scala 106:17]
    inv_d_inv_p_mul_io_ab <= inv_d_inv_sd @[Sbox.scala 107:17]
    inv_d_inv_p_mul_io_b0 <= inv_d_inv_io_i0 @[Sbox.scala 108:17]
    inv_d_inv_p_mul_io_b1 <= inv_d_inv_io_i1 @[Sbox.scala 109:17]
    inv_d_inv_p_mul_io_cd <= inv_d_inv_sb @[Sbox.scala 110:17]
    inv_d_inv_q_mul_clock <= inv_d_inv_clock
    inv_d_inv_q_mul_reset <= inv_d_inv_reset
    inv_d_inv_q_mul_io_a0 <= inv_d_inv_d_inv_io_o0 @[Sbox.scala 115:17]
    inv_d_inv_q_mul_io_a1 <= inv_d_inv_d_inv_io_o1 @[Sbox.scala 116:17]
    inv_d_inv_q_mul_io_ab <= inv_d_inv_sd @[Sbox.scala 117:17]
    inv_d_inv_q_mul_io_b0 <= inv_d_inv_io_i2 @[Sbox.scala 118:17]
    inv_d_inv_q_mul_io_b1 <= inv_d_inv_io_i3 @[Sbox.scala 119:17]
    inv_d_inv_q_mul_io_cd <= inv_d_inv_sa @[Sbox.scala 120:17]
    wire inv_p_mul_clock : Clock
    wire inv_p_mul_reset : UInt<1>
    wire inv_p_mul_io_A0 : UInt<1>
    wire inv_p_mul_io_A1 : UInt<1>
    wire inv_p_mul_io_A2 : UInt<1>
    wire inv_p_mul_io_A3 : UInt<1>
    wire inv_p_mul_io_a0 : UInt<1>
    wire inv_p_mul_io_a1 : UInt<1>
    wire inv_p_mul_io_Al : UInt<1>
    wire inv_p_mul_io_Ah : UInt<1>
    wire inv_p_mul_io_aa : UInt<1>
    wire inv_p_mul_io_B0 : UInt<1>
    wire inv_p_mul_io_B1 : UInt<1>
    wire inv_p_mul_io_B2 : UInt<1>
    wire inv_p_mul_io_B3 : UInt<1>
    wire inv_p_mul_io_b0 : UInt<1>
    wire inv_p_mul_io_b1 : UInt<1>
    wire inv_p_mul_io_Bl : UInt<1>
    wire inv_p_mul_io_Bh : UInt<1>
    wire inv_p_mul_io_bb : UInt<1>
    wire inv_p_mul_io_o0 : UInt<1>
    wire inv_p_mul_io_o1 : UInt<1>
    wire inv_p_mul_io_o2 : UInt<1>
    wire inv_p_mul_io_o3 : UInt<1>
    wire inv_p_mul_hi_mul_clock : Clock
    wire inv_p_mul_hi_mul_reset : UInt<1>
    wire inv_p_mul_hi_mul_io_a0 : UInt<1>
    wire inv_p_mul_hi_mul_io_a1 : UInt<1>
    wire inv_p_mul_hi_mul_io_ab : UInt<1>
    wire inv_p_mul_hi_mul_io_b0 : UInt<1>
    wire inv_p_mul_hi_mul_io_b1 : UInt<1>
    wire inv_p_mul_hi_mul_io_cd : UInt<1>
    wire inv_p_mul_hi_mul_io_o0 : UInt<1>
    wire inv_p_mul_hi_mul_io_o1 : UInt<1>
    node inv_p_mul_hi_mul__T = and(inv_p_mul_hi_mul_io_ab, inv_p_mul_hi_mul_io_cd) @[Sbox.scala 52:21]
    node inv_p_mul_hi_mul_t = not(inv_p_mul_hi_mul__T) @[Sbox.scala 52:13]
    node inv_p_mul_hi_mul__T_1 = and(inv_p_mul_hi_mul_io_a1, inv_p_mul_hi_mul_io_b1) @[Sbox.scala 53:23]
    node inv_p_mul_hi_mul__T_2 = not(inv_p_mul_hi_mul__T_1) @[Sbox.scala 53:15]
    node inv_p_mul_hi_mul__T_3 = xor(inv_p_mul_hi_mul__T_2, inv_p_mul_hi_mul_t) @[Sbox.scala 53:33]
    node inv_p_mul_hi_mul__T_4 = and(inv_p_mul_hi_mul_io_a0, inv_p_mul_hi_mul_io_b0) @[Sbox.scala 54:23]
    node inv_p_mul_hi_mul__T_5 = not(inv_p_mul_hi_mul__T_4) @[Sbox.scala 54:15]
    node inv_p_mul_hi_mul__T_6 = xor(inv_p_mul_hi_mul__T_5, inv_p_mul_hi_mul_t) @[Sbox.scala 54:33]
    inv_p_mul_hi_mul_io_o0 <= inv_p_mul_hi_mul__T_6 @[Sbox.scala 54:11]
    inv_p_mul_hi_mul_io_o1 <= inv_p_mul_hi_mul__T_3 @[Sbox.scala 53:11]
    wire inv_p_mul_lo_mul_clock : Clock
    wire inv_p_mul_lo_mul_reset : UInt<1>
    wire inv_p_mul_lo_mul_io_a0 : UInt<1>
    wire inv_p_mul_lo_mul_io_a1 : UInt<1>
    wire inv_p_mul_lo_mul_io_ab : UInt<1>
    wire inv_p_mul_lo_mul_io_b0 : UInt<1>
    wire inv_p_mul_lo_mul_io_b1 : UInt<1>
    wire inv_p_mul_lo_mul_io_cd : UInt<1>
    wire inv_p_mul_lo_mul_io_o0 : UInt<1>
    wire inv_p_mul_lo_mul_io_o1 : UInt<1>
    node inv_p_mul_lo_mul__T = and(inv_p_mul_lo_mul_io_ab, inv_p_mul_lo_mul_io_cd) @[Sbox.scala 52:21]
    node inv_p_mul_lo_mul_t = not(inv_p_mul_lo_mul__T) @[Sbox.scala 52:13]
    node inv_p_mul_lo_mul__T_1 = and(inv_p_mul_lo_mul_io_a1, inv_p_mul_lo_mul_io_b1) @[Sbox.scala 53:23]
    node inv_p_mul_lo_mul__T_2 = not(inv_p_mul_lo_mul__T_1) @[Sbox.scala 53:15]
    node inv_p_mul_lo_mul__T_3 = xor(inv_p_mul_lo_mul__T_2, inv_p_mul_lo_mul_t) @[Sbox.scala 53:33]
    node inv_p_mul_lo_mul__T_4 = and(inv_p_mul_lo_mul_io_a0, inv_p_mul_lo_mul_io_b0) @[Sbox.scala 54:23]
    node inv_p_mul_lo_mul__T_5 = not(inv_p_mul_lo_mul__T_4) @[Sbox.scala 54:15]
    node inv_p_mul_lo_mul__T_6 = xor(inv_p_mul_lo_mul__T_5, inv_p_mul_lo_mul_t) @[Sbox.scala 54:33]
    inv_p_mul_lo_mul_io_o0 <= inv_p_mul_lo_mul__T_6 @[Sbox.scala 54:11]
    inv_p_mul_lo_mul_io_o1 <= inv_p_mul_lo_mul__T_3 @[Sbox.scala 53:11]
    wire inv_p_mul_sum_mul_clock : Clock
    wire inv_p_mul_sum_mul_reset : UInt<1>
    wire inv_p_mul_sum_mul_io_a0 : UInt<1>
    wire inv_p_mul_sum_mul_io_a1 : UInt<1>
    wire inv_p_mul_sum_mul_io_ab : UInt<1>
    wire inv_p_mul_sum_mul_io_b0 : UInt<1>
    wire inv_p_mul_sum_mul_io_b1 : UInt<1>
    wire inv_p_mul_sum_mul_io_cd : UInt<1>
    wire inv_p_mul_sum_mul_io_o0 : UInt<1>
    wire inv_p_mul_sum_mul_io_o1 : UInt<1>
    node inv_p_mul_sum_mul__T = and(inv_p_mul_sum_mul_io_a0, inv_p_mul_sum_mul_io_b0) @[Sbox.scala 69:21]
    node inv_p_mul_sum_mul_t = not(inv_p_mul_sum_mul__T) @[Sbox.scala 69:13]
    node inv_p_mul_sum_mul__T_1 = and(inv_p_mul_sum_mul_io_ab, inv_p_mul_sum_mul_io_cd) @[Sbox.scala 70:23]
    node inv_p_mul_sum_mul__T_2 = not(inv_p_mul_sum_mul__T_1) @[Sbox.scala 70:15]
    node inv_p_mul_sum_mul__T_3 = xor(inv_p_mul_sum_mul__T_2, inv_p_mul_sum_mul_t) @[Sbox.scala 70:33]
    node inv_p_mul_sum_mul__T_4 = and(inv_p_mul_sum_mul_io_a1, inv_p_mul_sum_mul_io_b1) @[Sbox.scala 71:23]
    node inv_p_mul_sum_mul__T_5 = not(inv_p_mul_sum_mul__T_4) @[Sbox.scala 71:15]
    node inv_p_mul_sum_mul__T_6 = xor(inv_p_mul_sum_mul__T_5, inv_p_mul_sum_mul_t) @[Sbox.scala 71:33]
    inv_p_mul_sum_mul_io_o0 <= inv_p_mul_sum_mul__T_6 @[Sbox.scala 71:11]
    inv_p_mul_sum_mul_io_o1 <= inv_p_mul_sum_mul__T_3 @[Sbox.scala 70:11]
    node inv_p_mul__T = xor(inv_p_mul_lo_mul_io_o0, inv_p_mul_sum_mul_io_o0) @[Sbox.scala 228:18]
    node inv_p_mul__T_1 = xor(inv_p_mul_lo_mul_io_o1, inv_p_mul_sum_mul_io_o1) @[Sbox.scala 229:18]
    node inv_p_mul__T_2 = xor(inv_p_mul_hi_mul_io_o0, inv_p_mul_sum_mul_io_o0) @[Sbox.scala 230:18]
    node inv_p_mul__T_3 = xor(inv_p_mul_hi_mul_io_o1, inv_p_mul_sum_mul_io_o1) @[Sbox.scala 231:18]
    inv_p_mul_io_o0 <= inv_p_mul__T @[Sbox.scala 228:11]
    inv_p_mul_io_o1 <= inv_p_mul__T_1 @[Sbox.scala 229:11]
    inv_p_mul_io_o2 <= inv_p_mul__T_2 @[Sbox.scala 230:11]
    inv_p_mul_io_o3 <= inv_p_mul__T_3 @[Sbox.scala 231:11]
    inv_p_mul_hi_mul_clock <= inv_p_mul_clock
    inv_p_mul_hi_mul_reset <= inv_p_mul_reset
    inv_p_mul_hi_mul_io_a0 <= inv_p_mul_io_A2 @[Sbox.scala 199:18]
    inv_p_mul_hi_mul_io_a1 <= inv_p_mul_io_A3 @[Sbox.scala 200:18]
    inv_p_mul_hi_mul_io_ab <= inv_p_mul_io_Ah @[Sbox.scala 201:18]
    inv_p_mul_hi_mul_io_b0 <= inv_p_mul_io_B2 @[Sbox.scala 202:18]
    inv_p_mul_hi_mul_io_b1 <= inv_p_mul_io_B3 @[Sbox.scala 203:18]
    inv_p_mul_hi_mul_io_cd <= inv_p_mul_io_Bh @[Sbox.scala 204:18]
    inv_p_mul_lo_mul_clock <= inv_p_mul_clock
    inv_p_mul_lo_mul_reset <= inv_p_mul_reset
    inv_p_mul_lo_mul_io_a0 <= inv_p_mul_io_A0 @[Sbox.scala 209:18]
    inv_p_mul_lo_mul_io_a1 <= inv_p_mul_io_A1 @[Sbox.scala 210:18]
    inv_p_mul_lo_mul_io_ab <= inv_p_mul_io_Al @[Sbox.scala 211:18]
    inv_p_mul_lo_mul_io_b0 <= inv_p_mul_io_B0 @[Sbox.scala 212:18]
    inv_p_mul_lo_mul_io_b1 <= inv_p_mul_io_B1 @[Sbox.scala 213:18]
    inv_p_mul_lo_mul_io_cd <= inv_p_mul_io_Bl @[Sbox.scala 214:18]
    inv_p_mul_sum_mul_clock <= inv_p_mul_clock
    inv_p_mul_sum_mul_reset <= inv_p_mul_reset
    inv_p_mul_sum_mul_io_a0 <= inv_p_mul_io_a0 @[Sbox.scala 219:19]
    inv_p_mul_sum_mul_io_a1 <= inv_p_mul_io_a1 @[Sbox.scala 220:19]
    inv_p_mul_sum_mul_io_ab <= inv_p_mul_io_aa @[Sbox.scala 221:19]
    inv_p_mul_sum_mul_io_b0 <= inv_p_mul_io_b0 @[Sbox.scala 222:19]
    inv_p_mul_sum_mul_io_b1 <= inv_p_mul_io_b1 @[Sbox.scala 223:19]
    inv_p_mul_sum_mul_io_cd <= inv_p_mul_io_bb @[Sbox.scala 224:19]
    wire inv_q_mul_clock : Clock
    wire inv_q_mul_reset : UInt<1>
    wire inv_q_mul_io_A0 : UInt<1>
    wire inv_q_mul_io_A1 : UInt<1>
    wire inv_q_mul_io_A2 : UInt<1>
    wire inv_q_mul_io_A3 : UInt<1>
    wire inv_q_mul_io_a0 : UInt<1>
    wire inv_q_mul_io_a1 : UInt<1>
    wire inv_q_mul_io_Al : UInt<1>
    wire inv_q_mul_io_Ah : UInt<1>
    wire inv_q_mul_io_aa : UInt<1>
    wire inv_q_mul_io_B0 : UInt<1>
    wire inv_q_mul_io_B1 : UInt<1>
    wire inv_q_mul_io_B2 : UInt<1>
    wire inv_q_mul_io_B3 : UInt<1>
    wire inv_q_mul_io_b0 : UInt<1>
    wire inv_q_mul_io_b1 : UInt<1>
    wire inv_q_mul_io_Bl : UInt<1>
    wire inv_q_mul_io_Bh : UInt<1>
    wire inv_q_mul_io_bb : UInt<1>
    wire inv_q_mul_io_o0 : UInt<1>
    wire inv_q_mul_io_o1 : UInt<1>
    wire inv_q_mul_io_o2 : UInt<1>
    wire inv_q_mul_io_o3 : UInt<1>
    wire inv_q_mul_hi_mul_clock : Clock
    wire inv_q_mul_hi_mul_reset : UInt<1>
    wire inv_q_mul_hi_mul_io_a0 : UInt<1>
    wire inv_q_mul_hi_mul_io_a1 : UInt<1>
    wire inv_q_mul_hi_mul_io_ab : UInt<1>
    wire inv_q_mul_hi_mul_io_b0 : UInt<1>
    wire inv_q_mul_hi_mul_io_b1 : UInt<1>
    wire inv_q_mul_hi_mul_io_cd : UInt<1>
    wire inv_q_mul_hi_mul_io_o0 : UInt<1>
    wire inv_q_mul_hi_mul_io_o1 : UInt<1>
    node inv_q_mul_hi_mul__T = and(inv_q_mul_hi_mul_io_ab, inv_q_mul_hi_mul_io_cd) @[Sbox.scala 52:21]
    node inv_q_mul_hi_mul_t = not(inv_q_mul_hi_mul__T) @[Sbox.scala 52:13]
    node inv_q_mul_hi_mul__T_1 = and(inv_q_mul_hi_mul_io_a1, inv_q_mul_hi_mul_io_b1) @[Sbox.scala 53:23]
    node inv_q_mul_hi_mul__T_2 = not(inv_q_mul_hi_mul__T_1) @[Sbox.scala 53:15]
    node inv_q_mul_hi_mul__T_3 = xor(inv_q_mul_hi_mul__T_2, inv_q_mul_hi_mul_t) @[Sbox.scala 53:33]
    node inv_q_mul_hi_mul__T_4 = and(inv_q_mul_hi_mul_io_a0, inv_q_mul_hi_mul_io_b0) @[Sbox.scala 54:23]
    node inv_q_mul_hi_mul__T_5 = not(inv_q_mul_hi_mul__T_4) @[Sbox.scala 54:15]
    node inv_q_mul_hi_mul__T_6 = xor(inv_q_mul_hi_mul__T_5, inv_q_mul_hi_mul_t) @[Sbox.scala 54:33]
    inv_q_mul_hi_mul_io_o0 <= inv_q_mul_hi_mul__T_6 @[Sbox.scala 54:11]
    inv_q_mul_hi_mul_io_o1 <= inv_q_mul_hi_mul__T_3 @[Sbox.scala 53:11]
    wire inv_q_mul_lo_mul_clock : Clock
    wire inv_q_mul_lo_mul_reset : UInt<1>
    wire inv_q_mul_lo_mul_io_a0 : UInt<1>
    wire inv_q_mul_lo_mul_io_a1 : UInt<1>
    wire inv_q_mul_lo_mul_io_ab : UInt<1>
    wire inv_q_mul_lo_mul_io_b0 : UInt<1>
    wire inv_q_mul_lo_mul_io_b1 : UInt<1>
    wire inv_q_mul_lo_mul_io_cd : UInt<1>
    wire inv_q_mul_lo_mul_io_o0 : UInt<1>
    wire inv_q_mul_lo_mul_io_o1 : UInt<1>
    node inv_q_mul_lo_mul__T = and(inv_q_mul_lo_mul_io_ab, inv_q_mul_lo_mul_io_cd) @[Sbox.scala 52:21]
    node inv_q_mul_lo_mul_t = not(inv_q_mul_lo_mul__T) @[Sbox.scala 52:13]
    node inv_q_mul_lo_mul__T_1 = and(inv_q_mul_lo_mul_io_a1, inv_q_mul_lo_mul_io_b1) @[Sbox.scala 53:23]
    node inv_q_mul_lo_mul__T_2 = not(inv_q_mul_lo_mul__T_1) @[Sbox.scala 53:15]
    node inv_q_mul_lo_mul__T_3 = xor(inv_q_mul_lo_mul__T_2, inv_q_mul_lo_mul_t) @[Sbox.scala 53:33]
    node inv_q_mul_lo_mul__T_4 = and(inv_q_mul_lo_mul_io_a0, inv_q_mul_lo_mul_io_b0) @[Sbox.scala 54:23]
    node inv_q_mul_lo_mul__T_5 = not(inv_q_mul_lo_mul__T_4) @[Sbox.scala 54:15]
    node inv_q_mul_lo_mul__T_6 = xor(inv_q_mul_lo_mul__T_5, inv_q_mul_lo_mul_t) @[Sbox.scala 54:33]
    inv_q_mul_lo_mul_io_o0 <= inv_q_mul_lo_mul__T_6 @[Sbox.scala 54:11]
    inv_q_mul_lo_mul_io_o1 <= inv_q_mul_lo_mul__T_3 @[Sbox.scala 53:11]
    wire inv_q_mul_sum_mul_clock : Clock
    wire inv_q_mul_sum_mul_reset : UInt<1>
    wire inv_q_mul_sum_mul_io_a0 : UInt<1>
    wire inv_q_mul_sum_mul_io_a1 : UInt<1>
    wire inv_q_mul_sum_mul_io_ab : UInt<1>
    wire inv_q_mul_sum_mul_io_b0 : UInt<1>
    wire inv_q_mul_sum_mul_io_b1 : UInt<1>
    wire inv_q_mul_sum_mul_io_cd : UInt<1>
    wire inv_q_mul_sum_mul_io_o0 : UInt<1>
    wire inv_q_mul_sum_mul_io_o1 : UInt<1>
    node inv_q_mul_sum_mul__T = and(inv_q_mul_sum_mul_io_a0, inv_q_mul_sum_mul_io_b0) @[Sbox.scala 69:21]
    node inv_q_mul_sum_mul_t = not(inv_q_mul_sum_mul__T) @[Sbox.scala 69:13]
    node inv_q_mul_sum_mul__T_1 = and(inv_q_mul_sum_mul_io_ab, inv_q_mul_sum_mul_io_cd) @[Sbox.scala 70:23]
    node inv_q_mul_sum_mul__T_2 = not(inv_q_mul_sum_mul__T_1) @[Sbox.scala 70:15]
    node inv_q_mul_sum_mul__T_3 = xor(inv_q_mul_sum_mul__T_2, inv_q_mul_sum_mul_t) @[Sbox.scala 70:33]
    node inv_q_mul_sum_mul__T_4 = and(inv_q_mul_sum_mul_io_a1, inv_q_mul_sum_mul_io_b1) @[Sbox.scala 71:23]
    node inv_q_mul_sum_mul__T_5 = not(inv_q_mul_sum_mul__T_4) @[Sbox.scala 71:15]
    node inv_q_mul_sum_mul__T_6 = xor(inv_q_mul_sum_mul__T_5, inv_q_mul_sum_mul_t) @[Sbox.scala 71:33]
    inv_q_mul_sum_mul_io_o0 <= inv_q_mul_sum_mul__T_6 @[Sbox.scala 71:11]
    inv_q_mul_sum_mul_io_o1 <= inv_q_mul_sum_mul__T_3 @[Sbox.scala 70:11]
    node inv_q_mul__T = xor(inv_q_mul_lo_mul_io_o0, inv_q_mul_sum_mul_io_o0) @[Sbox.scala 228:18]
    node inv_q_mul__T_1 = xor(inv_q_mul_lo_mul_io_o1, inv_q_mul_sum_mul_io_o1) @[Sbox.scala 229:18]
    node inv_q_mul__T_2 = xor(inv_q_mul_hi_mul_io_o0, inv_q_mul_sum_mul_io_o0) @[Sbox.scala 230:18]
    node inv_q_mul__T_3 = xor(inv_q_mul_hi_mul_io_o1, inv_q_mul_sum_mul_io_o1) @[Sbox.scala 231:18]
    inv_q_mul_io_o0 <= inv_q_mul__T @[Sbox.scala 228:11]
    inv_q_mul_io_o1 <= inv_q_mul__T_1 @[Sbox.scala 229:11]
    inv_q_mul_io_o2 <= inv_q_mul__T_2 @[Sbox.scala 230:11]
    inv_q_mul_io_o3 <= inv_q_mul__T_3 @[Sbox.scala 231:11]
    inv_q_mul_hi_mul_clock <= inv_q_mul_clock
    inv_q_mul_hi_mul_reset <= inv_q_mul_reset
    inv_q_mul_hi_mul_io_a0 <= inv_q_mul_io_A2 @[Sbox.scala 199:18]
    inv_q_mul_hi_mul_io_a1 <= inv_q_mul_io_A3 @[Sbox.scala 200:18]
    inv_q_mul_hi_mul_io_ab <= inv_q_mul_io_Ah @[Sbox.scala 201:18]
    inv_q_mul_hi_mul_io_b0 <= inv_q_mul_io_B2 @[Sbox.scala 202:18]
    inv_q_mul_hi_mul_io_b1 <= inv_q_mul_io_B3 @[Sbox.scala 203:18]
    inv_q_mul_hi_mul_io_cd <= inv_q_mul_io_Bh @[Sbox.scala 204:18]
    inv_q_mul_lo_mul_clock <= inv_q_mul_clock
    inv_q_mul_lo_mul_reset <= inv_q_mul_reset
    inv_q_mul_lo_mul_io_a0 <= inv_q_mul_io_A0 @[Sbox.scala 209:18]
    inv_q_mul_lo_mul_io_a1 <= inv_q_mul_io_A1 @[Sbox.scala 210:18]
    inv_q_mul_lo_mul_io_ab <= inv_q_mul_io_Al @[Sbox.scala 211:18]
    inv_q_mul_lo_mul_io_b0 <= inv_q_mul_io_B0 @[Sbox.scala 212:18]
    inv_q_mul_lo_mul_io_b1 <= inv_q_mul_io_B1 @[Sbox.scala 213:18]
    inv_q_mul_lo_mul_io_cd <= inv_q_mul_io_Bl @[Sbox.scala 214:18]
    inv_q_mul_sum_mul_clock <= inv_q_mul_clock
    inv_q_mul_sum_mul_reset <= inv_q_mul_reset
    inv_q_mul_sum_mul_io_a0 <= inv_q_mul_io_a0 @[Sbox.scala 219:19]
    inv_q_mul_sum_mul_io_a1 <= inv_q_mul_io_a1 @[Sbox.scala 220:19]
    inv_q_mul_sum_mul_io_ab <= inv_q_mul_io_aa @[Sbox.scala 221:19]
    inv_q_mul_sum_mul_io_b0 <= inv_q_mul_io_b0 @[Sbox.scala 222:19]
    inv_q_mul_sum_mul_io_b1 <= inv_q_mul_io_b1 @[Sbox.scala 223:19]
    inv_q_mul_sum_mul_io_cd <= inv_q_mul_io_bb @[Sbox.scala 224:19]
    node inv_sa0 = xor(inv_io_i6, inv_io_i4) @[Sbox.scala 263:18]
    node inv_sa1 = xor(inv_io_i7, inv_io_i5) @[Sbox.scala 264:18]
    node inv_sb0 = xor(inv_io_i2, inv_io_i0) @[Sbox.scala 265:18]
    node inv_sb1 = xor(inv_io_i3, inv_io_i1) @[Sbox.scala 266:18]
    node inv_al = xor(inv_io_i5, inv_io_i4) @[Sbox.scala 267:17]
    node inv_ah = xor(inv_io_i7, inv_io_i6) @[Sbox.scala 268:17]
    node inv_aa = xor(inv_sa1, inv_sa0) @[Sbox.scala 269:18]
    node inv_bl = xor(inv_io_i1, inv_io_i0) @[Sbox.scala 270:17]
    node inv_bh = xor(inv_io_i3, inv_io_i2) @[Sbox.scala 271:17]
    node inv_bb = xor(inv_sb1, inv_sb0) @[Sbox.scala 272:18]
    node inv__T = and(inv_ah, inv_bh) @[Sbox.scala 274:20]
    node inv_ct1 = not(inv__T) @[Sbox.scala 274:15]
    node inv__T_1 = and(inv_sa0, inv_sb0) @[Sbox.scala 275:21]
    node inv_ct2 = not(inv__T_1) @[Sbox.scala 275:15]
    node inv__T_2 = and(inv_aa, inv_bb) @[Sbox.scala 276:20]
    node inv_ct3 = not(inv__T_2) @[Sbox.scala 276:15]
    node inv__T_3 = or(inv_sa0, inv_sb0) @[Sbox.scala 278:21]
    node inv__T_4 = not(inv__T_3) @[Sbox.scala 278:15]
    node inv__T_5 = and(inv_io_i7, inv_io_i3) @[Sbox.scala 278:36]
    node inv__T_6 = not(inv__T_5) @[Sbox.scala 278:31]
    node inv__T_7 = xor(inv__T_4, inv__T_6) @[Sbox.scala 278:28]
    node inv__T_8 = xor(inv__T_7, inv_ct1) @[Sbox.scala 278:44]
    node inv_c3 = xor(inv__T_8, inv_ct3) @[Sbox.scala 278:50]
    node inv__T_9 = or(inv_sa1, inv_sb1) @[Sbox.scala 279:21]
    node inv__T_10 = not(inv__T_9) @[Sbox.scala 279:15]
    node inv__T_11 = and(inv_io_i6, inv_io_i2) @[Sbox.scala 279:36]
    node inv__T_12 = not(inv__T_11) @[Sbox.scala 279:31]
    node inv__T_13 = xor(inv__T_10, inv__T_12) @[Sbox.scala 279:28]
    node inv__T_14 = xor(inv__T_13, inv_ct1) @[Sbox.scala 279:44]
    node inv_c2 = xor(inv__T_14, inv_ct2) @[Sbox.scala 279:50]
    node inv__T_15 = or(inv_al, inv_bl) @[Sbox.scala 280:20]
    node inv__T_16 = not(inv__T_15) @[Sbox.scala 280:15]
    node inv__T_17 = and(inv_io_i5, inv_io_i1) @[Sbox.scala 280:34]
    node inv__T_18 = not(inv__T_17) @[Sbox.scala 280:29]
    node inv__T_19 = xor(inv__T_16, inv__T_18) @[Sbox.scala 280:26]
    node inv__T_20 = xor(inv__T_19, inv_ct2) @[Sbox.scala 280:42]
    node inv_c1 = xor(inv__T_20, inv_ct3) @[Sbox.scala 280:48]
    node inv__T_21 = or(inv_io_i4, inv_io_i0) @[Sbox.scala 281:20]
    node inv__T_22 = not(inv__T_21) @[Sbox.scala 281:15]
    node inv__T_23 = and(inv_al, inv_bl) @[Sbox.scala 281:34]
    node inv__T_24 = not(inv__T_23) @[Sbox.scala 281:29]
    node inv__T_25 = xor(inv__T_22, inv__T_24) @[Sbox.scala 281:26]
    node inv__T_26 = and(inv_sa1, inv_sb1) @[Sbox.scala 281:51]
    node inv__T_27 = not(inv__T_26) @[Sbox.scala 281:45]
    node inv__T_28 = xor(inv__T_25, inv__T_27) @[Sbox.scala 281:42]
    node inv_c0 = xor(inv__T_28, inv_ct2) @[Sbox.scala 281:59]
    node inv_sd0 = xor(inv_d_inv_io_o2, inv_d_inv_io_o0) @[Sbox.scala 292:18]
    node inv_sd1 = xor(inv_d_inv_io_o3, inv_d_inv_io_o1) @[Sbox.scala 293:18]
    node inv_dl = xor(inv_d_inv_io_o1, inv_d_inv_io_o0) @[Sbox.scala 294:17]
    node inv_dh = xor(inv_d_inv_io_o3, inv_d_inv_io_o2) @[Sbox.scala 295:17]
    node inv_dd = xor(inv_sd1, inv_sd0) @[Sbox.scala 296:18]
    inv_io_o0 <= inv_q_mul_io_o0 @[Sbox.scala 346:11]
    inv_io_o1 <= inv_q_mul_io_o1 @[Sbox.scala 347:11]
    inv_io_o2 <= inv_q_mul_io_o2 @[Sbox.scala 348:11]
    inv_io_o3 <= inv_q_mul_io_o3 @[Sbox.scala 349:11]
    inv_io_o4 <= inv_p_mul_io_o0 @[Sbox.scala 350:11]
    inv_io_o5 <= inv_p_mul_io_o1 @[Sbox.scala 351:11]
    inv_io_o6 <= inv_p_mul_io_o2 @[Sbox.scala 352:11]
    inv_io_o7 <= inv_p_mul_io_o3 @[Sbox.scala 353:11]
    inv_d_inv_clock <= inv_clock
    inv_d_inv_reset <= inv_reset
    inv_d_inv_io_i0 <= inv_c0 @[Sbox.scala 283:17]
    inv_d_inv_io_i1 <= inv_c1 @[Sbox.scala 284:17]
    inv_d_inv_io_i2 <= inv_c2 @[Sbox.scala 285:17]
    inv_d_inv_io_i3 <= inv_c3 @[Sbox.scala 286:17]
    inv_p_mul_clock <= inv_clock
    inv_p_mul_reset <= inv_reset
    inv_p_mul_io_A0 <= inv_d_inv_io_o0 @[Sbox.scala 299:17]
    inv_p_mul_io_A1 <= inv_d_inv_io_o1 @[Sbox.scala 300:17]
    inv_p_mul_io_A2 <= inv_d_inv_io_o2 @[Sbox.scala 301:17]
    inv_p_mul_io_A3 <= inv_d_inv_io_o3 @[Sbox.scala 302:17]
    inv_p_mul_io_a0 <= inv_sd0 @[Sbox.scala 303:17]
    inv_p_mul_io_a1 <= inv_sd1 @[Sbox.scala 304:17]
    inv_p_mul_io_Al <= inv_dl @[Sbox.scala 305:17]
    inv_p_mul_io_Ah <= inv_dh @[Sbox.scala 306:17]
    inv_p_mul_io_aa <= inv_dd @[Sbox.scala 307:17]
    inv_p_mul_io_B0 <= inv_io_i0 @[Sbox.scala 308:17]
    inv_p_mul_io_B1 <= inv_io_i1 @[Sbox.scala 309:17]
    inv_p_mul_io_B2 <= inv_io_i2 @[Sbox.scala 310:17]
    inv_p_mul_io_B3 <= inv_io_i3 @[Sbox.scala 311:17]
    inv_p_mul_io_b0 <= inv_sb0 @[Sbox.scala 312:17]
    inv_p_mul_io_b1 <= inv_sb1 @[Sbox.scala 313:17]
    inv_p_mul_io_Bl <= inv_bl @[Sbox.scala 314:17]
    inv_p_mul_io_Bh <= inv_bh @[Sbox.scala 315:17]
    inv_p_mul_io_bb <= inv_bb @[Sbox.scala 316:17]
    inv_q_mul_clock <= inv_clock
    inv_q_mul_reset <= inv_reset
    inv_q_mul_io_A0 <= inv_d_inv_io_o0 @[Sbox.scala 323:17]
    inv_q_mul_io_A1 <= inv_d_inv_io_o1 @[Sbox.scala 324:17]
    inv_q_mul_io_A2 <= inv_d_inv_io_o2 @[Sbox.scala 325:17]
    inv_q_mul_io_A3 <= inv_d_inv_io_o3 @[Sbox.scala 326:17]
    inv_q_mul_io_a0 <= inv_sd0 @[Sbox.scala 327:17]
    inv_q_mul_io_a1 <= inv_sd1 @[Sbox.scala 328:17]
    inv_q_mul_io_Al <= inv_dl @[Sbox.scala 329:17]
    inv_q_mul_io_Ah <= inv_dh @[Sbox.scala 330:17]
    inv_q_mul_io_aa <= inv_dd @[Sbox.scala 331:17]
    inv_q_mul_io_B0 <= inv_io_i4 @[Sbox.scala 332:17]
    inv_q_mul_io_B1 <= inv_io_i5 @[Sbox.scala 333:17]
    inv_q_mul_io_B2 <= inv_io_i6 @[Sbox.scala 334:17]
    inv_q_mul_io_B3 <= inv_io_i7 @[Sbox.scala 335:17]
    inv_q_mul_io_b0 <= inv_sa0 @[Sbox.scala 336:17]
    inv_q_mul_io_b1 <= inv_sa1 @[Sbox.scala 337:17]
    inv_q_mul_io_Bl <= inv_al @[Sbox.scala 338:17]
    inv_q_mul_io_Bh <= inv_ah @[Sbox.scala 339:17]
    inv_q_mul_io_bb <= inv_aa @[Sbox.scala 340:17]
    node R1 = xor(io_i7, io_i5) @[Sbox.scala 380:20]
    node _T = xor(io_i7, io_i4) @[Sbox.scala 381:22]
    node R2 = not(_T) @[Sbox.scala 381:14]
    node R3 = xor(io_i6, io_i0) @[Sbox.scala 382:20]
    node _T_1 = xor(io_i5, R3) @[Sbox.scala 383:22]
    node R4 = not(_T_1) @[Sbox.scala 383:14]
    node R5 = xor(io_i4, R4) @[Sbox.scala 384:20]
    node R6 = xor(io_i3, io_i0) @[Sbox.scala 385:20]
    node R7 = xor(io_i2, R1) @[Sbox.scala 386:20]
    node R8 = xor(io_i1, R3) @[Sbox.scala 387:20]
    node R9 = xor(io_i3, R8) @[Sbox.scala 388:20]
    node B7 = xor(R7, R8) @[Sbox.scala 390:17]
    node B6 = not(R5) @[Sbox.scala 391:14]
    node _T_2 = xor(io_i1, R4) @[Sbox.scala 392:22]
    node B5 = not(_T_2) @[Sbox.scala 392:14]
    node B4 = xor(R1, R3) @[Sbox.scala 393:17]
    node _T_3 = xor(io_i1, R2) @[Sbox.scala 394:22]
    node _T_4 = xor(_T_3, R6) @[Sbox.scala 394:27]
    node B3 = not(_T_4) @[Sbox.scala 394:14]
    node B1 = not(R4) @[Sbox.scala 396:14]
    node B0 = xor(io_i2, R9) @[Sbox.scala 397:20]
    node T1 = xor(inv_io_o7, inv_io_o3) @[Sbox.scala 417:17]
    node T2 = xor(inv_io_o6, inv_io_o4) @[Sbox.scala 418:17]
    node T3 = xor(inv_io_o6, inv_io_o0) @[Sbox.scala 419:17]
    node _T_5 = xor(inv_io_o5, inv_io_o3) @[Sbox.scala 420:19]
    node T4 = not(_T_5) @[Sbox.scala 420:14]
    node _T_6 = xor(inv_io_o5, T1) @[Sbox.scala 421:19]
    node T5 = not(_T_6) @[Sbox.scala 421:14]
    node _T_7 = xor(inv_io_o5, inv_io_o1) @[Sbox.scala 422:19]
    node T6 = not(_T_7) @[Sbox.scala 422:14]
    node _T_8 = xor(inv_io_o4, T6) @[Sbox.scala 423:19]
    node T7 = not(_T_8) @[Sbox.scala 423:14]
    node T8 = xor(inv_io_o2, T4) @[Sbox.scala 424:17]
    node T9 = xor(inv_io_o1, T2) @[Sbox.scala 425:17]
    node T10 = xor(T3, T5) @[Sbox.scala 426:18]
    node _T_9 = not(T4) @[Sbox.scala 428:14]
    node _T_10 = not(T1) @[Sbox.scala 429:14]
    node _T_11 = not(T3) @[Sbox.scala 430:14]
    node _T_12 = not(T5) @[Sbox.scala 431:14]
    node _T_13 = xor(T2, T5) @[Sbox.scala 432:19]
    node _T_14 = not(_T_13) @[Sbox.scala 432:14]
    node _T_15 = xor(T3, T8) @[Sbox.scala 433:19]
    node _T_16 = not(_T_15) @[Sbox.scala 433:14]
    node _T_17 = not(T7) @[Sbox.scala 434:14]
    node _T_18 = not(T9) @[Sbox.scala 435:14]
    io_o0 <= _T_18 @[Sbox.scala 435:11]
    io_o1 <= _T_17 @[Sbox.scala 434:11]
    io_o2 <= _T_16 @[Sbox.scala 433:11]
    io_o3 <= _T_14 @[Sbox.scala 432:11]
    io_o4 <= _T_12 @[Sbox.scala 431:11]
    io_o5 <= _T_11 @[Sbox.scala 430:11]
    io_o6 <= _T_10 @[Sbox.scala 429:11]
    io_o7 <= _T_9 @[Sbox.scala 428:11]
    inv_clock <= clock
    inv_reset <= reset
    inv_io_i0 <= B0 @[Sbox.scala 400:15]
    inv_io_i1 <= B1 @[Sbox.scala 401:15]
    inv_io_i2 <= io_i0 @[Sbox.scala 402:15]
    inv_io_i3 <= B3 @[Sbox.scala 403:15]
    inv_io_i4 <= B4 @[Sbox.scala 404:15]
    inv_io_i5 <= B5 @[Sbox.scala 405:15]
    inv_io_i6 <= B6 @[Sbox.scala 406:15]
    inv_io_i7 <= B7 @[Sbox.scala 407:15]
