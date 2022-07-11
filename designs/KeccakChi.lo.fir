circuit chi :
  module chi :
    input clock : Clock
    input reset : UInt<1>
    input io_i0 : UInt<1>
    input io_i1 : UInt<1>
    input io_i2 : UInt<1>
    input io_i3 : UInt<1>
    input io_i4 : UInt<1>
    output io_o0 : UInt<1>
    output io_o1 : UInt<1>
    output io_o2 : UInt<1>
    output io_o3 : UInt<1>
    output io_o4 : UInt<1>
  
    node _T = not(io_i1) @[chi.scala 21:23]
    node _T_1 = and(_T, io_i2) @[chi.scala 21:30]
    node _T_2 = xor(io_i0, _T_1) @[chi.scala 21:20]
    node _T_3 = not(io_i2) @[chi.scala 22:23]
    node _T_4 = and(_T_3, io_i3) @[chi.scala 22:30]
    node _T_5 = xor(io_i1, _T_4) @[chi.scala 22:20]
    node _T_6 = not(io_i3) @[chi.scala 23:23]
    node _T_7 = and(_T_6, io_i4) @[chi.scala 23:30]
    node _T_8 = xor(io_i2, _T_7) @[chi.scala 23:20]
    node _T_9 = not(io_i4) @[chi.scala 24:23]
    node _T_10 = and(_T_9, io_i0) @[chi.scala 24:30]
    node _T_11 = xor(io_i3, _T_10) @[chi.scala 24:20]
    node _T_12 = not(io_i0) @[chi.scala 25:23]
    node _T_13 = and(_T_12, io_i1) @[chi.scala 25:30]
    node _T_14 = xor(io_i4, _T_13) @[chi.scala 25:20]
    io_o0 <= _T_2 @[chi.scala 21:11]
    io_o1 <= _T_5 @[chi.scala 22:11]
    io_o2 <= _T_8 @[chi.scala 23:11]
    io_o3 <= _T_11 @[chi.scala 24:11]
    io_o4 <= _T_14 @[chi.scala 25:11]
