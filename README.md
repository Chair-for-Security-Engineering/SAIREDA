# SAIREDA
Security-Aware Intermediate Representation and Electronic Design Automation

# Resources
- MLIR (https://mlir.llvm.org/)
- CIRCT (https://github.com/llvm/circt)
- Chisel/FIRRTL (https://www.chisel-lang.org/)
- z3 (https://github.com/Z3Prover/z3)

# SecFIR.NeL
A legal FIRRTL design with the following restrictions:
- Only Datatype: UInt(1.W), Clock , Reset Type
- Only Instructions: not, and, or, xor, node, connect, module

# Dependencies
- Build CIRCT/MLIR according to https://github.com/llvm/circt, however, at commit 688bd0d6f39f20367a305317ca5891dddc301c8f (Does not work with up-to-date version!) 
- Build z3 4.8.11 according to https://github.com/Z3Prover/z3 (Pre-build version is enough)

# Build Project
- Clone git repository
- Adapt paths for CIRCT and z3 in CMakeLists.txt
- Build project
```
cmake -S . -B build
cmake --build build
```

# Execution
Example command to read the Keccak design, insert PINI gadgets with normal randomness distribution, insert the gadget logic for second order, and output the result as an Verilog file:
```
./build/secfir_eda -i=designs/KeccakChi.lo.fir --firrtl-to-secfir --insert-combinatorial-logic-hierarchy --xag-transformation --set-share-attribute --insert-gadgets='masking=pini' --flatten-combinatorial-logic-hierarchy --distribute-randomness='order=2 rule=std uniqueRand=non' --insert-gadget-logic='order=2' -o=output/verilog/KeccakChi.v
```
*Options:* \
`-i=<low-fir-file>` : Input-design file. \
`-o=<verilog-file>` : Output-design file (During translation an error is displayed which can be safely ignored, see FIRRTL to SecFIR pass). \
`--print-ir-after=<pass-name>` : Prints the IR after the indicated pass in the terminal.\
`--pass-statistics` : Prints statistics of the executed pass \
`--pass-timings` : Print timing behavior of the executed passes \
`-h` : Display available options

# Passes
### FIRRTL to SecFIR
`--firrtl-to-secfir` : Translation from FIRRTL IR to SecFIR IR.\
*Remarks:* When executed an error message 'firrtl.circuit op Operations with a SymbolTable must have exactly one block' is displayed which can be safely ignored.

### Insert Combinatorial Logic Blocks
`--insert-combinatorial-logic-hierarchy` : Identifies blocks of combinatorial logic and groups each block in a region of a CombLogicOp.

### Flatten Combinatorial Logic Blocks
`--flatten-combinatorial-logic-hierarchy` : Removes CombLogicOp operations by moving all operations from the inside region to the region where the CombLogicOp is located.

### XOR-AND-Graph Transformation
`--xag-transformation` : Transforms logic inside CombLogicOps to XAG.\
*Requires:* CombLogicOp

### Set Share Attributes
`--set-share-attribute` : Marks all inputs, except for clock and reset, for sharing as preparation for boolean masking.\
*Requires:* Clock of type secfir.ClockType and reset named "reset" or "rst" or of type secfir.ResetType.

### Insert Side-Channel Secure Gadgets
`--insert-gadgets='masking=<value>'` : Replaces all AND operations with side-channel secure gadget operations and inserts SNI refresh gadgets where required. \
*Requires:* CombLogicOp, XAG \
*Options:* masking={probSec, probSecNoThightProve, ni, sni, doubleSni, pini, spini} 

### Distribute Randomness
`--distribute-randomness=order=<int> rule=<value> uniqueRand=<value>` : Pass that distributes randomness to the existing side-channel secure gadgets. The overall required randomness is dependent on the number of gadgets, the security order, and the level of optimization.\
*Requires:* Flattened CombLogicOp\
*Options:* order=integer; rule={std, sni, pini}; uniqueRand={non, t}

### Insert Gadget Logic
`--insert-gadget-logic='order=<int>'` : Replaces all existing side-channel secure gadgets with the corresponding concrete implementation. \
*Requires:* Flattened CombLogicOp, and distributed randomness\
*Options:* order=integer

