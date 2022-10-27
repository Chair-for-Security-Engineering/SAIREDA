# Description
A security extension for FIRRTL build as a security-aware EDA tool within the MLIR context.

# Resources
- MLIR (https://mlir.llvm.org/)
- CIRCT (https://github.com/llvm/circt)
- Chisel/FIRRTL (https://www.chisel-lang.org/)
- z3 (https://github.com/Z3Prover/z3)

# SecFIR.NeL
A legal FIRRTL design with the following restrictions:
- Only Datatype: UInt(1.W), Clock , Reset Type
- Only Instructions: not, and, or, xor, node, connect, module, circuit

# Dependencies
- Build CIRCT/MLIR according to https://github.com/llvm/circt and go to commit 688bd0d6f39f20367a305317ca5891dddc301c8f (Does not work with up-to-date version!) 
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
Example command to read the Keccak design, insert PINI gadgets with normal randomness distribution, insert the gadget logic for second order, and output the result as an Verilog file (Please note the remark for --firrtl-to-secfir):
```
./build/saireda -i=designs/KeccakChi.lo.fir --firrtl-to-secfir --insert-combinatorial-logic-hierarchy --xag-transformation --set-share-attribute --insert-gadgets='masking=pini' --define-gadget-type=type='hpc1' --flatten-combinatorial-logic-hierarchy --distribute-randomness='order=2 activeOrder=0 rule=std uniqueRand=non' --insert-gadget-logic='order=2 activeOrder=0' -o=output/verilog/KeccakChi.v
```
*Options:* \
`-i=<low-fir-file>` : Input-design file. \
`-o=<verilog-file>` : Output-design file (During translation an error is displayed which can be safely ignored, see FIRRTL to SecFIR pass). \
`--print-ir-after=<pass-name>` : Prints the IR after the indicated pass in the terminal.\
`--pass-statistics` : Prints statistics of the executed passes \
`--pass-timings` : Print timing behavior of the executed passes \
`-h` : Display available options

# Passes
### FIRRTL to SecFIR
`--firrtl-to-secfir` : Translation from FIRRTL IR to SecFIR IR.\
*Remarks:* When executed an error message 'firrtl.circuit op Operations with a SymbolTable must have exactly one block' is displayed which can be safely ignored.

### Insert Combinatorial Logic Blocks
`--insert-combinatorial-logic-hierarchy` : Identifies blocks of combinatorial logic and groups each block in a region of a CombLogicOp. By default, additional registers are inserted for pipelining, where required. \
*Options:* no-pipeline={true, false} 

### Flatten Combinatorial Logic Blocks
`--flatten-combinatorial-logic-hierarchy` : Removes CombLogicOp operations by moving all operations from the inside region to the region where the CombLogicOp is located.

### XOR-AND-Graph Transformation
`--xag-transformation` : Transforms logic inside CombLogicOps to XAG.\
*Requires:* CombLogicOp

### Insert Majority Logic
`--maj-to-logic` : Existing MajorityPrimOp operations are replaced by the logic of a majority function based on a given sorting network. Descriptions of sorting networks can be given according to https://bertdobbelaere.github.io/sorting_networks.html \
*Options:* sortNet=[path to file]

### Insert MUX Logic
`--mux-to-logic` : Existing MuxPrimOp operations are replaced by the logic of a multiplexer. \
*Requires:* CombLogicOp

### Insert Modules with Single Operations
`insert-module-pass`: Replaces either all or only marked logical gate operations with instantiations of a module, containing only a single logical gate. To mark a gate for replacement the attribute "ModuleReplace" is required. \
*Options:* method={all, marked}

### Set Share Attributes
`--set-share-attribute` : Marks all inputs, except for clock and reset, for sharing as preparation for boolean masking. Then it traverse through the design to mark all operations dependent on some marked input for sharing.\
*Requires:* Clock of type secfir.ClockType and reset named "reset" or "rst" or of type secfir.ResetType.

### Insert Side-Channel Secure Gadgets
`--insert-gadgets='masking=<value>'` : Replaces all AND operations with side-channel secure gadget operations and inserts SNI refresh gadgets where required. \
*Requires:* CombLogicOp, XAG \
*Options:* masking={none, probSec, probSecNoThightProve, ni, sni, doubleSni, pini, spini, cini, icini} 

### Distribute Randomness
`--distribute-randomness=order=<int> rule=<value> uniqueRand=<value>` : Pass that distributes randomness to the existing side-channel secure gadgets. The overall required randomness is dependent on the number of gadgets, the security order, and the level of optimization.\
*Requires:* Flattened CombLogicOp\
*Options:* order=integer; activeOrder=integer; rule={std, sni, pini}; uniqueRand={non, t}; maxSetSize=integer

### Insert Gadget Logic
`--insert-gadget-logic='order=<int> activeOrder=<int>'` : Replaces all existing side-channel secure gadgets with the corresponding concrete implementation and duplicates them according to the provided active security order. \
*Requires:* Flattened CombLogicOp, and distributed randomness\
*Options:* order=integer; activeOrder=integer; asModule=bool; pipeline=bool

### 
`--insert-module-pass=method=<value>` :
Replaces either all or only marked operations with instances 
modules that only contain one operation. \
Useful to hinder a synthesizer from optimizing security relevant
structures.\
*Requires* Flattened CombLogicOp \
*Options:* method={all, marked}

### *Optimization:* Remove Redundant Operations 
`--opt-redundant-operations` : Removes operations that perform the same operations as an already existing operation.\
*Requiers:* Flattened design.

### *Optimization:* Remove Node Operations
`--remove-node-ops`: Removes all NodeOp operations by replacing all usages with the corresponding input.

### *Optimization:* Remove Double NOT
`--opt-not`: Removes all double NOT gates, i.e., NOT(NOT())

### *Optimization:* Optimize Latency of Asynchron-Gadget Composition
`--opt-gadget-latency`: Optimization pass that switches the order of inputs to gadgets with asynchon latency, such that the LHS input is dependent on less gadgets. \
*Requires:* CombLogic and inserted gadgets

