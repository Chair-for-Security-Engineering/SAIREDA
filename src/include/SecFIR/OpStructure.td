/*
 * -----------------------------------------------------------------
 * COMPANY : Ruhr-University Bochum, Chair for Security Engineering
 * AUTHOR  : Jakob Feldtkeller (jakob.feldtkeller@rub.de)
 * -----------------------------------------------------------------
 *
 * Copyright (c) 2022, Jakob Feldtkeller
 *
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Please see license.rtf and README for license and further instructions.
 */

//===- OpStructure.td - Circuit and Module Definitions -----*- tablegen -*-===//
//
// This describes the SecFIR Circuit and Module MLIR ops.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLStructure.td)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

def CircuitOp : SecFIROp<"circuit",
      [IsolatedFromAbove, SymbolTable,
       SingleBlockImplicitTerminator<"DoneOp">]> {
  let summary = "SecFIR Circuit";
  let description = [{
    The "secfir.circuit" operation represents an overall Verilog circuit,
    containing a list of modules.
  }];
  let arguments = (ins StrAttr:$name);
  let results = (outs);
  let regions = (region SizedRegion<1>:$body);

  let skipDefaultBuilders = 1;
  let builders = [
    OpBuilderDAG<(ins "StringAttr":$name)>
  ];

  let extraClassDeclaration = [{
    OpBuilder getBodyBuilder() {
      assert(!body().empty() && "Unexpected empty 'body' region.");
      Block &bodyBlock = body().front();
      return OpBuilder(&bodyBlock, std::prev(bodyBlock.end()));
    }

    /// Return body of this circuit.
    Region &getBodyRegion();
    Block *getBody();
  }];

  let printer = [{ return ::print(p, *this); }];
  let parser = [{ return ::parse$cppClass(parser, result); }];

  let verifier = [{ return ::verifyCircuitOp(*this); }];
}

def ModuleOp : SecFIROp<"Module", 
      [IsolatedFromAbove, FunctionLike, Symbol, RegionKindInterface,
       SingleBlockImplicitTerminator<"OutputOp">]>{
  let summary = "SecFIR Module";
  let description = [{
    The "secfir.module" operation represents a Verilog module, including a given
    name, a list of ports, and a body that represents the connections within
    the module.
  }];

  let arguments = (ins StrArrayAttr:$argNames, StrArrayAttr:$resultNames);
  let results = (outs);
  let regions = (region SizedRegion<1>:$body);

  let skipDefaultBuilders = 1;
  let builders = [
    OpBuilderDAG<(ins "StringAttr":$name, "ArrayRef<ModulePortInfo>":$ports)>
  ];

   let extraClassDeclaration = [{
    using FunctionLike::getBody;

    // Implement RegionKindInterface.
    static RegionKind getRegionKind(unsigned index) { return RegionKind::Graph;}

    // Decode information about the input and output ports on this module.
    void getPortInfo(SmallVectorImpl<ModulePortInfo> &results) {
      getModulePortInfo(*this, results);
    }

    void getOutputPortInfo(SmallVectorImpl<ModulePortInfo> &results){
      getModuleOutputPortInfo(*this, results);
    }

    Block *getBodyBlock() { return &body().front(); }

    Operation *getOutputOp() {
      return &(getBodyBlock()->getOperations().back());}

    private:
    // This trait needs access to the hooks defined below.
    friend class OpTrait::FunctionLike<ModuleOp>;

    /// Returns the number of arguments, implementing OpTrait::FunctionLike.
    unsigned getNumFuncArguments() { return getType().getInputs().size(); }
    /// Returns the number of results, implementing OpTrait::FunctionLike.
    unsigned getNumFuncResults() { return getType().getResults().size(); }

    /// Hook for OpTrait::FunctionLike, called after verifying that the 'type'
    /// attribute is present and checks if it holds a function type.  Ensures
    /// getType, getNumFuncArguments, and getNumFuncResults can be called
    ///  safely.
    LogicalResult verifyType() {
      auto type = getTypeAttr().getValue();
      if (!type.isa<FunctionType>())
        return emitOpError("requires '" + getTypeAttrName() +
                           "' attribute of function type");
      return success();
    }
  public:
   }];
   let printer = [{ return ::print(p, *this); }];
}


def OutputOp : SecFIROp<"output", 
      [Terminator, HasParent<"ModuleOp">, NoSideEffect, ReturnLike]>{
  
  let summary = "Terminator operation for SecFIR";
  let description = [{
    "secfir.output" marks the end of a region in the SecFIR dialect and the values
    to put on the output ports.
  }];
  
   let arguments = (ins Variadic<AnyType>:$operands);

   let builders = [
     OpBuilderDAG<(ins), "build($_builder, $_state, llvm::None);">
   ];

  let assemblyFormat = "attr-dict ($operands^ `:` type($operands))?";
}

def DoneOp : SecFIROp<"done", [Terminator]> {
  let summary = "SecFIR termination operation";
  let description = [{
    "secfir.done" marks the end of a region in the SecFIR dialect.
  }];

  let arguments = (ins);
}
