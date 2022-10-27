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

//===- OpDeclarations.td - SecFIR declaration ops ----------*- tablegen -*-===//
//
// This describes the MLIR ops for SecFIR declarations.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLDeclarations.td)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//


//From RTL dialect
def InstanceOp : SecFIROp<"instance"> {
  let summary = "Create an instance of a module";
  let description = [{
    This represents an instance of a module. The inputs and results are 
    the referenced module's inputs and outputs.  Any parameters are stored in
    the "parameters" dictionary.
  }];

  let arguments = (ins StrAttr:$instanceName,
                       FlatSymbolRefAttr:$moduleName,
                       Variadic<AnyType>:$inputs);
  let results = (outs Variadic<AnyType>);

  let extraClassDeclaration = [{   
    StringAttr getResultName(size_t i);

    /// Lookup the module or extmodule for the symbol.  This returns null on
    /// invalid IR.
    Operation *getReferencedModule();
  }];
  
  let assemblyFormat = [{
    $instanceName $moduleName `(` $inputs `)` custom<ResultNameList>(attr-dict)
      `:` functional-type($inputs, results)
  }];
}

def NodeOp : SecFIROp<"node", [NoSideEffect, SameOperandsAndResultType]> {
  let summary = "No-op to name a value";
  let description = [{
    A node is simply a named intermediate value in a circuit. The node must
    be initialized to a value with a passive type and cannot be connected to.
    Nodes are often used to split a complicated compound expression into named
    subexpressions.

    ```
      %result = secfir.node %input : t1
    ```
    }];

  let arguments = (ins SecFIRType:$input, OptionalAttr<StrAttr>:$name);
  let results = (outs SecFIRType:$result);
  
  let assemblyFormat = [{
     $input attr-dict `:` type($input)
  }];
}

def RegOp : SecFIROp<"reg", [/*MemAlloc*/]> {
  let summary = "Define a new register";
  let description = [{
    Declare a new register:
    ```
      %name = secfir.reg %clockVal : t1
    ```
    }];

  let arguments = (ins SecFIRType:$input, ClockType:$clockVal, OptionalAttr<StrAttr>:$name);
  let results = (outs PassiveType:$result);

  let assemblyFormat = [{
     operands attr-dict `:` functional-type($input, $result)
  }];
}

def RegInitOp : SecFIROp<"reginit", [/*MemAlloc*/]> {
  let summary = "Define a new register with an initializer";
  let description = [{
    Declare a new register:
    ```
      %name = secfir.reginit %clockVal, %resetSignal, %resetValue : t1
    ```
    }];

  let arguments = (ins ClockType:$clockVal, ResetType:$resetSignal,
                       PassiveType:$resetValue, OptionalAttr<StrAttr>:$name);
  let results = (outs PassiveType:$result);

  let assemblyFormat = [{
     operands attr-dict `:` functional-type(operands, $result)
  }];
}
