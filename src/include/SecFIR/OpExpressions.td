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

//===- OpExpressions.td - SecFIR expression ops ------------*- tablegen -*-===//
//
// This describes the MLIR ops for SecFIR expressions.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLExpressions.td)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

def ConstantOp : SecFIROp<"constant", [NoSideEffect, ConstantLike,
                                       FirstAttrDerivedResultType]> {
  let summary = "Produce a constant value";
  let description = [{
    The constant operation produces a constant value of SInt or UInt type.
    ```
      %result = secfir.constant 42 : t1
    ```
    }];

  let arguments = (ins APIntAttr:$value);
  let results = (outs IntType:$result);

  let assemblyFormat = [{
     `(` $value `)` attr-dict `:` type($result)
  }];

  let builders = [
    OpBuilderDAG<(ins "IntType":$type, "const APInt &":$value)>
  ];
  let hasFolder = 1;
  let verifier = [{ return ::verifyConstantOp(*this); }];
}
//-----------------------------------------------------------------===//
// Primitive Operations
//===----------------------------------------------------------------------===//

/// PrimOp is a SecFIROp without side effects.
class PrimOp<string mnemonic, list<OpTrait> traits = []> :
    SecFIROp<mnemonic, !listconcat(traits, [NoSideEffect])>;

//===----------------------------------------------------------------------===//
// Binary Operations
//===----------------------------------------------------------------------===//

// Base class for binary primitive operators.
class BinaryPrimOp<string mnemonic, string resultTypeFunction, list<OpTrait> traits = []> :
    PrimOp<mnemonic, traits> {
  let arguments = (ins IntType:$lhs, IntType:$rhs, DefaultValuedAttr<I8Attr, "0">:$dublication);
  let results = (outs IntType:$result);

  let assemblyFormat = [{
    $lhs `,` $rhs  attr-dict `:`
       `(` type($lhs) `,` type($rhs) `)` `->` type($result)
  }];

  let extraClassDeclaration = !cast<code>(!strconcat(!cast<string>([{
    /// Return the result for inputs with the specified type, returning a null
    /// type if the input types are invalid.
    static SecFIRType getResultType(SecFIRType lhs, SecFIRType rhs,
                                    Location loc) {
      return }]), resultTypeFunction, !cast<string>([{(lhs, rhs);
    }
    static SecFIRType getResultType(ArrayRef<SecFIRType> inputs,
                                    ArrayRef<int32_t> integers, Location loc) {
      if (inputs.size() != 2 || !integers.empty())
        return {};
      return getResultType(inputs[0], inputs[1], loc);
    }
  }])));
}

def IsAssociative : NativeOpTrait<"IsAssociative">;

let hasFolder = 1 in
def AndPrimOp : BinaryPrimOp<"and", "getBitwiseBinaryResult", [Commutative, IsAssociative]>;
let hasFolder = 1 in
def OrPrimOp  : BinaryPrimOp<"or",  "getBitwiseBinaryResult", [Commutative, IsAssociative]>;
let hasFolder = 1 in
def XorPrimOp : BinaryPrimOp<"xor", "getBitwiseBinaryResult", [Commutative, IsAssociative]>;

//===----------------------------------------------------------------------===//
// Unary Operations
//===----------------------------------------------------------------------===//

// Base class for unary primitive operators.
class UnaryPrimOp<string mnemonic, string resultTypeFunction,
                  Type resultType, Type srcType,
                  list<OpTrait> traits = []> :
    PrimOp<mnemonic, traits> {
  let arguments = (ins srcType:$input);
  let results = (outs resultType:$result);

  let assemblyFormat = [{
    $input attr-dict `:` functional-type($input, $result)
  }];

  let extraClassDeclaration = !cast<code>(!strconcat(!cast<string>([{
    /// Return the result for inputs with the specified type, returning a null
    /// type if the input types are invalid.
    static SecFIRType getResultType(SecFIRType input, Location loc) {
      return }]), resultTypeFunction, !cast<string>([{(input);
    }
    static SecFIRType getResultType(ArrayRef<SecFIRType> inputs,
                                    ArrayRef<int32_t> integers, Location loc) {
      if (inputs.size() != 1 || !integers.empty())
        return {};
      return getResultType(inputs[0], loc);
    }
  }])));
}

def NotPrimOp : UnaryPrimOp<"not", "getNotResult", IntType, IntType>; 
