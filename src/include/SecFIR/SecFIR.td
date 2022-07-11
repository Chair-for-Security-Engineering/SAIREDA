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

//===- SecFIR.td - SecFIR dialect definition ---------------*- tablegen -*-===//
//
// This is the top level file for the SecFIR dialect.
// Derived work from MLIR FIRRTL Dialect
// (https://github.com/llvm/circt/blob/main/include/circt/Dialect/FIRRTL/FIRRTLDialect.td)
// at commit 688bd0d6f39f20367a305317ca5891dddc301c8f
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef SecFIR_TD
#define SecFIR_TD

include "mlir/IR/OpBase.td"
include "mlir/IR/SymbolInterfaces.td"
include "mlir/Interfaces/SideEffectInterfaces.td"
include "mlir/IR/RegionKindInterface.td"
include "mlir/Interfaces/ControlFlowInterfaces.td"
include "mlir/Pass/PassBase.td"

def SecFIRDialect : Dialect {
  let name = "secfir";

  let summary = "Types and operations for secfir dialect";
  let description = [{
    This dialect defines the `secfir` dialect, which is based on the
    FIRRTL dialect but extended to include more abstraction levels and 
    tailored for the needs of security-aware EDA.
    
    For more information on FIRRTL, see the [FIRRTL GitHub page]
    (https://github.com/freechipsproject/firrtl).
  }];

  let cppNamespace = "::circt::secfir";
}

// Base class for the operation in this dialect.
// class SecFIROp<string mnemonic, list<OpTrait> traits = []> :
//     Op<SecFIRDialect, mnemonic, traits>
class SecFIROp<string mnemonic, list<OpTrait> traits = []> :
    Op<SecFIRDialect, mnemonic, traits> 
{
         
}

include "SecFIR/Types.td"
include "SecFIR/OpStructure.td"
include "SecFIR/OpDeclarations.td"
include "SecFIR/OpExpressions.td"
include "SecFIR/OpStatements.td"
include "SecFIR/OpSecFIR.td"
include "SecFIR/OpSideChannel.td"

//include "Passes.td"

#endif // SecFIR_TD
