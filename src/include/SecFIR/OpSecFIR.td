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
 
//===- OpSecFIR.td - SecFIR ops --------------*- tablegen -*-===//
//
// This describes the MLIR ops for SecFIR operations that are not part of FIRRTL.
//
//===----------------------------------------------------------------------===//

def CombLogicOp : SecFIROp<"combLogic",
      [IsolatedFromAbove, RegionKindInterface]> 
{
    let summary = "SecFIR Combinational Logic Block";
    let description = [{
        The "secfir.CompLogicOP" operation represents a block of combinational logic,
        i.e., without any register.
    }];
  
    let arguments = (ins Variadic<IntType>:$input);
    let results = (outs Variadic<IntType>:$results);
    let regions = (region SizedRegion<1>:$body);

    let skipDefaultBuilders = 1;
    let builders = [
       OpBuilderDAG<(ins "TypeRange":$resultTypes, "ValueRange":$input)>,
    ];

    let extraClassDeclaration = [{
        // Implement RegionKindInterface.
        static RegionKind getRegionKind(unsigned index) { return RegionKind::SSACFG;}

         // TODO(mlir): FunctionLike shouldn't produce a getBody() helper, it is
    // squatting on the name.
    Block *getBodyBlock() { return &body().front(); }

    OpBuilder getBodyBuilder() {
      assert(!body().empty() && "Unexpected empty 'body' region.");
      Block &bodyBlock = body().front();
      return OpBuilder(&bodyBlock, std::prev(bodyBlock.end()));
    }
    }];

   // let printer = [{ return ::print(p, *this); }];
   
}

def OutputCombOp : SecFIROp<"outputComb", [Terminator, HasParent<"CombLogicOp">,
                                NoSideEffect, ReturnLike]> {
  let summary = "Terminator operation for secfir.combLogic";
  let description = [{
    secfir.outputComb is the terminator operation for combinatorial logic blocks
    and declares the corresponding output signals
  }];

  let arguments = (ins Variadic<IntType>:$operands);

  let builders = [OpBuilderDAG<(ins),
                               [{ build($_builder, $_state, llvm::None); }]>];

  let assemblyFormat = "attr-dict ($operands^ `:` type($operands))?";

  //let verifier = [{ return ::verifyOutputOp(this); }];
}
