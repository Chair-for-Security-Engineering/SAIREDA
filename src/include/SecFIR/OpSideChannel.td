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

/// Gadget is a SecFIROp without side effects.
class GadgetOp<string mnemonic, list<OpTrait> traits = []> :
    SecFIROp<mnemonic, !listconcat(traits, [NoSideEffect])>;


//===----------------------------------------------------------------------===//
// Binary Operations
//===----------------------------------------------------------------------===//

// Base class for binary gadget operators.
class BinaryGadgetOp<string mnemonic, string resultTypeFunction,
                   list<OpTrait> traits = []> :
    GadgetOp<mnemonic, traits> {
  let arguments = (ins IntType:$lhs, IntType:$rhs);
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

def SCAGadget : NativeOpTrait<"SCAGadget">;

def PiniAndGadgetOp : BinaryGadgetOp<"pini_and", "getBitwiseBinaryResult", [Commutative, SCAGadget]>;
def SniAndGadgetOp : BinaryGadgetOp<"sni_and", "getBitwiseBinaryResult", [Commutative, SCAGadget]>;
def SniPiniAndGadgetOp : BinaryGadgetOp<"sni_pini_and", "getBitwiseBinaryResult", [Commutative, SCAGadget]>;
def CiniAndGadgetOp : BinaryGadgetOp<"cini_and", "getBitwiseBinaryResult", [Commutative, SCAGadget]>;
def IciniAndGadgetOp : BinaryGadgetOp<"icini_and", "getBitwiseBinaryResult", [Commutative, SCAGadget]>;

//===----------------------------------------------------------------------===//
// Unary Operations
//===----------------------------------------------------------------------===//

// Base class for unary primitive operators.
class UnaryGadgetOp<string mnemonic, string resultTypeFunction,
                  Type resultType, Type srcType,
                  list<OpTrait> traits = []> :
    GadgetOp<mnemonic, traits> {
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

def SniRefreshOp : UnaryPrimOp<"sni_ref", "getRefreshResult", IntType, IntType, [SCAGadget]>;