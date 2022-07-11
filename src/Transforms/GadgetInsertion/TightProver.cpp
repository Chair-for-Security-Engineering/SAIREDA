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
#include "Passes/GadgetInsertion.h"
#include "Passes/TransformationPasses.h"

#include<set>
#include<tuple>
#include<math.h>
#include<algorithm>

namespace circt{
namespace secfir{
    /// Function that checks whether a vector is in the span of
    /// a set of vectors, where all vecors are encoded as an integer
    /// in binary representation
    bool inSpan(
        unsigned element,
        std::set<unsigned> set
    ){
        //Get all possible combinations of vectors in the set
        for(unsigned i=0; i<pow(2,set.size()); i++){
            unsigned vec = 0;
            unsigned j=0;
            //Compute the sum of the vectors
            for(unsigned inO: set){
                    if(i & (1 << j)){
                        vec = vec ^ inO;
                    }
                    j++;
            }
            //Check whether the element is equal to the current vector
            if(vec == element){
                return true;
            }
        }
        return false;
    }


    /// Function that implements the tightProver algorithm, which verifies
    /// probing security of a combinatorial logic block and thereby identifies
    /// postions where an SNI refresh gadget needs to be inserted to fullfil
    /// probing security. The algorithm is taken from Belaid et al, "Tight Private
    /// Circuits: Achieving Probing Security with the Least Refreshing", 2018
    ///
    /// Only combinatorial logic blocks as XAG are supported, where AND gates are 
    /// replaced by SNI AND operations.
    ///
    /// combLogicBlock      The block of combinatorial logic that should be analysed
    /// builder             An operation builder for IR manipulation (only used for 
    ///                             constructive variant)
    /// numberRefGadgets    Memory address where the number of inserted refresh 
    ///                             gadgets will be written to (only used for 
    ///                             constructive variant)
    /// constructSecure     True => constructive variant; False => verification only
    bool tightProver(
        secfir::CombLogicOp combLogicBlock,
        mlir::OpBuilder &builder,
        unsigned *numberRefGadgets,
        bool constructSecure
    ){
        //Get the number of instructions and inputs of the combinatorial logic
        unsigned logicSize = combLogicBlock.getBodyBlock()->getOperations().size();
        unsigned argumentSize = combLogicBlock.getBodyBlock()->getArguments().size();
        //Create a map from intermediate values to an encoding and a corresponding reverse map
        mlir::DenseMap<mlir::Value, unsigned> valueEncoding(logicSize+argumentSize);
        mlir::DenseMap<unsigned, mlir::Value> valueEncodingRev(logicSize+argumentSize);
        //Create different variables for required values
        std::vector<mlir::Operation *> andGadgets;
        std::vector<mlir::Value> flawedValues;
        std::vector<mlir::Operation *> flawedValueGadgets;
        std::set<unsigned> combList;

        //Get the encoding of all inputs to the combinatorial logic
        unsigned i = 0;
        for(auto argument: combLogicBlock.getBodyBlock()->getArguments()){
            if(argument.getType().isa<secfir::UIntType>()){
                //The encoding is the index of the input in binary representation
                valueEncoding[argument] = 1 << i;
                i++;
                //Fill the reverse mapping
                valueEncodingRev[valueEncoding[argument]] = argument;
            }
        }
        //Do the encoding for all operations within the combinatorial logic
        for (auto &op : combLogicBlock.getBodyBlock()->getOperations()) {
            //Handle XOR operations
            if(secfir::isa<secfir::XorPrimOp>(op)){
                secfir::XorPrimOp xorOp = secfir::dyn_cast<secfir::XorPrimOp>(op);
                //The encoding is the xor of the inputs
                valueEncoding[xorOp.getResult()] =
                            valueEncoding[xorOp.lhs()] ^ valueEncoding[xorOp.rhs()];
                //Fill the reverse mapping
                valueEncodingRev[valueEncoding[xorOp.getResult()]] = xorOp.getResult();
            //Handle NOT operation
            }else if(secfir::isa<secfir::NotPrimOp>(op)){
                secfir::NotPrimOp notOp = secfir::dyn_cast<secfir::NotPrimOp>(op);
                //The encoding is the same as for the input
                valueEncoding[notOp.getResult()] = valueEncoding[notOp.input()];
                //Fill the reverse mapping
                valueEncodingRev[valueEncoding[notOp.getResult()]] = notOp.getResult();
            //Handle SNI AND gadgets
            }else if(secfir::isa<secfir::SniAndGadgetOp>(op)){
                secfir::SniAndGadgetOp sniOp = secfir::dyn_cast<secfir::SniAndGadgetOp>(op);
                //Add gadget to the list of SNI AND gadgets
                andGadgets.push_back(&op);
                //This extends the width of the binary encoding by adding a new postion
                valueEncoding[sniOp.getResult()] =  1 << i;
                //Fill the reverse mapping
                valueEncodingRev[valueEncoding[sniOp.getResult()]] = sniOp.getResult();
                i++;
                //Add the inputs to the list of values that need to be analysed
                combList.insert(valueEncoding[sniOp.lhs()]);
                combList.insert(valueEncoding[sniOp.rhs()]);
            //Handle SNI refresh gadgets
            }else if(secfir::isa<secfir::SniRefreshOp>(op)){
                secfir::SniRefreshOp sniOp = secfir::dyn_cast<secfir::SniRefreshOp>(op);
                //This extends the width of the binary encoding by adding a new postion
                valueEncoding[sniOp.getResult()] =  1 << i;
                //Fill the reverse mapping
                valueEncodingRev[valueEncoding[sniOp.getResult()]] = sniOp.getResult();
                i++;
            }
        }
        //Go through the list of all values that should be analysed
        //(inputs to multiplication gadgets)
        for(unsigned comb : combList){
            std::vector<mlir::Operation *> G;
            std::set<unsigned> O;
            bool init = true;
            bool addedToG = true;
            while(true){
                //Define a variable that indicates whether there 
                //was a change to G in this round
                addedToG = false;
                //Go though the list of multiplication gadgets to 
                //build the sets G and O (from the algorithm in the paper)
                for(mlir::Operation *op : andGadgets){
                    secfir::SniAndGadgetOp andGadget = 
                                secfir::dyn_cast<secfir::SniAndGadgetOp>(op);
                    //In the first round, build the sets G and O from scratch
                    if(init){
                        //Check whether the current value to analyse is an input
                        //of the current multiplication gadget and if yes add 
                        //the gadget itself to G and the other input to O
                        if(valueEncoding[andGadget.lhs()] == comb){
                            G.push_back(op);
                            O.insert(valueEncoding[andGadget.rhs()]);
                            addedToG = true;
                        }else if(valueEncoding[andGadget.rhs()] == comb){
                            G.push_back(op);
                            O.insert(valueEncoding[andGadget.lhs()]);
                             addedToG = true;
                        }
                    //In all other rounds extend the sets G and O if necessary
                    }else{
                        //Check whether the current value to analyse is in the span
                        //of the vectors in O, and if yes, add the gadget to the set
                        //G and the other input to O
                        if(inSpan(valueEncoding[andGadget.lhs()] - comb, O)){
                            if(std::find(G.begin(), G.end(), op) == G.end()){
                                G.push_back(op);
                                O.insert(valueEncoding[andGadget.rhs()]);
                                addedToG = true;
                            } 
                        } else if(inSpan(valueEncoding[andGadget.rhs()] - comb, O)){
                            if(std::find(G.begin(), G.end(), op) == G.end()){
                                G.push_back(op);
                                O.insert(valueEncoding[andGadget.lhs()]);
                                addedToG = true;
                            } 
                        }
                    }
                }
                //Check for existing attacks by checking whether
                //the current value to analyse is in the span fromed
                //by the vectors in O
                if(inSpan(comb, O)){
                    //For the constructive variant we mark the postition 
                    //where an refresh gadget should be inserted
                    if(constructSecure){  
                        //Get the value that corresponds to comb
                        mlir::Value flawedValue = valueEncodingRev[comb];
                        flawedValues.push_back(flawedValue);
                        flawedValueGadgets.push_back(G[0]);
                    }else{
                        //In the verification only variant we return
                        //the result "insecure"
                        return false;
                    }
                    //If an attack was found, we don't can stop searching
                    break;
                }
                //End search if G does not change any more
                if(addedToG == false) break;
                //Indicate that we are past the first round
                init = false;
            }
        }
        //For the constructive variant insert refresh gadgets at all 
        //postions that were previously marked
        if(constructSecure){
            for(unsigned i=0; i<flawedValues.size(); i++){
                //Create a SNI refresh operation and use the output for 
                //the first multiplication gadget that uses this value
                builder.setInsertionPointAfterValue(flawedValues[i]);
                auto refOp = builder.create<secfir::SniRefreshOp>(
                            flawedValueGadgets[i]->getLoc(),
                            flawedValues[i].getType(),
                            flawedValues[i]);
                flawedValues[i].replaceUsesWithIf(refOp.getResult(), 
                            [flawedValueGadgets, i](OpOperand &operand){if(operand.getOwner() == flawedValueGadgets[i]) return true; else return false;});
                (*numberRefGadgets)++;
            }
        }
        //Return the result "probing secure" if the algorithm runs to the end 
        return true;
    }
}
}