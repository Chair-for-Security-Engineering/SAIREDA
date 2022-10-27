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

namespace circt{
namespace secfir{

using namespace circt;

    /// Function that checks that a specific value has an SNI gadget in all
    /// its computation path, i.e., it is not influenced by an input without
    /// SNI gadget in between. If that is true for all output values of an NI 
    /// gadget then the gadget is SNI (Barthe et al. in "Strong Non-Interference 
    /// and Type Directed Higher-Order Masking", 2016)
    ///
    /// value       Value that should be checked
    bool checkSniOfNi(
        mlir::Value value
    ){
        //Return false if it is an input
        if(value.isa<mlir::BlockArgument>()){
            return false;
        //Return true if the defining operation is and SNI gadget
        }else if(secfir::isa<secfir::SniAndGadgetOp>(value.getDefiningOp()) ||
                secfir::isa<secfir::SniRefreshOp>(value.getDefiningOp())){
            return true;
        }else{
            //Check all inputs to the defining operation
            for(mlir::Value input: value.getDefiningOp()->getOperands()){
                return checkSniOfNi(input);
            }
        }
    }

    /// Function that inserts a DoubleSNI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertDoubleSniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    ){
        //Create a SNI refresh operation for the RHS input of the AND operation
        auto refOp = builder.create<secfir::SniRefreshOp>(
                    andOp.getLoc(),
                    andOp.rhs().getType(),
                    andOp.rhs());
        //Create a SNI AND operation 
        auto sniAndOp = builder.create<secfir::SniAndGadgetOp>(
                    andOp.getLoc(),
                    andOp.getResult().getType(),
                    andOp.lhs(),
                    refOp.getResult());
        //Use the ouput of the SNI AND gadget instead of the ouput of the AND operation
        andOp.getResult().replaceAllUsesWith(sniAndOp.getResult());
    }

    /// Function that inserts a SNI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertSniMultiplication(
        secfir::AndPrimOp *andOp,
        mlir::OpBuilder *builder
    ){
        //Create a SNI AND operation 
        auto sniAndOp = builder->create<secfir::SniAndGadgetOp>(
                andOp->getLoc(),
                andOp->getResult().getType(),
                andOp->lhs(),
                andOp->rhs());
        //Use the ouput of the PINI gadget instead of the ouput of the AND operation
        andOp->getResult().replaceAllUsesWith(sniAndOp.getResult());        
    }

    /// Function that inserts an SNI refresh gadget at the input
    /// of an operation. 
    ///
    /// input       Input that should be refreshed
    /// user        Operation that should use the refreshed value
    /// builder     An operation builder for IR manipulation
    void insertSniRefresh(
        mlir::Value *input,
        mlir::Operation *user,
        mlir::OpBuilder *builder
    ){
        //Create a new refresh gadget
        auto refOp = builder->create<secfir::SniRefreshOp>(
                user->getLoc(),
                input->getType(),
                *input);
        //Connect the result with the input of the operation
        input->replaceUsesWithIf(refOp.getResult(), 
                [user](OpOperand &operand){if(operand.getOwner() == user) return true; else return false;});
    }

    /// Function that ensures that all intermediate values are used only once,
    /// except as input for SNI refresh gadgets. This property ensures NI of the 
    /// combinatorial logic and can be used as first step to ensure SNI, according
    /// to Barthe et al. in "Strong Non-Interference and Type Directed Higher-Order
    /// Masking", 2016.
    ///
    /// logicBlock      The combinatorial logic that should be secured
    /// builder         An operation builder for IR manipulation
    void insertSniRefreshForNi(
        secfir::CombLogicOp logicBlock,
        mlir::OpBuilder builder,
        unsigned *numberRefGadgets
    ){
        //Refresh all multiple usages of inputs to the combinatorial logic
        for(auto argument : logicBlock.getBodyBlock()->getArguments()){
            bool first = true;
            std::vector<mlir::Operation*> users;
            //Go through all operations using this argument and add all 
            //but the first to a list
            for(auto use :argument.getUsers()){
                if(!first){
                    users.push_back(use);
                }
                first = false;
            }
            //Create a new refresh gadget for all operations in the created list
            for(auto use: users){
                builder.setInsertionPointAfterValue(argument);
                auto refOp = builder.create<secfir::SniRefreshOp>(
                            logicBlock.getLoc(),
                            argument.getType(),
                            argument);
                (*numberRefGadgets)++;
                //Replace the input of the opeartion with the output of the 
                //refresh gadget
                argument.replaceUsesWithIf(refOp.getResult(), 
                    [use](OpOperand &operand){if(operand.getOwner() == use) return true; else return false;});
            }
        }
        //Refresh all multiple usages of intermediate results
        for (auto &internalOp : logicBlock.getBodyBlock()->getOperations()) {
            bool first = true;
            std::vector<mlir::Operation*> uses;
            //Go through all operations using the result value of this operation
            //and add all but the first to a list
            for(auto use : internalOp.getUsers()){
                if(!first){
                    uses.push_back(use);
                }
                first = false;
            }
            //Create a new refresh gadget for all operations in the created list
            for(auto use : uses){
                builder.setInsertionPointAfter(&internalOp);
                auto refOp = builder.create<secfir::SniRefreshOp>(
                            internalOp.getLoc(),
                            internalOp.getResults()[0].getType(),
                            internalOp.getResults()[0]);
                (*numberRefGadgets)++;
                //Replace the input of the opeartion with the output of the 
                //refresh gadget
                internalOp.getResults()[0].replaceUsesWithIf(refOp.getResult(), 
                    [use](OpOperand &operand){if(operand.getOwner() == use) return true; else return false;});
            }
        }
    }

    /// Function that inserts the logic of the DOM multiplication gadget.
    /// We added a register at each output to ensure SNI.
    ///
    /// gadget              The SNI multiplication gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertDOMAnd(
            secfir::SniAndGadgetOp gadget, 
            unsigned numberShares,
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            unsigned startIndexFreshRandomness
    ){
        //Get the attribute of the gadget that indicates which randomness bits to use
        mlir::ArrayAttr arrayAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        auto arrayRef = arrayAttr.getValue();
        auto vector = arrayRef.vec();
        //Distrubute the randomness assigned to this gadget
        unsigned randIndex = 0;
        std::vector<std::vector<unsigned>> rand(numberShares, std::vector<unsigned>(numberShares));
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=i+1; j<numberShares; j++){
                rand[i][j] =  vector.at(randIndex).dyn_cast<mlir::IntegerAttr>().getInt();
                rand[j][i] = rand[i][j];
                randIndex++;
            }
        }
        //Create a vector for the result shares
        std::vector<mlir::Value> sharedResult(numberShares);  
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<mlir::Value> dummyValuesRhs(numberShares);
        std::vector<mlir::Value> dummyValuesLhs(numberShares);
        std::vector<mlir::Value> sharesRhs(numberShares);
        std::vector<mlir::Value> sharesLhs(numberShares);
        bool dummyLhs = false;
        bool dummyRhs = false;
        //Check whether a dummy operation is required for one of the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(oldToNewValueMap.count(gadget.lhs()) == 0) dummyLhs = true;
        if(oldToNewValueMap.count(gadget.rhs()) == 0) dummyRhs = true;
        //Get the right hand input shares. Either the real shares, 
        //create a dummy operations, or take an existing dummy operations
        if(dummyRhs){
            if(dummyMap.count(gadget.rhs()) == 0){
                for(unsigned i=0; i<numberShares; i++){
                    secfir::ShareType shareDomain = secfir::ShareType::get(
                                    opBuilder.getContext(), 1, i);
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                        gadget.getLoc(),
                        shareDomain,
                        dummyValue);
                    dummyValuesRhs[i] = constOp.getResult();
                }
            }else{
                dummyValuesRhs = dummyMap[gadget.rhs()];
            }
            sharesRhs = dummyValuesRhs;
        }else{
            sharesRhs = oldToNewValueMap[gadget.rhs()];
        }
        //Get the left hand input shares. Either the real shares, 
        //create a dummy operations, or take an existing dummy operations
        if(dummyLhs){
            if(dummyMap.count(gadget.lhs()) == 0){
                for(unsigned i=0; i<numberShares; i++){
                    secfir::ShareType shareDomain = secfir::ShareType::get(
                                    opBuilder.getContext(), 1, i);
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                        gadget.getLoc(),
                        shareDomain,
                        dummyValue);
                    dummyValuesLhs[i] = constOp.getResult();
                }
            }else{
                dummyValuesLhs = dummyMap[gadget.lhs()];
            }
            sharesLhs = dummyValuesLhs;
        }else{
            sharesLhs = oldToNewValueMap[gadget.lhs()];
        }
        //Define intermediate variables
        std::vector<std::vector<mlir::Value>> u(numberShares, std::vector<mlir::Value>(numberShares));
        //Create the DOM multiplication logic
        for(unsigned i=0; i<numberShares; i++){
            secfir::ShareType shareDomain_i = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, i);
            std::vector<mlir::Value> temp;
            for(unsigned j=0; j<numberShares; j++){
                if(j==i) continue;
                auto and_ab_ij = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        sharesLhs[i],
                        sharesRhs[j]);
                auto xor_rand = opBuilder.create<secfir::XorPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        and_ab_ij.getResult(),
                        moduleArguments[startIndexFreshRandomness + rand[i][j]]);
                auto reg_xor = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        xor_rand.getResult(),
                        moduleArguments[0],
                        opBuilder.getStringAttr("reg" + std::to_string(i)));
                if(temp.size() > 0){
                    auto xor_reg = opBuilder.create<secfir::XorPrimOp>(
                            gadget.getLoc(),
                            shareDomain_i,
                            reg_xor.getResult(),
                            temp[temp.size()-1]);
                    temp.push_back(xor_reg.getResult());
                }else{
                    temp.push_back(reg_xor.getResult());
                }
            }
            auto and_ab_i = opBuilder.create<secfir::AndPrimOp>(
                    gadget.getLoc(),
                    shareDomain_i,
                    sharesLhs[i],
                    sharesRhs[i]);
            auto xor_temp = opBuilder.create<secfir::XorPrimOp>(
                    gadget.getLoc(),
                    shareDomain_i,
                    and_ab_i.getResult(),
                    temp[temp.size()-1]);
            auto reg_out = opBuilder.create<secfir::RegOp>( 
                    gadget.getLoc(),
                    shareDomain_i,
                    xor_temp.getResult(),
                    moduleArguments[0],
                    opBuilder.getStringAttr("reg" + std::to_string(i)));
            sharedResult[i] = reg_out.getResult();
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        gadget.removeAttr("ToShare");
        // auto alreadyShared = opBuilder.getBoolAttr(true);
        // gadget.setAttr("Shared", alreadyShared);
        //Update list of parallel shares for all the created shares
        for(mlir::Value share : sharedResult){
            //Get an instance of the current share domain
            secfir::ShareType shareType = share.getType().dyn_cast<secfir::ShareType>();
            //Add all parallel shares to the list of parallel shares
            for(mlir::Value parallelShare : sharedResult){
                //Ignore the same share
                if(parallelShare == share) continue;
                //Add the parallel share to the list of the current share
                shareType.setParallelShare(share, parallelShare);
            }
        }
        //Map the result shares to the result signal of the old module
        oldToNewValueMap[gadget.getResult()] = sharedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyLhs) dummyMap[gadget.lhs()] = dummyValuesLhs;
        if(dummyRhs) dummyMap[gadget.rhs()] = dummyValuesRhs;
        //Mark following operations that use the result as to be shared
        // auto shareIt = opBuilder.getBoolAttr(true);
        // for(auto inst : gadget.getResult().getUsers()){
        //     if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
        //         inst->setAttr("ToShare", shareIt);
        //     }
        // }
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadget.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[gadget.getResult()].size(); shareId++){
                dummyMap[gadget.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[gadget.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }


    /// Function that inserts the logic of a single DOM multiplication 
    /// We add a register at each output to ensure SNI
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeDomMultiplication(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<mlir::Value> &sharedLhs,
            std::vector<mlir::Value> &sharedRhs,
            std::vector<mlir::Value> &sharedResult,
            std::vector<mlir::Value> &randomness,
            mlir::Value clk
    ){
        //Ensure same number of shares for both inputs
        assert(sharedLhs.size() == sharedRhs.size() &&
                 "Number of shares need to be equal for both inputs!");
        assert(sharedLhs.size() == sharedResult.size() &&
                 "Number of shares need to be equal for inputs and result!");
        //Get number of shares
        unsigned numberShares = sharedLhs.size();
        //Mapping from 2D randomness indices to 1D indices
        unsigned randIndex = 0;
        std::vector<std::vector<unsigned>> rand(numberShares, 
                        std::vector<unsigned>(numberShares));
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=i+1; j<numberShares; j++){
                rand[i][j] =  randIndex;
                rand[j][i] = rand[i][j];
                //Verify that enough randomness is provided
                assert(randIndex < randomness.size() && "More randomness required!");
                randIndex++;
            }
        }
        secfir::UIntType uintType = secfir::UIntType::get(
                                 opBuilder.getContext(), 1);
        //Define intermediate variables
        std::vector<std::vector<mlir::Value>> u(numberShares, 
                        std::vector<mlir::Value>(numberShares));
        //Create the DOM multiplication logic
        for(unsigned i=0; i<numberShares; i++){
            std::vector<mlir::Value> temp;
            for(unsigned j=0; j<numberShares; j++){
                if(j==i) continue;
                auto and_ab_ij = opBuilder.create<secfir::AndPrimOp>(
                        location,
                        uintType,
                        sharedLhs[i],
                        sharedRhs[j]);
                auto xor_rand = opBuilder.create<secfir::XorPrimOp>(
                        location,
                        and_ab_ij.getResult().getType(),
                        and_ab_ij.getResult(),
                        randomness[rand[i][j]]);
                auto reg_xor = opBuilder.create<secfir::RegOp>(
                        location,
                        xor_rand.getResult().getType(),
                        xor_rand.getResult(),
                        clk,
                        opBuilder.getStringAttr("_dom_inter" + std::to_string(i)));
                if(temp.size() > 0){
                    auto xor_reg = opBuilder.create<secfir::XorPrimOp>(
                            location,
                            reg_xor.getResult().getType(),
                            reg_xor.getResult(),
                            temp[temp.size()-1]);
                    temp.push_back(xor_reg.getResult());
                }else{
                    temp.push_back(reg_xor.getResult());
                }
            }
            auto and_ab_i = opBuilder.create<secfir::AndPrimOp>(
                    location,
                    sharedLhs[i].getType(),
                    sharedLhs[i],
                    sharedRhs[i]);
            auto xor_temp = opBuilder.create<secfir::XorPrimOp>(
                    location,
                    and_ab_i.getResult().getType(),
                    and_ab_i.getResult(),
                    temp[temp.size()-1]);
            auto reg_out = opBuilder.create<secfir::RegOp>( 
                    location,
                    xor_temp.getResult().getType(),
                    xor_temp.getResult(),
                    clk,
                    opBuilder.getStringAttr("dom_out" + std::to_string(i)));
            sharedResult[i] = reg_out.getResult();
        }
    }

    /// Function that inserts the logic of the SNI refresh gadget.
    /// DOM multiplication gadget with constant input b=(1,0,...,0)
    /// and registers at the outputs to ensure SNI. Intermediate registers
    /// that are obsolete for security are removed.
    ///
    /// gadget              The SNI refresh gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertDOMRefresh(
            secfir::SniRefreshOp gadget, 
            unsigned numberShares,
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            mlir::Block::BlockArgListType moduleArguments, 
            unsigned startIndexFreshRandomness
    ){
        //Get the attribute of the gadget that indicates which randomness bits to use
        mlir::ArrayAttr arrayAttr = gadget.getAttrOfType<mlir::ArrayAttr>("RandIndices");
        auto arrayRef = arrayAttr.getValue();
        auto vector = arrayRef.vec();
        //Distrubute the randomness assigned to this gadget
        unsigned randIndex = 0;
        std::vector<std::vector<unsigned>> rand(numberShares, std::vector<unsigned>(numberShares));
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=i+1; j<numberShares; j++){
                rand[i][j] =  vector.at(randIndex).dyn_cast<mlir::IntegerAttr>().getInt();
                rand[j][i] = rand[i][j];
                randIndex++;
            }
        }
        //Create a vector for the result shares
        std::vector<mlir::Value> sharedResult(numberShares);  
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<mlir::Value> dummyValuesInput(numberShares);
        std::vector<mlir::Value> sharesInput(numberShares);
        bool dummy = false;
        //Check whether a dummy operation is required for the input.
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(oldToNewValueMap.count(gadget.input()) == 0) dummy = true;
        //Get the input shares. Either the real shares, 
        //create a dummy operations, or take an existing dummy operations
        if(dummy){
            if(dummyMap.count(gadget.input()) == 0){
                for(unsigned i=0; i<numberShares; i++){
                    secfir::ShareType shareDomain = secfir::ShareType::get(
                                    opBuilder.getContext(), 1, i);
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                        gadget.getLoc(),
                        shareDomain,
                        dummyValue);
                    dummyValuesInput[i] = constOp.getResult();
                }
            }else{
                dummyValuesInput = dummyMap[gadget.input()];
            }
            sharesInput = dummyValuesInput;
        }else{
            sharesInput = oldToNewValueMap[gadget.input()];
        }
        //Create the logic of the refresh gadget
        for(unsigned i=0; i<numberShares; i++){
            secfir::ShareType shareDomain_i = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, i);
            std::vector<mlir::Value> temp;
            temp.push_back(sharesInput[i]);
            for(unsigned j=0; j<numberShares; j++){
                if(j==i) continue;
                auto xor_rand = opBuilder.create<secfir::XorPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        moduleArguments[startIndexFreshRandomness + rand[i][j]],
                        temp[temp.size()-1]);
                temp.push_back(xor_rand.getResult());
            }
            auto reg = opBuilder.create<secfir::RegOp>(
                    gadget.getLoc(), 
                    shareDomain_i, 
                    temp[temp.size()-1], 
                    moduleArguments[0],
                    opBuilder.getStringAttr("refresh" + std::to_string(i)));
            sharedResult[i] = reg.getResult();
        }
        //Mark the original operation as shared and remove 
        //the indication that it should be shared
        gadget.removeAttr("ToShare");
        // auto alreadyShared = opBuilder.getBoolAttr(true);
        // gadget.setAttr("Shared", alreadyShared);
        //Update list of parallel shares for all the created shares
        for(mlir::Value share : sharedResult){
            //Get an instance of the current share domain
            secfir::ShareType shareType = share.getType().dyn_cast<secfir::ShareType>();
            //Add all parallel shares to the list of parallel shares
            for(mlir::Value parallelShare : sharedResult){
                //Ignore the same share
                if(parallelShare == share) continue;
                //Add the parallel share to the list of the current share
                shareType.setParallelShare(share, parallelShare);
            }
        }
        //Map the result shares to the result signal of the old module
        oldToNewValueMap[gadget.getResult()] = sharedResult;
        //Map possible dummy values to the corresponding input value
        if(dummy) dummyMap[gadget.input()] = dummyValuesInput;
        //Mark following operations that use the result as to be shared
        // auto shareIt = opBuilder.getBoolAttr(true);
        // for(auto inst : gadget.getResult().getUsers()){
        //     if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
        //         inst->setAttr("ToShare", shareIt);
        //     }
        // }
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadget.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[gadget.getResult()].size(); shareId++){
                dummyMap[gadget.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[gadget.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }

    /// Function that inserts the logic of a single DOM refresh gadget. 
    /// We add a register at each output to ensure SNI
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedInput         Vector of shares of the LHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeDomRefresh(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<mlir::Value> &sharedInput,
            std::vector<mlir::Value> &sharedResult,
            std::vector<mlir::Value> &randomness,
            mlir::Value clk
    ){
        //Ensure same number of shares for both input and output
        assert(sharedInput.size() == sharedResult.size() &&
                 "Number of shares need to be equal for inputs and result!");
        //Get number of shares
        unsigned numberShares = sharedInput.size();
        //Mapping from 2D randomness indices to 1D indices
        unsigned randIndex = 0;
        std::vector<std::vector<unsigned>> rand(numberShares, std::vector<unsigned>(numberShares));
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=i+1; j<numberShares; j++){
                rand[i][j] =  randIndex;
                rand[j][i] = rand[i][j];
                //Verify that enough randomness is provided
                assert(randIndex < randomness.size() && "More randomness required!");
                randIndex++;
            }
        }
        //Create the logic of the refresh gadget
        for(unsigned i=0; i<numberShares; i++){
            std::vector<mlir::Value> temp;
            temp.push_back(sharedInput[i]);
            for(unsigned j=0; j<numberShares; j++){
                if(j==i) continue;
                auto xor_rand = opBuilder.create<secfir::XorPrimOp>(
                        location,
                        temp[temp.size()-1].getType(),
                        randomness[rand[i][j]],
                        temp[temp.size()-1]);
                temp.push_back(xor_rand.getResult());
            }
            auto reg = opBuilder.create<secfir::RegOp>(
                    location, 
                    temp[temp.size()-1].getType(), 
                    temp[temp.size()-1], 
                    clk,
                    opBuilder.getStringAttr("refresh" + std::to_string(i)));
            sharedResult[i] = reg.getResult();
        }
    }

}
}