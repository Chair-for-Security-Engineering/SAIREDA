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

    /// Function that inserts a PINI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertPiniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    ){
        //Create a PINI AND gadget with the same inputs as the AND operation
        auto piniOp = builder.create<secfir::PiniAndGadgetOp>(
                    andOp.getLoc(),
                    andOp.getResult().getType(),
                    andOp.lhs(),
                    andOp.rhs());
        //Use the ouput of the PINI gadget instead of the ouput of the AND operation
        andOp.getResult().replaceAllUsesWith(piniOp.getResult());
    }

    /// Function that inserts a multiplication gadget that is both
    /// PINI and SNI, which replaces an AND operation, where the 
    /// references are replaced but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertSpiniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    ){
        //Create a PINI AND gadget with the same inputs as the AND operation
        auto spiniOp = builder.create<secfir::SniPiniAndGadgetOp>(
                    andOp.getLoc(),
                    andOp.getResult().getType(),
                    andOp.lhs(),
                    andOp.rhs());
        //Use the ouput of the PINI gadget instead of the ouput of the AND operation
        andOp.getResult().replaceAllUsesWith(spiniOp.getResult());
    }

    /// Function that shares a connect operation by connecting each share of the
    /// source to the correspondng share of the destination
    ///
    /// regOp               The unshared register operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// numberShares        The number of shares
    void shareConnect(
            secfir::ConnectOp connectOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            unsigned numberShares
    ){  
        //Get input and output shares and connect each individually
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            mlir::Value dest = oldToNewValueMap[connectOp.dest()][shareId];
            mlir::Value src = oldToNewValueMap[connectOp.src()][shareId];
            //Create new op
            auto newOp = opBuilder.create<secfir::ConnectOp>(
                    connectOp.getLoc(), dest, src);
            //Copy all attributes to the new operation, except for the 
            //consumed "ToShare" attribute
            newOp.setAttrs(connectOp.getAttrs());
            newOp.removeAttr("ToShare");
            connectOp.removeAttr("ToShare");
            auto alreadyShared = opBuilder.getBoolAttr(true);
            connectOp.setAttr("Shared", alreadyShared);
            //Move insertion point for next operation
            opBuilder.setInsertionPointAfter(newOp);
        }     
    }

    /// Function that shares a register operation by creating a new register
    /// for each share domain.
    ///
    /// regOp               The unshared register operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareRegister(
            secfir::RegOp regOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            unsigned numberShares
    ){
        //Create a vector for the result shares
        std::vector<mlir::Value> sharedResult(numberShares);  
        //Get input and output shares and connect each individually
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            mlir::Value src = oldToNewValueMap[regOp.input()][shareId];
            secfir::ShareType type = secfir::ShareType::get(
                                opBuilder.getContext(), 1, shareId);
            //Create new op
            auto newOp = opBuilder.create<secfir::RegOp>(
                    regOp.getLoc(), 
                    type, 
                    src, 
                    oldToNewValueMap[regOp.clockVal()][0], 
                    regOp.nameAttr());
            //Copy all attributes to the new operation, except for the 
            //consumed "ToShare" attribute
            newOp.setAttrs(regOp.getAttrs());
            newOp.removeAttr("ToShare");
            //Add result share to the result vector
            sharedResult[shareId] = newOp.getResult();
            //Move insertion point for next operation
            opBuilder.setInsertionPointAfter(newOp);
        }    
        regOp.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        regOp.setAttr("Shared", alreadyShared);
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
        oldToNewValueMap[regOp.getResult()] = sharedResult;
        //Mark following operations that use the result as to be shared
        auto shareIt = opBuilder.getBoolAttr(true);
        for(auto inst : regOp.getResult().getUsers()){
            if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
                inst->setAttr("ToShare", shareIt);
            }
        }

        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(regOp.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[regOp.getResult()].size(); shareId++){
                dummyMap[regOp.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[regOp.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }

    /// Function that shares a XOR operation by creating a seperat instance for
    /// each share.
    ///
    /// xorOp               The unshared xor operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareXor(
            secfir::XorPrimOp xorOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            unsigned numberShares
    ){
        //Create a vector for the result shares
        std::vector<mlir::Value> sharedResult(numberShares);  
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<mlir::Value> dummyValuesRhs(numberShares);
        std::vector<mlir::Value> dummyValuesLhs(numberShares);
        bool dummyLhs = false;
        bool dummyRhs = false;
        //Check whether a dummy operation is required for one of the inputs
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(oldToNewValueMap.count(xorOp.lhs()) == 0) dummyLhs = true;
        if(oldToNewValueMap.count(xorOp.rhs()) == 0) dummyRhs = true;
        //Get the input shares and create a new XOR operation for each share
        for(unsigned shareId=0; shareId<numberShares; shareId++){
            //Get the left hand input for this share index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            mlir::Value lhs;
            if(!dummyLhs){
                lhs = oldToNewValueMap[xorOp.lhs()][shareId];
            }else{
                if(dummyMap.count(xorOp.lhs()) == 0){
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                            xorOp.getLoc(),
                            xorOp.getResult().getType(),
                            dummyValue);
                    lhs = constOp.getResult();
                }else{
                    lhs = dummyMap[xorOp.lhs()][shareId];
                }
            }
            //Get the right hand input for this share index. Either the 
            //real input, create a dummy operation, or take an existing dummy operation
            mlir::Value rhs;
            if(!dummyRhs){
                rhs = oldToNewValueMap[xorOp.rhs()][shareId];
            }else{
                if(dummyMap.count(xorOp.rhs()) == 0){
                    secfir::ConstantOp constOp=  opBuilder.create<secfir::ConstantOp>(
                            xorOp.getLoc(),
                            xorOp.getResult().getType(),
                            dummyValue);
                    rhs = constOp.getResult();
                }else{
                    rhs = dummyMap[xorOp.rhs()][shareId];
                }
            }
            secfir::ShareType type = secfir::ShareType::get(
                            opBuilder.getContext(), 1, shareId);
            //Create new operation
            auto newOp = opBuilder.create<secfir::XorPrimOp>(
                    xorOp.getLoc(), type, lhs, rhs);
            //Copy all attributes to the new operation, except for the 
            //consumed "ToShare" attribute
            newOp.setAttrs(xorOp.getAttrs());
            newOp.removeAttr("ToShare");
            //Add result share to the result vector
            sharedResult[shareId] = newOp.getResult();
            //Add possible dummy values to the corresponding vector
            if(dummyLhs) dummyValuesLhs[shareId] = newOp.lhs();
            if(dummyRhs) dummyValuesRhs[shareId] = newOp.rhs();
            //Move insertion point for next operation
            opBuilder.setInsertionPointAfter(newOp);
        }
        //Mark original operation as shared and remove the mark that
        //indicated it should be shared.
        xorOp.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        xorOp.setAttr("Shared", alreadyShared);
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
        oldToNewValueMap[xorOp.getResult()] = sharedResult;
        //Map possible dummy values to the corresponding input value
        if(dummyLhs) dummyMap[xorOp.lhs()] = dummyValuesLhs;
        if(dummyRhs) dummyMap[xorOp.rhs()] = dummyValuesRhs;

        //Mark following operations that use the result as to be shared
        auto shareIt = opBuilder.getBoolAttr(true);
        for(auto inst : xorOp.getResult().getUsers()){
            if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
                inst->setAttr("ToShare", shareIt);
            }
        }
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(xorOp.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[xorOp.getResult()].size(); shareId++){
                dummyMap[xorOp.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[xorOp.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }

    /// Function that shares a NOT operation inverting the share with domain ID 0 
    /// and forwarding all other shares. 
    ///
    /// notOp               The unshared not operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareNot(
            secfir::NotPrimOp notOp, 
            mlir::OpBuilder &opBuilder,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
            mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
            unsigned numberShares
    ){
        //Create a vector for the result shares
        std::vector<mlir::Value> sharedResult(numberShares);  
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        std::vector<mlir::Value> dummyValues(numberShares);
        bool dummy = false;
        //Check whether a dummy operation is required for the input.
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(oldToNewValueMap.count(notOp.input()) == 0) dummy = true;
        //Get the first share, if available the original share if not use 
        //a dummy variable.
        mlir::Value input;
        if(!dummy){
            input = oldToNewValueMap[notOp.input()][0];
        }else{
            if(dummyMap.count(notOp.input()) == 0){
                secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                        notOp.getLoc(),
                        notOp.getResult().getType(),
                        dummyValue);
                input = constOp.getResult();
                dummyValues[0] = constOp.getResult();
            }else{
                dummyValues[0] = dummyMap[notOp.input()][0];
            }
        }
        //Connect the first share to a not operation
        secfir::ShareType shareDomain_0 = secfir::ShareType::get(
                        opBuilder.getContext(), 1, 0);
        auto newOp = opBuilder.create<secfir::NotPrimOp>(
                notOp.getLoc(), shareDomain_0, input);
        //Copy all attributes to the new operation, except for the 
        //consumed "ToShare" attribute
        newOp.setAttrs(notOp.getAttrs());
        newOp.removeAttr("ToShare");
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        notOp.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        notOp.setAttr("Shared", alreadyShared);
        //Add all other input shares to the result vector.
        //Either the original value or a dummy value if necessary.
        sharedResult[0] = newOp.getResult();
        for(unsigned shareId=1; shareId<numberShares; shareId++){
            if(!dummy){
                sharedResult[shareId] = oldToNewValueMap[notOp.input()][shareId];
            }else{
                if(dummyMap.count(notOp.input()) == 0){
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                            notOp.getLoc(),
                            notOp.getResult().getType(),
                            dummyValue);
                    input = constOp.getResult();
                    sharedResult[shareId] = constOp.getResult();
                    dummyValues[shareId] = constOp.getResult();
                }else{
                    sharedResult[shareId] = dummyMap[notOp.input()][shareId];
                    dummyValues[shareId] = dummyMap[notOp.input()][shareId];
                }
            }
            //Add parallel shares to list in share domain zero
            shareDomain_0.setParallelShare(newOp.getResult(), sharedResult[shareId]);
        }
        //Move insertion point for next operation
        opBuilder.setInsertionPointAfter(newOp);
        //Map the result shares to the result signal of the old module
        oldToNewValueMap[notOp.getResult()] = sharedResult;
        if(dummy) dummyMap[notOp.input()] = dummyValues;
        //Mark following operations that use the result as to be shared
        auto shareIt = opBuilder.getBoolAttr(true);
        for(auto inst : notOp.getResult().getUsers())
            if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
                inst->setAttr("ToShare", shareIt);
            }
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(notOp.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[notOp.getResult()].size(); shareId++){
                dummyMap[notOp.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[notOp.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }

    /// Function that shares a node operation by removing it.
    ///
    /// nodeOp              The unshared node operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// numberShares        The number of shares
    void shareNode(
        secfir::NodeOp nodeOp,
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dummyMap,
        unsigned numberShares
    ){
        //Define variable to organize the usage of dummy input operations
        auto dummyValue = opBuilder.getBoolAttr(false);
        bool dummy = false;
        std::vector<mlir::Value> dummyValues(numberShares);
        //Check whether a dummy operation is required for the input.
        //A dummy value is required if the input value was not already shared
        //which can happen if the output of a register is used
        if(oldToNewValueMap.count(nodeOp.input()) == 0) dummy = true;
        //Use the input shares as shares for the output.
        //If available use the original input shares and dummy shares otherwise.
        if(!dummy){
            oldToNewValueMap[nodeOp.getResult()] = oldToNewValueMap[nodeOp.input()];
        }else{
            if(dummyMap.count(nodeOp.input()) == 0){
                for(unsigned shareId=0; shareId<numberShares; shareId++){
                    secfir::ConstantOp constOp = opBuilder.create<secfir::ConstantOp>(
                            nodeOp.getLoc(),
                            nodeOp.getResult().getType(),
                            dummyValue);
                    dummyValues[shareId] = constOp.getResult();
                }
                dummyMap[nodeOp.getResult()] = dummyValues;
            }else{
                dummyMap[nodeOp.getResult()] = dummyMap[nodeOp.input()];
            }
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        nodeOp.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        nodeOp.setAttr("Shared", alreadyShared);
        //Mark following operations that use the result as to be shared
        auto shareIt = opBuilder.getBoolAttr(true);
        for(auto inst : nodeOp.getResult().getUsers()){
            if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
                inst->setAttr("ToShare", shareIt);
            }
        }
    }

    /// Function that shares an output operation by marking all shares as outputs.
    ///
    /// outputOp            The unshared output operation
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// numberShares        The number of shares
    void shareOutput(
        secfir::OutputOp outputOp,
        mlir::OpBuilder &opBuilder,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &oldToNewValueMap,
        unsigned numberShares
    ){
        //Create a vector with all output shares
        mlir::SmallVector<mlir::Value, 1> outputValues;
        for(auto output : outputOp.getOperands()){
            for(size_t shareId=0; shareId<numberShares; shareId++){
                outputValues.push_back(oldToNewValueMap[output][shareId]);
            }
        }
        opBuilder.create<secfir::OutputOp>(outputOp.getLoc(), outputValues);

        //Mark the original output operation as shared and remove 
        //the indication that it should be shared
        outputOp.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        outputOp.setAttr("Shared", alreadyShared);
    }

    /// Function that inserts the logic of the HPC_2 gadget.
    /// Algorithm in Cassiers et al. "Hardware Private Circuits:
    /// From Trivial Composition to Full Verification", 2020.
    ///
    /// gadget              The PINI gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertHPC2(
            secfir::PiniAndGadgetOp gadget, 
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
        std::vector<std::vector<mlir::Value>> v(numberShares, std::vector<mlir::Value>(numberShares));
        //Create the HPC_2 gadget for the given inputs
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=0; j<numberShares; j++){
                if(i==j) continue;
                secfir::ShareType shareDomain_i = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, i);
                secfir::ShareType shareDomain_j = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, j);
                auto randReg = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        moduleArguments[startIndexFreshRandomness + rand[i][j]].getType(), 
                        moduleArguments[startIndexFreshRandomness + rand[i][j]], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("r" + std::to_string(i)+ std::to_string(j)));
                auto notLhs = opBuilder.create<secfir::NotPrimOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        sharesLhs[i]);
                auto and_u = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        randReg.getResult(),
                        notLhs.getResult());

                auto xor_v = opBuilder.create<secfir::XorPrimOp>(
                        gadget.getLoc(),
                        shareDomain_j,
                        sharesRhs[j],
                        moduleArguments[startIndexFreshRandomness + rand[i][j]]);
                u[i][j] = and_u.getResult();
                v[i][j] = xor_v.getResult();
            }
        }
        for(unsigned i=0; i<numberShares; i++){
            secfir::ShareType shareDomain_i = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, i);
            auto regRhs = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        sharesRhs[i], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("b" + std::to_string(i)));
            auto and_ab = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        sharesLhs[i],
                        regRhs.getResult());
            auto reg_ab = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        and_ab.getResult(), 
                        moduleArguments[0],
                        opBuilder.getStringAttr("ab" + std::to_string(i)));

            std::vector<mlir::Value> temp;
            for(unsigned j=0; j<numberShares; j++){
                if(i==j) continue;
                auto reg_v = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        v[i][j], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("v" + std::to_string(i)+ std::to_string(j)));
                auto and_av = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        sharesLhs[i],
                        reg_v.getResult());
                auto reg_av = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        and_av.getResult(), 
                        moduleArguments[0],
                        opBuilder.getStringAttr("av" + std::to_string(i)+ std::to_string(j)));
                auto reg_u = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        u[i][j], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("u" + std::to_string(i)+ std::to_string(j)));
                auto xor_avu = opBuilder.create<secfir::XorPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        reg_av.getResult(),
                        reg_u.getResult());
                if(temp.size() > 0){
                    auto xor_sum = opBuilder.create<secfir::XorPrimOp>(
                            gadget.getLoc(),
                            shareDomain_i,
                            xor_avu.getResult(),
                            temp[temp.size()-1]);
                    temp.push_back(xor_sum.getResult());
                }else{
                    temp.push_back(xor_avu.getResult());
                }
            }
            auto xor_sum = opBuilder.create<secfir::XorPrimOp>(
                    gadget.getLoc(),
                    shareDomain_i,
                    reg_ab.getResult(),
                    temp[temp.size()-1]);
            sharedResult[i] = xor_sum.getResult();
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        gadget.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        gadget.setAttr("Shared", alreadyShared);
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
        auto shareIt = opBuilder.getBoolAttr(true);
        for(auto inst : gadget.getResult().getUsers()){
            if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
                inst->setAttr("ToShare", shareIt);
            }
        }
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadget.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[gadget.getResult()].size(); shareId++){
                dummyMap[gadget.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[gadget.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }

    /// Function that inserts the logic of the HPC_2 gadget with an
    /// additional output register, which makes it SNI as well.
    /// Algorithm in Cassiers et al. "Hardware Private Circuits:
    /// From Trivial Composition to Full Verification", 2020.
    ///
    /// gadget              The PINI gadget operation
    /// numberShares        The number of shares    
    /// opBuilder           An operation builder for IR manipulation
    /// oldToNewValueMap    A map from unshared to shared values
    /// dummyMap            A map from unshared to shared dummy values
    /// moduleArguments     List of module arguments that contains fresh randomness
    /// startIndexFreshRandomness   The index of the module argument list where the 
    ///                                 fresh randomness starts
    void insertHPC2withOutputRegister(
            secfir::SniPiniAndGadgetOp gadget, 
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
        std::vector<std::vector<mlir::Value>> v(numberShares, std::vector<mlir::Value>(numberShares));
        //Create the HPC_2 gadget for the given inputs
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=0; j<numberShares; j++){
                if(i==j) continue;
                secfir::ShareType shareDomain_i = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, i);
                secfir::ShareType shareDomain_j = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, j);
                auto randReg = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        moduleArguments[startIndexFreshRandomness + rand[i][j]].getType(), 
                        moduleArguments[startIndexFreshRandomness + rand[i][j]], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("r" + std::to_string(i)+ std::to_string(j)));
                auto notLhs = opBuilder.create<secfir::NotPrimOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        sharesLhs[i]);
                auto and_u = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        randReg.getResult(),
                        notLhs.getResult());

                auto xor_v = opBuilder.create<secfir::XorPrimOp>(
                        gadget.getLoc(),
                        shareDomain_j,
                        sharesRhs[j],
                        moduleArguments[startIndexFreshRandomness + rand[i][j]]);
                u[i][j] = and_u.getResult();
                v[i][j] = xor_v.getResult();
            }
        }
        for(unsigned i=0; i<numberShares; i++){
            secfir::ShareType shareDomain_i = secfir::ShareType::get(
                                 opBuilder.getContext(), 1, i);
            auto randRhs = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        sharesRhs[i], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("b" + std::to_string(i)));
            auto and_ab = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        sharesLhs[i],
                        randRhs.getResult());
            auto reg_ab = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        and_ab.getResult(), 
                        moduleArguments[0],
                        opBuilder.getStringAttr("ab" + std::to_string(i)));
            std::vector<mlir::Value> temp;
            for(unsigned j=0; j<numberShares; j++){
                if(i==j) continue;
                auto reg_v = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        v[i][j], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("v" + std::to_string(i)+ std::to_string(j)));
                auto and_av = opBuilder.create<secfir::AndPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        sharesLhs[i],
                        reg_v.getResult());
                auto reg_av = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        and_av.getResult(), 
                        moduleArguments[0],
                        opBuilder.getStringAttr("av" + std::to_string(i)+ std::to_string(j)));
                auto reg_u = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        u[i][j], 
                        moduleArguments[0],
                        opBuilder.getStringAttr("u" + std::to_string(i)+ std::to_string(j)));
                auto xor_avu = opBuilder.create<secfir::XorPrimOp>(
                        gadget.getLoc(),
                        shareDomain_i,
                        reg_av.getResult(),
                        reg_u.getResult());
                if(temp.size() > 0){
                    auto xor_sum = opBuilder.create<secfir::XorPrimOp>(
                            gadget.getLoc(),
                            shareDomain_i,
                            xor_avu.getResult(),
                            temp[temp.size()-1]);
                    temp.push_back(xor_sum.getResult());
                }else{
                    temp.push_back(xor_avu.getResult());
                }
            }
            auto xor_sum = opBuilder.create<secfir::XorPrimOp>(
                    gadget.getLoc(),
                    shareDomain_i,
                    reg_ab.getResult(),
                    temp[temp.size()-1]);

            auto reg_out = opBuilder.create<secfir::RegOp>(
                        gadget.getLoc(), 
                        shareDomain_i, 
                        xor_sum.getResult(), 
                        moduleArguments[0],
                        opBuilder.getStringAttr("c" + std::to_string(i)));
            sharedResult[i] = reg_out.getResult();
        }
        //Mark the original not operation as shared and remove 
        //the indication that it should be shared
        gadget.removeAttr("ToShare");
        auto alreadyShared = opBuilder.getBoolAttr(true);
        gadget.setAttr("Shared", alreadyShared);
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
        auto shareIt = opBuilder.getBoolAttr(true);
        for(auto inst : gadget.getResult().getUsers()){
            if(!inst->hasAttrOfType<mlir::IntegerAttr>("Shared")){
                inst->setAttr("ToShare", shareIt);
            }
        }
        //Check whether the result was already used and replaced by a dummy value.
        //If so then replace the dummy value with the real result
        if(dummyMap.count(gadget.getResult()) != 0){
            for(unsigned shareId=0; shareId<dummyMap[gadget.getResult()].size(); shareId++){
                dummyMap[gadget.getResult()][shareId].replaceAllUsesWith(sharedResult[shareId]);
                dummyMap[gadget.getResult()][shareId].getDefiningOp()->erase();
            }
        }
    }
}
}