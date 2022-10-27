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

    /// Function that inserts a CINI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertCiniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    ){
        //Create a PINI AND gadget with the same inputs as the AND operation
        auto ciniOp = builder.create<secfir::CiniAndGadgetOp>(
                    andOp.getLoc(),
                    andOp.getResult().getType(),
                    andOp.lhs(),
                    andOp.rhs());
        //Use the ouput of the PINI gadget instead of the ouput of the AND operation
        andOp.getResult().replaceAllUsesWith(ciniOp.getResult());
    }

    /// Function that inserts an ICINI multiplication gadget that 
    /// replaces an AND operation, where the references are replaced
    /// but the old operation is not deleted.
    ///
    /// andOp       AND operation that should be replaced
    /// builder     An operation builder for IR manipulation
    void insertIciniMultiplication(
        secfir::AndPrimOp andOp,
        mlir::OpBuilder builder
    ){
        //Create a PINI AND gadget with the same inputs as the AND operation
        auto iciniOp = builder.create<secfir::IciniAndGadgetOp>(
                    andOp.getLoc(),
                    andOp.getResult().getType(),
                    andOp.lhs(),
                    andOp.rhs());
        //Use the ouput of the PINI gadget instead of the ouput of the AND operation
        andOp.getResult().replaceAllUsesWith(iciniOp.getResult());
    }

    /// Function that inserts the logic of the HPC_correction gadget.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeCiniHPC1(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<std::vector<mlir::Value>> &sharedLhs,
            std::vector<std::vector<mlir::Value>> &sharedRhs,
            std::vector<std::vector<mlir::Value>> &sharedResult,
            std::vector<mlir::Value> &randomness,
            std::vector<mlir::Value> clk,
            bool pipeline
    ){
        //Ensure same number of shares for both inputs
        assert(sharedLhs.size() == sharedRhs.size() &&
                 "Number of shares need to be equal for both inputs!");
        assert(sharedLhs.size() == sharedResult.size() &&
                 "Number of shares need to be equal for inputs and result!");

        //Get number of shares
        unsigned numberShares = sharedLhs.size();
        unsigned numberDuplications = sharedLhs[0].size();
        //Mapping from 2D randomness indices to 1D indices
        unsigned randIndex = 0;
        std::vector<mlir::Value> randomness_ref(numberShares*(numberShares-1)/2);
        std::vector<mlir::Value> randomness_mul(numberShares*(numberShares-1)/2);
        std::vector<std::vector<unsigned>> rand(numberShares, std::vector<unsigned>(numberShares));
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=i+1; j<numberShares; j++){
                rand[i][j] =  randIndex;
                rand[j][i] = rand[i][j];
                //Verify that enough randomness is provided
                assert(randomness_ref.size()+randIndex < randomness.size() && "More randomness required!");
                //Divide randomness for refresh and multiplication
                randomness_ref[randIndex] = randomness[randIndex];
                randomness_mul[randIndex] = randomness[randomness_ref.size()+randIndex];
                //Increment randomness index
                randIndex++;
            }
        }

        //Define intermediate variables
        std::vector<std::vector<mlir::Value>> v_tilde(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<std::vector<mlir::Value>>> v(numberShares, std::vector<std::vector<mlir::Value>>(numberShares, std::vector<mlir::Value>(numberDuplications)));
        std::vector<std::vector<std::vector<mlir::Value>>> z(numberShares, std::vector<std::vector<mlir::Value>>(numberShares, std::vector<mlir::Value>(numberDuplications)));
        secfir::UIntType uintType = secfir::UIntType::get(
                                 opBuilder.getContext(), 1);
        std::vector<std::vector<mlir::Value>> lhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Insert registers for LHS if gadget should be pipelined internally
        for(unsigned share_i=0; share_i<numberShares; share_i++){
            for(unsigned dupId=0; dupId<numberDuplications; dupId++){
                if(pipeline){
                    auto regLhs = opBuilder.create<secfir::RegOp>(
                            location, 
                            sharedLhs[share_i][dupId].getType(),
                            sharedLhs[share_i][dupId],
                            clk[dupId],
                            opBuilder.getStringAttr("_hpc_correct_a_s" + std::to_string(share_i)+ "_d" + std::to_string(dupId)));
                    lhs[share_i][dupId] = regLhs.result();
                }else{
                    lhs[share_i][dupId] = sharedLhs[share_i][dupId];
                }
            }
        }
        //Masking of RHS
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                std::vector<mlir::Value> temp_sum;
                temp_sum.push_back(sharedRhs[share_i][dupId]);
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    if(share_i == share_j) continue;
                    auto xor_v = opBuilder.create<secfir::XorPrimOp>(
                        location,
                        uintType,
                        temp_sum[temp_sum.size()-1],
                        randomness_ref[rand[share_i][share_j]]);
                    xor_v.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                    temp_sum.push_back(xor_v.getResult());
                }

                v_tilde[share_i][dupId] = temp_sum[temp_sum.size()-1];
            }
        }
        //Correction of RHS and first register stage
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    mlir::ValueRange valRange(v_tilde[share_i]);
                    auto majority = opBuilder.create<secfir::MajorityPrimOp>(
                        location,
                        uintType,
                        valRange);
                     auto reg_v = opBuilder.create<secfir::RegOp>(
                        location, 
                        majority.getResult().getType(), 
                        majority.getResult(), 
                        clk[dupId],
                        opBuilder.getStringAttr("_cini_mul_v" + std::to_string(share_i)  + std::to_string(share_j) + std::to_string(dupId)));
                    v[share_i][share_j][dupId] = reg_v.getResult();
                }
            }
        }
        //Multiplication, refresh and second register stage
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    mlir::Value reg_in;
                    auto and_ab = opBuilder.create<secfir::AndPrimOp>(
                            location,
                            lhs[share_i][dupId].getType(),
                            lhs[share_i][dupId],
                            v[share_j][share_i][dupId]);
                    reg_in = and_ab.getResult();
                    if(share_i != share_j){
                        auto xor_rand = opBuilder.create<secfir::XorPrimOp>(
                            location,
                            uintType,
                            and_ab.getResult(),
                            randomness_mul[rand[share_i][share_j]]);
                        xor_rand.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                        reg_in = xor_rand.getResult();
                    }
                    auto reg_z = opBuilder.create<secfir::RegOp>(
                        location, 
                        reg_in.getType(), 
                        reg_in, 
                        clk[dupId],
                        opBuilder.getStringAttr("_cini_mul_z" + std::to_string(share_i)  + std::to_string(share_j) + std::to_string(dupId)));
                    z[share_i][share_j][dupId] = reg_z.getResult();
                }
            }
        }
        //Reduction
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                std::vector<mlir::Value> temp_sum;
                temp_sum.push_back(z[share_i][share_i][dupId]);
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    if(share_i == share_j) continue;
                    auto xor_red = opBuilder.create<secfir::XorPrimOp>(
                            location,
                            z[share_i][share_j][dupId].getType(),
                            temp_sum[temp_sum.size()-1],
                            z[share_i][share_j][dupId]);
                    temp_sum.push_back(xor_red.getResult());
                }
                sharedResult[share_i][dupId] = temp_sum[temp_sum.size()-1];
            }
        }
    }

    /// Function that inserts the logic of the HPC_2^C gadget.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers        
    void placeCiniHPC2(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<std::vector<mlir::Value>> &sharedLhs,
            std::vector<std::vector<mlir::Value>> &sharedRhs,
            std::vector<std::vector<mlir::Value>> &sharedResult,
            std::vector<mlir::Value> &randomness,
            std::vector<mlir::Value> clk,
            bool pipeline
    ){
        //Ensure same number of shares for both inputs
        assert(sharedLhs.size() == sharedRhs.size() &&
                 "Number of shares need to be equal for both inputs!");
        assert(sharedLhs.size() == sharedResult.size() &&
                 "Number of shares need to be equal for inputs and result!");
        //Get number of shares
        unsigned numberShares = sharedLhs.size();
        unsigned numberDuplications = sharedLhs[0].size();
        assert((numberShares <= 3 && numberDuplications <= 5) && "HPC_2^C is insecure for the selected configuration!");
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

        //Define intermediate variables
        std::vector<std::vector<std::vector<mlir::Value>>> v_tilde(
                    numberShares, std::vector<std::vector<mlir::Value>>(
                        numberShares, std::vector<mlir::Value>(numberDuplications)));
        secfir::UIntType uintType = secfir::UIntType::get(
                                 opBuilder.getContext(), 1);
        std::vector<std::vector<mlir::Value>> lhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Insert registers for LHS if gadget should be pipelined internally
        for(unsigned share_i=0; share_i<numberShares; share_i++){
            for(unsigned dupId=0; dupId<numberDuplications; dupId++){
                if(pipeline){
                    auto regLhs = opBuilder.create<secfir::RegOp>(
                            location, 
                            sharedLhs[share_i][dupId].getType(),
                            sharedLhs[share_i][dupId],
                            clk[dupId],
                            opBuilder.getStringAttr("_hpc_correct_a_s" + std::to_string(share_i)+ "_d" + std::to_string(dupId)));
                    lhs[share_i][dupId] = regLhs.result();
                }else{
                    lhs[share_i][dupId] = sharedLhs[share_i][dupId];
                }
            }
        }
        //Masking of RHS
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    if(share_i == share_j) continue;
                    auto xor_v = opBuilder.create<secfir::XorPrimOp>(
                        location,
                        uintType,
                        sharedRhs[share_j][dupId],
                        randomness[rand[share_i][share_j]]);
                    v_tilde[share_i][share_j][dupId] = xor_v.getResult();
                }
            }
        }
        //Correction and partial products
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                auto regRhs = opBuilder.create<secfir::RegOp>(
                        location, 
                        sharedRhs[share_i][dupId].getType(), 
                        sharedRhs[share_i][dupId], 
                        clk[dupId],
                        opBuilder.getStringAttr("_hpc_correct_b_s" + std::to_string(share_i)+ "_d" + std::to_string(dupId)));
                auto and_ab = opBuilder.create<secfir::AndPrimOp>(
                            location,
                            lhs[share_i][dupId].getType(),
                            lhs[share_i][dupId],
                            regRhs.getResult());
                auto reg_ab = opBuilder.create<secfir::RegOp>(
                            location, 
                            and_ab.getResult().getType(), 
                            and_ab.getResult(), 
                            clk[dupId],
                            opBuilder.getStringAttr("_hpc_correct_ab_s" + std::to_string(share_i) + "_d" + std::to_string(dupId)));

                std::vector<mlir::Value> temp_sum;
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    if(share_i == share_j) continue;
                    auto randReg = opBuilder.create<secfir::RegOp>(
                        location, 
                        randomness[rand[share_i][share_j]].getType(), 
                        randomness[rand[share_i][share_j]], 
                        clk[dupId],
                        opBuilder.getStringAttr("_hpc_correct_r" + std::to_string(share_i)+ std::to_string(share_j) + "_d" + std::to_string(dupId)));
                        randReg.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                    auto notLhs = opBuilder.create<secfir::NotPrimOp>(
                            location, 
                            lhs[share_i][dupId].getType(), 
                            lhs[share_i][dupId]);
                    notLhs.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                    auto and_u = opBuilder.create<secfir::AndPrimOp>(
                            location,
                            notLhs.getResult().getType(),
                            randReg.getResult(),
                            notLhs.getResult());
                    auto reg_u = opBuilder.create<secfir::RegOp>(
                        location, 
                        and_u.getResult().getType(), 
                        and_u.getResult(), 
                        clk[dupId],
                        opBuilder.getStringAttr("_hpc_correct_u" + std::to_string(share_i)+ std::to_string(share_j) + "_d" + std::to_string(dupId)));
                    //Correction
                    mlir::ValueRange valRange(v_tilde[share_i][share_j]);
                    auto majority = opBuilder.create<secfir::MajorityPrimOp>(
                        location,
                        uintType,
                        valRange);
                    auto reg_v = opBuilder.create<secfir::RegOp>(
                        location, 
                        majority.getResult().getType(),
                        majority.getResult(),
                        clk[dupId],
                        opBuilder.getStringAttr("_hpc_correct_v" + std::to_string(share_i)+ std::to_string(share_j) + "_d" + std::to_string(dupId)));
                    auto z = opBuilder.create<secfir::AndPrimOp>(
                            location,
                            lhs[share_i][dupId].getType(),
                            lhs[share_i][dupId],
                            reg_v.getResult());
                    //z.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                    auto reg_z = opBuilder.create<secfir::RegOp>(
                            location, 
                            z.getResult().getType(), 
                            z.getResult(), 
                            clk[dupId],
                            opBuilder.getStringAttr("_hpc_correct_z" + std::to_string(share_i)+ std::to_string(share_j) + "_d" + std::to_string(dupId)));
                    auto xor_uz = opBuilder.create<secfir::XorPrimOp>(
                            location,
                            reg_z.getResult().getType(),
                            reg_z.getResult(),
                            reg_u.getResult());

                    if(temp_sum.size() > 0){
                        auto xor_sum = opBuilder.create<secfir::XorPrimOp>(
                                location,
                                xor_uz.getResult().getType(),
                                xor_uz.getResult(),
                                temp_sum[temp_sum.size()-1]);
                        //xor_sum.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                        temp_sum.push_back(xor_sum.getResult());
                    }else{
                        temp_sum.push_back(xor_uz.getResult());
                    }
                }
                auto xor_sum = opBuilder.create<secfir::XorPrimOp>(
                        location,
                        reg_ab.getResult().getType(),
                        reg_ab.getResult(),
                        temp_sum[temp_sum.size()-1]);
                sharedResult[share_i][dupId] = xor_sum.getResult();
            }
        }
    }

    /// Function that inserts the logic of the ICINI multiplication gadget.
    ///
    /// location            Location of the gadget
    /// opBuilder           An operation builder used to place the logic
    /// sharedLhs           Vector of shares of the LHS to the gadget
    /// sharedRhs           Vector of shares of the RHS to the gadget
    /// sharedResult        Vector where the result shares will be placed,
    ///                             size needs already to be initialized
    /// randomness          Vector of random values to use
    /// clk                 Clock to use for the registers       
    /// pipeline            If true, gadget is pipelined internally  
    void placeIciniMultiplicationLogic(
            mlir::Location location,
            mlir::OpBuilder &opBuilder,
            std::vector<std::vector<mlir::Value>> &sharedLhs,
            std::vector<std::vector<mlir::Value>> &sharedRhs,
            std::vector<std::vector<mlir::Value>> &sharedResult,
            std::vector<mlir::Value> &randomness,
            std::vector<mlir::Value> clk,
            bool pipeline
    ){
       //Ensure same number of shares for both inputs
        assert(sharedLhs.size() == sharedRhs.size() &&
                 "Number of shares need to be equal for both inputs!");
        assert(sharedLhs.size() == sharedResult.size() &&
                 "Number of shares need to be equal for inputs and result!");

        //Get number of shares
        unsigned numberShares = sharedLhs.size();
        unsigned numberDuplications = sharedLhs[0].size();
         unsigned activeOrder = floor(numberDuplications/2);
        //Mapping from 2D randomness indices to 1D indices
        unsigned randIndex = 0;
        std::vector<mlir::Value> randomness_ref(activeOrder*numberShares*(numberShares-1)/2);
        std::vector<mlir::Value> randomness_mul(activeOrder*numberShares*(numberShares-1)/2);
        std::vector<std::vector<std::vector<unsigned>>> rand_index(
                        numberShares, std::vector<std::vector<unsigned>>(
                                numberShares, std::vector<unsigned>(activeOrder+1)));
        for(unsigned i=0; i<numberShares; i++){
            for(unsigned j=i+1; j<numberShares; j++){
                for(unsigned m=0; m<activeOrder; m++){
                    rand_index[i][j][m] =  randIndex;
                    rand_index[j][i][m] = rand_index[i][j][m];
                    //Verify that enough randomness is provided
                    assert(randIndex < randomness.size() && "More randomness required!");
                    assert(randomness_ref.size()+randIndex < randomness.size() && "More randomness required!");
                    //Set randomness for refresh
                    randomness_ref[randIndex] = randomness[randIndex];
                    randomness_mul[randIndex] = randomness[randomness_ref.size()+randIndex];
                    //Increment randomness index
                    randIndex++;
                } 
            }
        }
        //Define intermediate variables
        std::vector<std::vector<mlir::Value>> v_tilde(numberShares, std::vector<mlir::Value>(numberDuplications));
        std::vector<std::vector<std::vector<mlir::Value>>> v(numberShares, std::vector<std::vector<mlir::Value>>(numberShares, std::vector<mlir::Value>(numberDuplications)));
        std::vector<std::vector<std::vector<mlir::Value>>> z(numberShares, std::vector<std::vector<mlir::Value>>(numberShares, std::vector<mlir::Value>(numberDuplications)));
        secfir::UIntType uintType = secfir::UIntType::get(
                                 opBuilder.getContext(), 1);
        std::vector<std::vector<mlir::Value>> lhs(numberShares, std::vector<mlir::Value>(numberDuplications));
        //Insert registers for LHS if gadget should be pipelined internally
        for(unsigned share_i=0; share_i<numberShares; share_i++){
            for(unsigned dupId=0; dupId<numberDuplications; dupId++){
                if(pipeline){
                    auto regLhs = opBuilder.create<secfir::RegOp>(
                            location, 
                            sharedLhs[share_i][dupId].getType(),
                            sharedLhs[share_i][dupId],
                            clk[dupId],
                            opBuilder.getStringAttr("_hpc_correct_a_s" + std::to_string(share_i)+ "_d" + std::to_string(dupId)));
                    lhs[share_i][dupId] = regLhs.result();
                }else{
                    lhs[share_i][dupId] = sharedLhs[share_i][dupId];
                }
            }
        }
        //Masking of RHS
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                std::vector<mlir::Value> temp_sum;
                temp_sum.push_back(sharedRhs[share_i][dupId]);
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    if(share_i == share_j) continue;
                    for(unsigned m=0; m<activeOrder; m++){
                        auto xor_v = opBuilder.create<secfir::XorPrimOp>(
                            location,
                            uintType,
                            temp_sum[temp_sum.size()-1],
                            randomness_ref[rand_index[share_i][share_j][m]]);
                        xor_v.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                        temp_sum.push_back(xor_v.getResult());
                    }
                }
                v_tilde[share_i][dupId] = temp_sum[temp_sum.size()-1];
            }
        }
        //Correction of RHS and first register stage
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    mlir::ValueRange valRange(v_tilde[share_i]);
                    auto majority = opBuilder.create<secfir::MajorityPrimOp>(
                        location,
                        uintType,
                        valRange);
                     auto reg_v = opBuilder.create<secfir::RegOp>(
                        location, 
                        majority.getResult().getType(), 
                        majority.getResult(), 
                        clk[dupId],
                        opBuilder.getStringAttr("_cini_mul_v" + std::to_string(share_i)  + std::to_string(share_j) + std::to_string(dupId)));
                    v[share_i][share_j][dupId] = reg_v.getResult();
                }
            }
        }
        //Multiplication, refresh and second register stage
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    std::vector<mlir::Value> temp_sum;
                    auto and_ab = opBuilder.create<secfir::AndPrimOp>(
                            location,
                            lhs[share_i][dupId].getType(),
                            lhs[share_i][dupId],
                            v[share_j][share_i][dupId]);
                    temp_sum.push_back(and_ab.getResult());
                    if(share_i != share_j){
                        for(unsigned m=0; m<activeOrder; m++){
                            auto xor_rand = opBuilder.create<secfir::XorPrimOp>(
                                location,
                                uintType,
                                temp_sum[temp_sum.size()-1],
                                randomness_mul[rand_index[share_i][share_j][m]]);
                            xor_rand.setAttr("ModuleReplace", opBuilder.getBoolAttr(true));
                            temp_sum.push_back(xor_rand.getResult());
                        }
                    }
                    auto reg_z = opBuilder.create<secfir::RegOp>(
                        location, 
                        temp_sum[temp_sum.size()-1].getType(), 
                        temp_sum[temp_sum.size()-1], 
                        clk[dupId],
                        opBuilder.getStringAttr("_cini_mul_z" + std::to_string(share_i)  + std::to_string(share_j) + std::to_string(dupId)));
                    z[share_i][share_j][dupId] = reg_z.getResult();
                }
            }
        }
        //Reduction
        for(unsigned dupId=0; dupId<numberDuplications; dupId++){
            for(unsigned share_i=0; share_i<numberShares; share_i++){
                std::vector<mlir::Value> temp_sum;
                temp_sum.push_back(z[share_i][share_i][dupId]);
                for(unsigned share_j=0; share_j<numberShares; share_j++){
                    if(share_i == share_j) continue;
                    auto xor_red = opBuilder.create<secfir::XorPrimOp>(
                            location,
                            z[share_i][share_j][dupId].getType(),
                            temp_sum[temp_sum.size()-1],
                            z[share_i][share_j][dupId]);
                    temp_sum.push_back(xor_red.getResult());
                }
                sharedResult[share_i][dupId] = temp_sum[temp_sum.size()-1];
            }
        }
    }
}
}