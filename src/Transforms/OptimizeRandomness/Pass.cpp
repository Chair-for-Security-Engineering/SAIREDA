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
#include "SecFIR/SecFIRDialect.h"
#include "Passes/TransformationPasses.h"
#include "Passes/OptimizeRandomness.h"

#include <math.h> 

namespace circt{
namespace secfir{

using namespace circt;


    void secfir::DistributeRandomness::runOnOperation() {
        llvm::errs() << "---Randomness-Distribution Pass---\n";
        
        //Get a builder vor IR manipulation
        mlir::OpBuilder builder(&getContext());
        //Get current module operation
        secfir::CircuitOp circuit = getOperation();
        if(parameterOrder == 1 && parameterDistributionRule != DistributionRule::std_rule){
            circuit.emitError() << "'distribute-randomness' pass only supports std rule for order=1!";
            signalPassFailure();
            return;
        }
        unsigned uniqueRand = 0;
        if(parameterUniqueRandomnessPerGadget == UniqueRandomnessPerGadget::t_bit){
            uniqueRand = parameterOrder;
        }
    
        for(auto &module : circuit.getBody()->getOperations()){
            if(secfir::isa<secfir::ModuleOp>(module)){
                secfir::ModuleOp m = secfir::dyn_cast<secfir::ModuleOp>(module);
                unsigned moduleSize = m.getBodyBlock()->getOperations().size();
                //Get a list of all gadgets
                std::vector<mlir::Operation*> gadgets;
                for (auto &op : m.getBodyBlock()->getOperations()) {
                     if(secfir::isa<secfir::PiniAndGadgetOp>(op) ||
                        secfir::isa<secfir::SniAndGadgetOp>(op) ||
                        secfir::isa<secfir::SniRefreshOp>(op)   ||
                        secfir::isa<secfir::SniPiniAndGadgetOp>(op) ||
                        secfir::isa<secfir::CiniAndGadgetOp>(op) ||
                        secfir::isa<secfir::IciniAndGadgetOp>(op)
                    ){
                        gadgets.push_back(&op);
                        gadgetsStatistic++;
                    }
                }
                //Initialize statistics of minmal and maximal set size
                minSetSizeStatistic = gadgets.size();
                maxSetSizeStatistic = 0;
                //Compute the randomness requirements for one gadget
                unsigned randomnessPerGate = floor(parameterOrder*(parameterOrder+1)/2);
                unsigned hpc2cRandomnessPerGate = randomnessPerGate;
                unsigned hpc1cRandomnessPerGate = 2*randomnessPerGate;
                unsigned iciniRandomnessPerGate = 2*parameterActiveOrder*randomnessPerGate;
                randomnessPerGadgetStatistic = randomnessPerGate;
                //Handle standard distribution
                if(parameterDistributionRule == DistributionRule::std_rule){
                    unsigned usedRandomness = 0;
                    for(unsigned gadgetIndex=0; gadgetIndex<gadgets.size(); gadgetIndex++){
                        std::vector<mlir::Attribute> randVec;
                        //CINI and ICINI gadgets have a different randomness requirement,
                        //handle them first
                        if(secfir::isa<secfir::CiniAndGadgetOp>(gadgets[gadgetIndex])){
                            StringAttr gadgetType = gadgets[gadgetIndex]->getAttrOfType<StringAttr>("GadgetType");
                            if(gadgetType.getValue() == "HPC_1"){
                                //Set the statistic of randomness per gadget for designs using CINI
                                randomnessPerGadgetStatistic = hpc1cRandomnessPerGate;
                                //Add randomness indices for ICINI gadgets
                                for(unsigned randomness=0; randomness<hpc1cRandomnessPerGate; randomness++){
                                    randVec.push_back(builder.getI16IntegerAttr(usedRandomness));
                                    usedRandomness++;
                                }
                            }else if(gadgetType.getValue() == "HPC_2"){
                                assert((parameterOrder <= 2 && parameterActiveOrder <= 2) && "HPC_2^C is insecure for the selected configuration!");
                                //Set the statistic of randomness per gadget for designs using CINI
                                randomnessPerGadgetStatistic = hpc2cRandomnessPerGate;
                                //Add randomness indices for ICINI gadgets
                                for(unsigned randomness=0; randomness<hpc2cRandomnessPerGate; randomness++){
                                    randVec.push_back(builder.getI16IntegerAttr(usedRandomness));
                                    usedRandomness++;
                                }
                            }
                        }else if(secfir::isa<secfir::IciniAndGadgetOp>(gadgets[gadgetIndex])){
                            //Set the statistic of randomness per gadget for designs using ICINI
                            randomnessPerGadgetStatistic = iciniRandomnessPerGate;
                            //Add randomness indices for ICINI gadgets
                            for(unsigned randomness=0; randomness<iciniRandomnessPerGate; randomness++){
                                randVec.push_back(builder.getI16IntegerAttr(usedRandomness));
                                usedRandomness++;
                            }
                        }else if(secfir::isa<secfir::PiniAndGadgetOp>(gadgets[gadgetIndex])){
                            StringAttr gadgetType = gadgets[gadgetIndex]->getAttrOfType<StringAttr>("GadgetType");
                            if(gadgetType.getValue() == "HPC_1"){
                                //Set the statistic of randomness per gadget for designs using HPC1
                                randomnessPerGadgetStatistic = 2*randomnessPerGate;
                                //Add randomness indices for HPC1 gadgets
                                for(unsigned randomness=0; randomness<2*randomnessPerGate; randomness++){
                                    randVec.push_back(builder.getI16IntegerAttr(usedRandomness));
                                    usedRandomness++;
                                }
                            }else if(gadgetType.getValue() == "HPC_2"){
                                //Set the statistic of randomness per gadget for designs using HPC2
                                randomnessPerGadgetStatistic = randomnessPerGate;
                                //Add randomness indices for HPC2 gadgets
                                for(unsigned randomness=0; randomness<randomnessPerGate; randomness++){
                                    randVec.push_back(builder.getI16IntegerAttr(usedRandomness));
                                    usedRandomness++;
                                }
                            }
                        }else{
                            //Handle all gadgets that are not ICINI
                            for(unsigned randomness=0; randomness<randomnessPerGate; randomness++){
                                randVec.push_back(builder.getI16IntegerAttr(usedRandomness));
                                usedRandomness++;
                            }
                        }
                       
                        mlir::ArrayRef<mlir::Attribute> arrayRef(randVec);
                        mlir::ArrayAttr randArrayAttr = builder.getArrayAttr(arrayRef);
                        gadgets[gadgetIndex]->setAttr("RandIndices", randArrayAttr);
                    }
                    //Update statistics
                    randomnessStatistic = usedRandomness;
                    minSetSizeStatistic = 0;
                    //Add the number of required randomness as attribute to the module
                    mlir::IntegerAttr reqRandomness = builder.getI16IntegerAttr(randomnessStatistic);
                    module.setAttr("RequiredRandomness", reqRandomness);
                    //Exit as there is nothing more to do
                    return;
                }

                llvm::errs() << "Determining dependent values and gadgets... ";
                //Determine which values depend on which other values
                mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> dependentValues(moduleSize);
                mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> dependentGadgets(moduleSize);
                determineDependentValuesAndGadgets(m.getBodyBlock()->getOperations(), dependentValues, dependentGadgets);
                llvm::errs() << "\r" << std::string(70, ' ') << "\r";

                //When all randomness should be reusable, add all gadgets where the outputs
                //get combined to the list
                if(parameterUniqueRandomnessPerGadget == UniqueRandomnessPerGadget::non){
                    llvm::errs() << "Determining gadgets that are combined downstream... ";
                    addCombinedOutputGadgetsOpt(
                        m.getBodyBlock()->getOperations(),
                        dependentGadgets
                    );
                    llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                }
                //For SNI also add all gadgets that have dependent inputs to the list
                if(parameterDistributionRule == DistributionRule::sni_rule){
                    llvm::errs() << "Determining gadgets with dependent inputs... ";
                    addDependentInputGadgets(gadgets, dependentGadgets, dependentValues);
                    llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                }
                llvm::errs() << "Determining clusters of gadgets... ";
                //Divide gadgets into sets of parallel gadgets (with an heuristic algorithm)
                std::vector<std::vector<mlir::Operation*>> parallelOps;  
                determineParallelGadgetsFirstFitHeuristic(
                            gadgets, 
                            dependentGadgets, 
                            parameterMaxSetSize, 
                            parallelOps); 
                llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                //Determin minimum and maximum set size
                for(auto opSet: parallelOps){
                    //Update minimal and maximal set size statistics
                    if(opSet.size() < minSetSizeStatistic){
                        minSetSizeStatistic = opSet.size();
                    }
                    if(opSet.size() > maxSetSizeStatistic){
                        maxSetSizeStatistic = opSet.size();
                    }
                }

                llvm::errs() << "Determining randomness distribution... ";
                //Get randomness assignment for the largest set
                std::vector<std::vector<unsigned>> assignment;
                std::vector<unsigned> usedRandomness;
                //Handle PINI distribution rule
                if(parameterDistributionRule == DistributionRule::pini_rule){            
                    //Get the radmoness assignment and the number 
                    //of required random bits for this set
                    piniDistributionHeuristic(
                                maxSetSizeStatistic, 
                                randomnessPerGate - uniqueRand, 
                                &assignment,
                                &usedRandomness);
                //Handle SNI distribution rule
                } else if(parameterDistributionRule == DistributionRule::sni_rule){   
                    //Get the radmoness assignment and the number 
                    //of required random bits for this set
                    sniDistributionHeuristic(
                                maxSetSizeStatistic,
                                randomnessPerGate - uniqueRand,
                                &assignment,
                                &usedRandomness);
                }
                llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                llvm::errs() << "Assigning randomness to gadgets... ";
                //Set randomness assignments for all sets of parallel operations
                for(unsigned setIndex=0; setIndex<parallelOps.size(); setIndex++){
                    //Offset all randomness indices with the number of randomness
                    //used befor the current set
                    unsigned setUsedRandomness = 0;
                    for(unsigned gadgetIndex=0; gadgetIndex<parallelOps[setIndex].size(); gadgetIndex++){
                        std::vector<mlir::Attribute> randVec;
                        //If some randomness should be unique to the gadget, set those first
                        for(unsigned randomness=0; randomness<uniqueRand; randomness++){
                            randVec.push_back(
                                    builder.getI16IntegerAttr(
                                        setUsedRandomness + randomnessStatistic));
                            setUsedRandomness++;
                        }
                        //Add randomness that is potentially reused
                        for(unsigned randomness : assignment[gadgetIndex]){
                            randVec.push_back(
                                    builder.getI16IntegerAttr(
                                        randomness + randomnessStatistic + uniqueRand*parallelOps[setIndex].size()));
                        }
                        mlir::ArrayRef<mlir::Attribute> arrayRef(randVec);
                        mlir::ArrayAttr randArrayAttr = builder.getArrayAttr(arrayRef);
                        parallelOps[setIndex][gadgetIndex]->setAttr("RandIndices", randArrayAttr);
                    }
                    //Increase the number of overall used randomness
                    randomnessStatistic += 
                        usedRandomness[parallelOps[setIndex].size()] + uniqueRand*parallelOps[setIndex].size();    
                }
                llvm::errs() << "\r" << std::string(70, ' ') << "\r";
                savedRandomnessStatistic += 
                        randomnessPerGate*gadgetsStatistic - randomnessStatistic; 
                meanSetSizeStatistic = ((double)gadgets.size() / (double)parallelOps.size()) * 100; 
                numSetStatistic += numSetStatistic + parallelOps.size();
            }
            //Add the number of required randomness as attribute to the module
            mlir::IntegerAttr reqRandomness = builder.getI16IntegerAttr(randomnessStatistic);
            module.setAttr("RequiredRandomness", reqRandomness);
        }
    }

    void registerDistributeRandomnessPass(){
        mlir::PassRegistration<DistributeRandomness>(
            "distribute-randomness", 
            "randomness distribution for SNI and PIN gadgets",
            []() -> std::unique_ptr<mlir::Pass>{return secfir::createDistributeRandomnessPass();});
    }

    std::unique_ptr<mlir::Pass> createDistributeRandomnessPass(){
	    return std::make_unique<DistributeRandomness>();
	}
}
}