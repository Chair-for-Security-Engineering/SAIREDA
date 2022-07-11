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
#include "Passes/OptimizeRandomness.h"

namespace circt{
namespace secfir{

using namespace circt;

    /// Function that determines the list of values and gadgets a specifc value depend on.
    /// Does currently only work with designs where all inputs to an operation are already
    /// defined.
    ///
    /// operations:         the list of operations the analysis will be done for
    /// dependentValues:    datastructure that will contain the mapping from values
    ///                         to the list of values it depends on
    /// dependentOps:    datastructure that will contain for each gadgets the 
    ///                     list of other gadgets it depends on
    void determineDependentValuesAndGadgets(
        mlir::Block::OpListType &operations,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues,
        mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps
    ){  
        //Preperations for progress notification
        int numOps = operations.size();
        int treatedOps = 0;
        unsigned int progress_step = std::max(10, int(numOps/100));
        bool contained = false;
        //Go through all operations in the module 
        for (auto &op : operations) {
             //Ensure that the operation has a result, which is the value we analyse
            if(op.getResults().size() == 1){
                //Get the result
                mlir::Value res = op.getResults()[0];
                //Add an empty vector to the mapping for this value
                std::vector<mlir::Value> vector;
                dependentValues[res] = vector;
                //Add the value itself to the list of values it depends on
                dependentValues[res].push_back(res);

                //Add a new set to the list of dependencies
                std::set<mlir::Operation*> opVector;
                dependentOps[&op] = opVector;
               
                //If the defining operation is an SNI gadget there are no
                //more values it depends on otherwise add all values that 
                //the inputs of the operation depend on to the list
                if(!(secfir::isa<secfir::SniAndGadgetOp>(op) ||
                        secfir::isa<secfir::SniPiniAndGadgetOp>(op) ||
                        secfir::isa<secfir::SniRefreshOp>(op))
                ){
                    //Go through all inputs of the operation    
                    for(mlir::Value input: op.getOperands()){
                        //Check whether the input as a list of values it depends on
                        //and if yes then add all values to the list otherwise add only
                        //the input to the list
                        if(dependentValues.count(input) == 1){
                            //Go through all values the input depends on
                            for(mlir::Value v_input: dependentValues[input]){
                                //Check whether this value is already in the list 
                                contained = false;
                                for(mlir::Value v_value: dependentValues[res]){
                                    if(v_value == v_input){
                                        contained = true;
                                        break;
                                    }
                                }
                                //If not then add the value to the list
                                if(!contained) dependentValues[res].push_back(v_input);
                            }
                        }else{
                            //Check whether the input is already in the list
                            contained = false;
                            for(mlir::Value v_value: dependentValues[res]){
                                if(v_value == input){
                                    contained = true;
                                    break;
                                }
                            }
                            //If not than add the input to the list
                            if(!contained) dependentValues[res].push_back(input);
                        }    
                    }
                }
            }

            //Get dependent operations by combining the dependent operations from all inputs
            for(mlir::Value input: op.getOperands()){
                //Check that there is an operation defining the input
                if(input.getDefiningOp()){
                    //For SNI gadgets in the input we only need to add this SNI gadget
                    if(secfir::isa<secfir::SniAndGadgetOp>(input.getDefiningOp()) ||
                            secfir::isa<secfir::SniRefreshOp>(input.getDefiningOp())   ||
                            secfir::isa<secfir::SniPiniAndGadgetOp>(input.getDefiningOp())
                    ){
                        //Add the gadget to the list if it is not already in it
                        dependentOps[&op].insert(input.getDefiningOp());
                    }else{
                        //For PINI gadgets we need to add this PINI gadget to the list
                        //of dependent gadgets from the input
                        if(secfir::isa<secfir::PiniAndGadgetOp>(input.getDefiningOp())){
                            ///Add the gadget to the list if it is not already in it
                            dependentOps[&op].insert(input.getDefiningOp());
                        }
                        //Add all gadgets the input depends on the the list of dependent gadgets
                        for(mlir::Operation *gadget: dependentOps[input.getDefiningOp()]){
                            //Add the gadget to the list if it is not already in it
                                dependentOps[&op].insert(gadget);
                        }
                    }
                }       
            }
            //Output some progress notification
            treatedOps++;
            if(((treatedOps % progress_step) == 0) || treatedOps == int(numOps-1)){
                float progress = float(treatedOps) / float(numOps-1);
                if(progress != 1.0){
                    llvm::errs() << "[ " << int(progress * 100.0) << " %]\b\b\b\b\b\b";
                    if(progress >= 0.1) llvm::errs() << "\b";
                }
            }
        }   
    }

    /// Function that determines sets of parallel gadgets 
    /// (inputs is independent of any outputs) using a simple 
    /// heuristic: A gadget is always put in the first set it fits in.
    ///
    /// gadgets:        list of gadgets
    /// dependentOps:   mapping from every gadget to a list of gadgets
    ///                     it despends on
    /// parallelOps:    datastructure that will contain the sets of 
    ///                     parallel gadgets      
    void determineParallelGadgetsFirstFitHeuristic(
        std::vector<mlir::Operation *> &gadgets,
        mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps,
        std::vector<std::vector<mlir::Operation*>> &parallelOps
    ){
        unsigned treatedGadgets = 0;
        unsigned int progress_step = std::max(10, int(gadgets.size()/100));
        //Find a set for all gadgets listed in the dependentOps list
        for(mlir::Operation *gadget: gadgets){
            bool placed = false;
            //Go through all available sets
            for(unsigned setIndex=0; setIndex<parallelOps.size(); setIndex++){
                bool found = false;
                //Check whether there is one element in this set that is also in
                //the set of dependent gadgets for the gadget that we want to place
                for(mlir::Operation *element_set : parallelOps[setIndex]){
                    if(dependentOps[gadget].find(element_set) != dependentOps[gadget].end()){
                        found = true;
                    }
                }
                //If no element contradicts the placement of the gadget in this set
                //then add the gadget to the set
                if(!found){
                    parallelOps[setIndex].push_back(gadget);
                    //Indicate that we have found a place
                    placed = true;
                    //Do not further look for any other sets
                    break;
                }
            }
            //If the gadget fits in no available set
            //then create a new set for this gadget
            if(!placed){
                std::vector<mlir::Operation*> vector;
                vector.push_back(gadget);
                parallelOps.push_back(vector);
            }

            treatedGadgets++;
            if(((treatedGadgets % progress_step) == 0) || treatedGadgets == int(gadgets.size()-1)){
                float progress = float(treatedGadgets) / float(gadgets.size()-1);
                if(progress != 1.0){
                    llvm::errs() << "[ " << int(progress * 100.0) << " %]\b\b\b\b\b\b";
                    if(progress >= 0.1) llvm::errs() << "\b";
                }
            }
        }
    }

    /// Function that extends the set of gadgets one gadget depends on by all
    /// gadgets that get as input some dependent value to the input of the gadget.
    /// This is required for parallel SNI gates, as there the inputs need to be 
    /// independent.
    ///
    /// gadgets:            List of gadgets
    /// dependentOps:       Mapping from a gadget to a list of gadgets on which the gadget
    ///                         depends. This list will be extendet.
    /// dependentValues:    Mapping from values to values that value depends on. 
    void addDependentInputGadgets(
        std::vector<mlir::Operation*> gadgets,
        mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues
    ){
         //Preperation for progress notification
        unsigned int progress_step = std::max(10, int(gadgets.size()/100));
        int treatedGadgets = 0;
        //Extend the list for all gadgets
        for(mlir::Operation *gadget: gadgets){
            //Get all dependent values of all inputs to the gadget
            for(mlir::Value input: gadget->getOperands()){
                for(mlir::Value depValue: dependentValues[input]){
                    //Get all users of the gadgets that are itself gadgets
                    for(mlir::Operation *user : depValue.getUsers()){
                        if(secfir::isa<secfir::PiniAndGadgetOp>(user) ||
                        secfir::isa<secfir::SniAndGadgetOp>(user) ||
                        secfir::isa<secfir::SniRefreshOp>(user)   ||
                        secfir::isa<secfir::SniPiniAndGadgetOp>(user)
                        ){
                            //Add the user to the list if it is not already in it
                            dependentOps[gadget].insert(user);
                        }

                    }
                }
                //Handle the case where there is no entry for an input in the list 
                //of dependent values
                if(!dependentValues.count(input) || dependentValues[input].size() == 0){
                    //Get all user gadgets of the input
                    for(mlir::Operation *user: input.getUsers()){
                        if(secfir::isa<secfir::PiniAndGadgetOp>(user) ||
                        secfir::isa<secfir::SniAndGadgetOp>(user) ||
                        secfir::isa<secfir::SniRefreshOp>(user)   ||
                        secfir::isa<secfir::SniPiniAndGadgetOp>(user)
                        ){
                            //Add the user to the list if it is not already in it
                            dependentOps[gadget].insert(user);
                        }
                    }
                }
            }
             //Print progress notification
            treatedGadgets++;
            if(((treatedGadgets % progress_step) == 0) || treatedGadgets == int(gadgets.size()-1)){
                float progress = float(treatedGadgets) / float(gadgets.size()-1);
                if(progress != 1.0){
                    llvm::errs() << "[ " << int(progress * 100.0) << " %]\b\b\b\b\b\b";
                    if(progress >= 0.1) llvm::errs() << "\b";
                }
            }
        }
    }

    /// Recursive function that extends the set of gadgets the specified gadget depends 
    /// on by all gadgets where the output is combined at some point in the module. This
    /// is necessary for a cluster of parallel gadgets where all randomness 
    /// should potentially be reused. SNI gadgets will stop propagation of dependencies.
    ///
    /// gadget              Gadget that is analysed
    /// upstream_op:        Start operation of the analysis
    /// dependentOps:       Mapping from a gadget to a list of gadgets on which the gadget
    ///                         depends. This list will be extendet.
    /// dependentValues:    Mapping from values to values that value depends on. 
    void addCombinedOutputForGadget(
        mlir::Operation* gadget,
        mlir::Operation* upstream_op,
        mlir::DenseMap<mlir::Operation*, std::vector<mlir::Operation*>> &dependentOps,
        mlir::DenseMap<mlir::Value, std::vector<mlir::Value>> &dependentValues
    ){
        bool contained = false;
        //Stop propagation of dependencies for SNI gadgets
        if(upstream_op != gadget && (
                secfir::isa<secfir::SniPiniAndGadgetOp>(upstream_op) ||
                secfir::isa<secfir::SniAndGadgetOp>(upstream_op) ||
                secfir::isa<secfir::SniRefreshOp>(upstream_op))){
                    return;
        }
        //Get output value of this gadget (all gadgets have exactly one output)
        mlir::Value gadget_out = gadget->getResults()[0];
        //Check that current operation has exactly one result and get this value
        if(upstream_op->getResults().size() == 1){
            mlir::Value upstream_op_res = upstream_op->getResults()[0];
            //Get all operations that get the result as input
            for(mlir::Operation *upstream_op_user: upstream_op_res.getUsers()){
                //Check that this user operation is an operation with result and get
                //all inputs of this operation that are not the one we are comming from
                if(upstream_op_user->getResults().size() == 1){
                    for(mlir::Value arg: upstream_op_user->getOperands()){
                        if(arg != upstream_op_res){
                            //Get all dependencies of this input
                            for(mlir::Value dep_val: dependentValues[arg]){
                                //Check that the dependency is a gadget and not the gadget
                                //we come from
                                if(dep_val.getDefiningOp()){
                                    if(dep_val != gadget_out 
                                            && dependentOps.count(dep_val.getDefiningOp())){
                                        mlir::Operation *gadget_dep = dep_val.getDefiningOp();
                                        //Check whether this gadget is already in the list 
                                        //of the gadget we come from
                                        contained = false;
                                        for(mlir::Operation *op_dep: dependentOps[gadget]){
                                            if(gadget_dep == op_dep){
                                                contained = true;
                                                break;
                                            }
                                        }
                                        //Add gadget to the list of not already contained
                                        if(!contained) dependentOps[gadget].push_back(gadget_dep);
                                    }
                                }
                            }
                        }
                    }
                }               
            }   
            //Recursive call with the next operations
            for(mlir::Operation* user: upstream_op_res.getUsers())
                addCombinedOutputForGadget(gadget, user, dependentOps, dependentValues);
        }
    }

    /// Optimized version of a function that extends the set of gadgets one 
    /// gadget depends on by all gadgets where the output is combined at some 
    /// point in the module. This is necessary for a cluster of parallel gadgets 
    /// where all randomness should potentially be reused. 
    /// Uses the fact, that an operation is dependent on all gadgets it combines
    /// and that SNI and output gadgets are the operations with the most dependencies.
    ///
    /// operations          List of operations in module
    /// dependentOps:       Mapping from a gadget to a list of gadgets on which the gadget
    ///                         depends. This list will be extendet.
    void addCombinedOutputGadgetsOpt(
         mlir::Block::OpListType &operations,
         mlir::DenseMap<mlir::Operation*, std::set<mlir::Operation*>> &dependentOps
    ){
        //Preperation for progress notification
        unsigned int progress_step = std::max(10, int(operations.size()/100));
        int treatedGadgets = 0;
        //Go thorugh all operations and search for SNI gadgets or outputs
        for(mlir::Operation &op: operations){
            //Handle SNI gadgets
            if(secfir::isa<secfir::SniPiniAndGadgetOp>(op) ||
                secfir::isa<secfir::SniAndGadgetOp>(op) ||
                secfir::isa<secfir::SniRefreshOp>(op)
            ){
                //Ensure that all pairs of gadgets this gadget depends on
                //have each other in the list of dependent gadgets
                for(mlir::Operation *gadget_i: dependentOps[&op]){
                    for(mlir::Operation *gadget_j: dependentOps[&op]){
                        if(gadget_i == gadget_j) continue;
                        //Add gadget to the list of not already contained
                        dependentOps[gadget_i].insert(gadget_j);
                    }
                }
            //Handle output operations
            }else if(secfir::isa<secfir::OutputOp>(op)){
                unsigned int progress_step_output = std::max(10, int(op.getOperands().size()/100));
                int treatedOutputs = 0;
                //We need to handle all output values seperately
                for(mlir::Value input: op.getOperands()){
                    //Check that there is a defining of to the output value 
                    if(input.getDefiningOp()){
                        mlir::Operation *input_op = input.getDefiningOp();
                         //Ensure that all pairs of gadgets this output depends on
                        //have each other in the list of dependent gadgets
                        for(mlir::Operation *gadget_i: dependentOps[input_op]){
                            for(mlir::Operation *gadget_j: dependentOps[input_op]){
                                if(gadget_i == gadget_j) continue;
                                //Add gadget to the list of not already contained
                                dependentOps[gadget_i].insert(gadget_j);
                            }
                        }
                    }
                    //Print progress notification
                    treatedOutputs++;
                    if(((treatedOutputs % progress_step_output) == 0) || treatedOutputs == int(op.getOperands().size()-1)){
                        float progress = float(treatedOutputs) / float(op.getOperands().size()-1);
                        if(progress != 1.0){
                            llvm::errs() << "[out " << int(progress * 100.0) << " %]\b\b\b\b\b\b\b\b\b";
                            if(progress >= 0.1) llvm::errs() << "\b";
                        }
                    }
                }
            }
            //Print progress notification
            treatedGadgets++;
            if(((treatedGadgets % progress_step) == 0) || treatedGadgets == unsigned(operations.size()-1)){
                float progress = float(treatedGadgets) / float(operations.size()-1);
                if(progress != 1.0){
                    llvm::errs() << "[ " << int(progress * 100.0) << " %]\b\b\b\b\b\b";
                    if(progress >= 0.1) llvm::errs() << "\b";
                }
            }
        }
    }
}
}