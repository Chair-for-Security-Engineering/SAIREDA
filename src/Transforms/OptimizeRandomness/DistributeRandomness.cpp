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

    /// Function that searches for a distribution of randomness for a set of parallel
    /// SNI gadgets using the SMT solver Z3, i.e., a distribution where there exists 
    /// no pair of random values that go to more than one gadget simultaneously. 
    ///
    /// numberGates:        number of gadgets in the parallel set of gadgets
    /// randomnessPerGate:  number of random elements that each gadget requires (determined by the order)
    /// numberRandomness:   number of random elements available overall
    /// assignment:         pointer to a data structure that is used for the found assignment
    bool sniDistributionSMT(
                unsigned numberGates, 
                unsigned randomnessPerGate, 
                unsigned numberRandomness, 
                std::vector<std::vector<unsigned>> *assignment
    ){
        // Get a z3 context
        z3::context z3;
        // Set a timeout for the solver (5min)
        z3::params para(z3);
        para.set(":timeout", 600000u);
        // Define vectors for SAT variables where u[i][k] indicates that
        // random value k is used by gadget i and x[i][j][k] indicates 
        // that gate i and j share random value k
        std::vector<std::vector<std::vector<z3::expr>>> x;
        std::vector<std::vector<z3::expr>> u;
        //Define a temporary variable for variable names
        std::string name;
    
        //--Initialize empty variables for the solver
        for(unsigned i=0; i < numberGates; i++){
            x.push_back(std::vector<std::vector<z3::expr>>());
            u.push_back(std::vector<z3::expr>());
            //Initialize x
            for(unsigned j=i+1; j < numberGates; j++){
                x[i].push_back(std::vector<z3::expr>());
                for(unsigned k=0; k<numberRandomness; k++){
                    name = "x_" + std::to_string(i) + "_" + std::to_string(j) + "_" + std::to_string(k);
                    z3::expr value = z3.int_const(name.c_str());
                    x[i][j-(i+1)].push_back(value);
                }
            }
            //Initialize u
            for(unsigned k=0; k<numberRandomness; k++){
                name = "u_" + std::to_string(i) + "_" + std::to_string(k);
                z3::expr value = z3.int_const(name.c_str());
                u[i].push_back(value);
            }
        }
        //--Set constraints for the solver
        //Create a solver and add the timeout configuration
        z3::solver solver(z3);
        solver.set(para);

        for(unsigned i=0; i < numberGates; i++){
            //Initialize constraint that ensures that each gadget has 
            //the right amount of random values
            z3::expr numGateRand = z3.int_val(0);
            for(unsigned j=i+1; j < numberGates; j++){
                //Initialize constraint that ensures that only one 
                //value is shared between two different gadgets
                z3::expr oneShared = z3.int_val(0);
                for(unsigned k=0; k<numberRandomness; k++){
                    //Add up all x for a specific pair of gadgets (i,j)
                    oneShared = oneShared + x[i][j-(i+1)][k];
                    //Add constraints for the value of x (boolean)
                    solver.add(x[i][j-(i+1)][k] >= 0);
                    solver.add(x[i][j-(i+1)][k] <= 1);
                    //Add constraint that ensures the correct relation between 
                    //u and x
                    solver.add(( (u[i][k] == 1) & 
                            (u[j][k] == 1) & 
                            (x[i][j-(i+1)][k] == 1)) | 
                            (!((u[i][k] == 1) & (u[j][k] == 1)) & 
                            (x[i][j-(i+1)][k] == 0))
                        );
                }
                //Add constraint that ensures that only one value is 
                //shared between two gadgets
                solver.add(oneShared <= 1);
            }
            for(unsigned k=0; k<numberRandomness; k++){
                //Add up all u for a specific gadget i
                numGateRand = numGateRand + u[i][k];
                //Add constraint for the value of u (boolean)
                solver.add(u[i][k] >= 0);
                solver.add(u[i][k] <= 1);
            }
            //Add constraint that ensures that each gadget has
            //the right amount of random values
            solver.add(numGateRand == (int)randomnessPerGate);
        }
        //Solve the specified SMT problem
        z3::check_result res=solver.check();
        if(res == z3::sat){
            //If a solution was found then populate the provided data structure with
            //found assignment
            for(unsigned i=0; i<numberGates; i++){
                assignment->push_back(std::vector<unsigned>()); 
            }
            //Get the result from the solver
            z3::model model = solver.get_model();
            //Go through all variables defined in the SAT problem and assign the satisfiable
            //assignment to the corresponding result variable
            for(unsigned i=0; i<model.size(); i++){
                z3::func_decl v = model[i];
                std::vector<std::string> parts = secutil::split(v.name().str(), "_");
                //Find the u variables
                if(v.name().str().find("u") == 0){                    
                    if(model.get_const_interp(v).get_numeral_int() == 1){
                        unsigned i1 = std::stoi(parts[1]);
                        unsigned i2 = std::stoi(parts[2]);
                        //Add solution to assignment
                        assignment->at(i1).push_back(i2);
                    }
                }
            }
            return true;
        }else{
            //If no solution was found return false
            return false;
        }    
    }

    /// A wrapper function for sniDistributionSMT where the resulting
    /// assignment gets lost (useful for access in Python)
    unsigned sniDistributionSMTWrapper(
                unsigned numberGates, 
                unsigned randomnessPerGate,
                unsigned start
    ){
         std::vector<std::vector<unsigned>> assignment;
         unsigned randomness = start-1;
         bool res = false;
         while(!res){
            randomness++;
            res = sniDistributionSMT(numberGates, randomnessPerGate, randomness, &assignment);
         }
         return randomness;
    }

    /// Recursive function that searches for a valid next random value (fulfilling the 
    /// conditions for random reuse in parallel SNI gadgets) given a valid partial 
    /// assignment.
    ///
    /// assignment:         Valid partial assignment that was already found (can be empty)
    /// start:              Index of the randomness were the alg. starts looking
    /// randomnessParGate:  Number of values required (length of final assignment)
    /// numberRandomness:   Number of overall available randomness
    /// pairs:              List of pairs of indices that are already used and, hence, 
    ///                         forbidden, pairs are (i, pairs[i][0]),...,(i, pairs[i][n])
    bool findAssignmentSni(
                std::vector<unsigned> *assignment,
                unsigned start,
                unsigned randomnessPerGate,
                unsigned numberRandomness,
                std::vector<std::set<unsigned>> *pairs
    ){  
        //Return true if a valid assignment with enough random values was found
        if(assignment->size() == randomnessPerGate)
            return true;
        //Search for a next valid random value for the assignment
        //All values until the last entry in assignment can be ignored as they are 
        //already tested 
        for(unsigned index=start; index<numberRandomness; index++){
            //Check whether this random value can be added to the found partial assignment 
            bool inPairs = false;
            for(unsigned element_0 : *assignment){
                //Values in assignment are in increasing order and we only check for values
                //larger then the last entry
                if(element_0 < index && pairs->at(element_0).find(index) != pairs->at(element_0).end()){
                    inPairs = true;
                }
            }
            if(!inPairs){
                //Add this random value to the assignment if it is allowed
                assignment->push_back(index);
                //Recursively search a random value for the next postion 
                if(findAssignmentSni(assignment, index+1, randomnessPerGate, numberRandomness, pairs)){
                    //Return true if a valid assignment was found
                    return true;
                } else{
                    //Remove the added random value again, if no valid assignment was found
                    assignment->pop_back();
                }
            }
        }
        return false;
    }

    /// Function that searches for a distribution of randomness for a set of parallel
    /// SNI gadgets using a heuristic algorithm, i.e., a distribution where there exists 
    /// no pair of random values that go to more than one gadget simultaneously.
    ///
    /// numberGates:        number of gadgets in the parallel set of gadgets
    /// randomnessPerGate:  number of random elements that each gadget requires 
    ///                           (determined by the security order)
    /// assignment:         pointer to a data structure that is used for the found assignment
    unsigned sniDistributionHeuristic(
                unsigned numberGates, 
                unsigned randomnessPerGate, 
                std::vector<std::vector<unsigned>> *assignment,
                std::vector<unsigned> *usedRandomness = NULL
    ){
        //Initialize the overall randomness to the number of randomness one gate needs
        unsigned numberRandomness = randomnessPerGate;
        //Initialize the number of used randomness for zero and one gate gates
        if(usedRandomness != NULL){
            usedRandomness->push_back(0);
            usedRandomness->push_back(numberRandomness);
        }
        //Declare required variables
        //pairs[i] will store indices with are already used together with index i 
        std::vector<std::set<unsigned>> pairs;
        for(unsigned i=0; i<numberRandomness; i++){
            pairs.push_back(std::set<unsigned>());
        }
        //Initialize assignment for first gadget
        assignment->push_back(std::vector<unsigned>());
        for(unsigned i=0; i<randomnessPerGate; i++){
            //Add current value to assignment of gadget 0
            assignment->at(0).push_back(i);
            //Add all pairs of values already used
            for(unsigned j=i+1; j<randomnessPerGate; j++){
                pairs[i].insert(j);
            }
        }
        //Initialize the number of treated gates to one
        unsigned treatedGates = 1;
        unsigned int progress_step = std::max(10, int(numberGates/100));
        //Search for new assignments until there are enough assignments for
        //the required number of gadgets
        while(treatedGates < numberGates){

            if(((treatedGates % progress_step) == 0) || treatedGates == numberGates-1){
                float progress = float(treatedGates) / float(numberGates-1);
                if(progress != 1.0){
                    llvm::errs() << "[ " << int(progress * 100.0) << " %]\b\b\b\b\b\b";
                    if(progress >= 0.1) llvm::errs() << "\b";
                }
            }


            //Seach with a number of random values until no new assignment can be found
            bool found = true;
            while(found){
                //Get next valid assignment
                std::vector<unsigned> thisAssignment;
                found = findAssignmentSni(&thisAssignment, 0, randomnessPerGate, numberRandomness, &pairs);
                //If a valid assignment was found update the state variables
                if(found){
                    //Add found assignment to the list of assignments
                    assignment->push_back(std::vector<unsigned>());
                    for(unsigned element : thisAssignment){
                        assignment->at(assignment->size()-1).push_back(element);
                        //Insert used pairs of indices to the list
                        for(unsigned element_0 : thisAssignment){
                            if(element < element_0){
                                pairs[element].insert(element_0);
                            }else if(element_0 < element){
                                pairs[element_0].insert(element);
                            }
                        }
                    }
                    //Set the number of randomness required until now
                    if(usedRandomness != NULL){
                        usedRandomness->push_back(numberRandomness);
                    }
                    //Increase the number of treated gates
                    treatedGates++;
                }
                //Exit loop when enough assignments are found
                if(treatedGates == numberGates) break;
            }
            //If no new assignments can be found but more are necessary
            //than add a new random value
            if(treatedGates < numberGates){
                //Initialize a new empty list in the pair list for this new value
                pairs.push_back(std::set<unsigned>());
                //Increase the number of overall available randomness
                numberRandomness++;
            }
        }
        //Return the number of required randomness
        return numberRandomness;
    }

    /// A wrapper function for sniDistributionHeuristic where the resulting
    /// assignment gets lost (useful for access in Python)
    unsigned sniDistributionHeuristicWrapper(
                unsigned numberGates, 
                unsigned randomnessPerGate
    ){
         std::vector<std::vector<unsigned>> assignment;
         return sniDistributionHeuristic(numberGates, randomnessPerGate, &assignment);
    }


    /// Recursive function that searches for a valid next random value (fulfilling the 
    /// conditions for random reuse in parallel PINI gadgets) given a valid partial 
    /// assignment.
    ///
    /// assignment:         Valid partial assignment that was already found (can be empty)
    /// index:              Postion for which a value should be found
    /// randomnessParGate:  Number of values required (length of final assignment)
    /// pairs:              List of pairs of indices that are already used and, hence, 
    ///                         forbidden, pairs are (i, pairs[i][0]),...,(i, pairs[i][n])
    /// fixed:              List of indices that can only used at a fixed postion,
    ///                          where fixed[i] contains all values that can be used at 
    ///                          postion i
    /// free:               List of indices that can be used at any postion
    bool findAssignmentPini(
                std::vector<unsigned> *assignment,
                unsigned index,
                unsigned randomnessPerGate,
                std::vector<std::set<unsigned>> *pairs,
                std::vector<std::set<unsigned>> *fixed,
                std::vector<unsigned> *free
    ){  
        //Return true if a valid assignment with enough random values was found
        if(assignment->size() == randomnessPerGate)
            return true;
        
        //Try all possible candidates for this position (determined by index)
        //First try all random values where the postion is already fixed to this position
        //Reverse order seems to have a better heuristic
        //(Python has an randomly ordered set and achieves better results)
        for(std::set<unsigned>::reverse_iterator element=fixed->at(index).rbegin(); element!=fixed->at(index).rend(); element++){
            //Check whether this random value can be added to the found partial assignment 
            bool inPairs = false;
            for(unsigned element_0 : *assignment){
                if(element_0 < *element && pairs->at(element_0).find(*element) != pairs->at(element_0).end()){
                    inPairs = true;
                } else if(*element < element_0 && pairs->at(*element).find(element_0) != pairs->at(*element).end()){
                    inPairs = true;
                }
            }
            if(!inPairs){
                //Add this random value to the assignment if it is allowed
                assignment->push_back(*element);
                //Recursively search a random value for the next postion 
                if(findAssignmentPini(assignment, index+1, randomnessPerGate, pairs, fixed, free)){
                    //Return true if a valid assignment was found
                    return true;
                } else{
                    //Remove the added random value again, if no valid assignment was found
                    assignment->pop_back();
                }
            }
        }
        //Try a free random value (when it exists) for this postion if non of the 
        //fixed values yield a valid assignment. 
        if(free->size() > 0){
            //Get first free random value and remove it from the list of free values
            unsigned usedFree = free->at(0);
            free->erase(free->begin());
            //Add the free value to the current (parital) assignment
            assignment->push_back(usedFree);
            //Recursively search a random value for the next postion 
            if(findAssignmentPini(assignment, index+1, randomnessPerGate, pairs, fixed, free)){
                //Return true if a valid assignment was found
                return true;
            } else{
                //Remove the added random value again, if no valid assignment was found
                assignment->pop_back();
                //Add the removed value to the list of free values
                free->push_back(usedFree);
                //Return false. There is no need to try other free values
                return false;
            }
        } else {
            //Return false if no free random value exists
            return false;
        }
    }

    /// Function that searches for a distribution of randomness for a set of parallel
    /// PINI gadgets using a heuristic algorithm, i.e., a distribution where there exists 
    /// no pair of random values that go to more than one gadget simultaneously and reused 
    /// random values are always used at the same postion. 
    ///
    /// numberGates:        number of gadgets in the parallel set of gadgets
    /// randomnessPerGate:  number of random elements that each gadget requires 
    ///                           (determined by the security order)
    /// assignment:         pointer to a data structure that is used for the found assignment
    unsigned piniDistributionHeuristic(
                unsigned numberGates, 
                unsigned randomnessPerGate, 
                std::vector<std::vector<unsigned>> *assignment,
                std::vector<unsigned> *usedRandomness = NULL
    ){
        //Initialize the overall randomness to the number of randomness one gate needs
        unsigned numberRandomness = randomnessPerGate;
        //Initialize the number of used randomness for zero and one gate gates
        if(usedRandomness != NULL){
            usedRandomness->push_back(0);
            usedRandomness->push_back(numberRandomness);
        }
        //Declare required variables
        //pairs[i] will store indices with are already used together with index i 
        std::vector<std::set<unsigned>> pairs;
        for(unsigned i=0; i<numberRandomness; i++){
            pairs.push_back(std::set<unsigned>());
        }
        //fixed[i] will store indices that are used at position i
        std::vector<std::set<unsigned>> fixed;
        //a list of random values that have not yet a fixed postion
        std::vector<unsigned> free;

        //Initialize assignment for first gadget
        assignment->push_back(std::vector<unsigned>());
        for(unsigned i=0; i<randomnessPerGate; i++){
            //Add current value to assignment of gadget 0
            assignment->at(0).push_back(i);
            //Add current value to the list of elements where index is fixed
            fixed.push_back(std::set<unsigned>());
            fixed[i].insert(i);
            //Add all pairs of values already used
            for(unsigned j=i+1; j<randomnessPerGate; j++){
                pairs[i].insert(j);
            }
        }
        //Initialize the number of treated gates to one
        unsigned treatedGates = 1;
        unsigned int progress_step = std::max(10, int(numberGates/100));
        //Search for new assignments until there are enough assignments for
        //the required number of gadgets
        while(treatedGates < numberGates){

            if(((treatedGates % progress_step) == 0) || treatedGates == numberGates-1){
                float progress = float(treatedGates) / float(numberGates-1);
                if(progress != 1.0){
                    llvm::errs() << "[ " << int(progress * 100.0) << " %]\b\b\b\b\b\b";
                    if(progress >= 0.1) llvm::errs() << "\b";
                }
            }

            //Seach with a number of random values until no new assignment can be found
            bool found = true;
            while(found){
                //Get next valid assignment
                std::vector<unsigned> thisAssignment;
                found = findAssignmentPini(&thisAssignment, 0, randomnessPerGate, &pairs, &fixed, &free);
                //If a valid assignment was found update the state variables
                if(found){
                    //Add found assignment to the list of assignments
                    assignment->push_back(std::vector<unsigned>());
                    for(unsigned element : thisAssignment){
                        assignment->at(assignment->size()-1).push_back(element);
                        //Insert used pairs of indices to the list
                        for(unsigned element_0 : thisAssignment){
                            if(element < element_0){
                                pairs[element].insert(element_0);
                            }else if(element_0 < element){
                                pairs[element_0].insert(element);
                            }
                        }
                    }
                    //Add new indices that are fixed at one postion to the list
                    for(unsigned i=0; i<thisAssignment.size(); i++){
                        fixed[i].insert(thisAssignment[i]);
                    }
                    //Set the number of randomness required until now
                    if(usedRandomness != NULL){
                        usedRandomness->push_back(numberRandomness);
                    }
                    //Increase the number of treated gates
                    treatedGates++;
                }
                //Exit loop when enough assignments are found
                if(treatedGates == numberGates) break;
            }
            //If no new assignments can be found but more are necessary
            //than add a new random value
            if(treatedGates < numberGates){
                //Add the new random value to the list of free values
                free.push_back(numberRandomness);
                //Initialize a new empty list in the pair list for this new value
                pairs.push_back(std::set<unsigned>());
                //Increase the number of overall available randomness
                numberRandomness++;
            }
        }
        //Return the number of required randomness
        return numberRandomness;
    }

    /// A wrapper function for piniDistributionHeuristic where the resulting
    /// assignment gets lost (useful for access in Python)
    unsigned piniDistributionHeuristicWrapper(
                unsigned numberGates, 
                unsigned randomnessPerGate
    ){
         std::vector<std::vector<unsigned>> assignment;
         return piniDistributionHeuristic(numberGates, randomnessPerGate, &assignment, NULL);
    }

}
}