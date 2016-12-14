#include "rrcs.h"

#define random(x) (rand()%x)


/*
    Function:
        compute_number_of_redundant_chunks: the function is used to compute the number of redundant chunks added by RRCS
        
    The Input Parameter:
        total: the total number of the chunks in a file
        non_duplicate: the number of non-duplicate chunks in the file
        parameter: the system parameter \lambda in RRCS
        
    Output:
        num_redundant: the number of redundant chunks added by RRCS
*/

int compute_number_of_redundant_chunks (int total, int non_duplicate, float parameter)
{
    int upper_bound = ceil(total * parameter);               // get the upper bound
    int num_redundant = 0;
    
    if(non_duplicate == 0)
    {
        num_redundant = random(upper_bound) + 1;
    }
    else if(non_duplicate < total && total > 0)
    {
        num_redundant = random(upper_bound);
    }
    else
    {
        num_redundant = 0;  
    }
    
    return num_redundant;
}




