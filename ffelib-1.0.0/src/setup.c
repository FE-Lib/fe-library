/*
 * setup.c
 *
 *  Created on: 2014/06/06
 *      Author: h_ksk
 */

//#include <stdlib.h>
#include "common.h"
//#include "tfel_dpvs.h"


#define N 2//Non-Monotone


void tfel_gen_setup_params(int d);


int main(int argc, char *argv[]) {
	unsigned int d = 0; //a number of attributes
    int c;
    
    while ((c = getopt (argc, argv, "d:")) != -1) {
        
        switch (c)
        {
            case 'd':
                d = atoi(optarg);
                printf("d = %d\n", d);
                break;
            case '?':
                if (optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                             "Unknown option character `\\x%x'.\n", optopt);
                return -1;
            default:
                exit(-1);
        }
    }
    if (d <= 0) {
        fprintf(stderr, "a number of attributes error\n");
        exit(-1);
    }

    tfel_gen_setup_params(d);

	printf("setup return \n");

	return 0;

}

void tfel_gen_setup_params(int d) {
    //generate vector n
    int i, a;
    a = N;//FE with Non-Monotone
    TFELIB_ERROR result;
    tfel_vector_n *vec_n = NULL;
    if((vec_n = (tfel_vector_n*)malloc(sizeof(tfel_vector_n))) == NULL) {
        perror("malloc failed.");
        exit(1);
    }
    if ((vec_n->n = (unsigned int*)malloc(sizeof(unsigned int)*d)) == NULL) {
        free(vec_n);
        printf("malloc failed\n");
        exit(1);
    }
    for (i = 0; i < d; i++) {
        vec_n->n[i] = a;
    }
    tfel_gen_ob(d, vec_n);
    
    free(vec_n->n);
    free(vec_n);
    
    return ;
}





