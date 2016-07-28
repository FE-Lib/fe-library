/*
 * KeyGen.c
 *
 *  Created on: 2014/09/28
 *      Author: h_ksk
 */



#include "common.h"

int tfel_keygen_cp(char *inputcsv, char *key, char *useratt);
int tfel_keygen_kp(char *inputcsv, char *key, char *policy_string);

//入力の引数は、公開鍵pk, マスター鍵sk, 属性リスト, 属性集合Γ, 秘密鍵sk_Γのファイル名
int main(int argc, char *argv[]) {
    struct option long_opts[] = {
        {"cp", required_argument, NULL, 'c'},
        {"kp", required_argument, NULL, 'k'},
        {"key", required_argument, NULL, 'y'},
        {0, 0, 0, 0}
    };
    
	FILE *fp;
    int i, j, k;
	int d; //number of att_set

	int c;
    int aflag = FALSE, kflag = FALSE, uflag = FALSE, cpflag = FALSE, kpflag = FALSE;
	char *inputcsv = NULL, *key = "userkey";
    char *policy_string = NULL;//KP-FE
    char *listfile = NULL;//KP-FE
	char *public_params = PUBLIC_FILE".ffel";
    char *useratt = "useratt.csv";
    unsigned char *sk_Gamma_buf = NULL;
	//while ((c = getopt (argc, argv, "f:C:K:k:h:")) != -1) {
    while ((c = getopt_long (argc, argv, "a:c:k:y:h:", long_opts, NULL)) != -1) {

			switch (c)
			{
				case 'a': //csv file
					aflag = TRUE;
					inputcsv = optarg;
					printf("attribute set = %s\n", inputcsv);
					break;
                case 'c':
                    cpflag = TRUE;
                    uflag = TRUE;
                    useratt = optarg;
                    printf("useratt csv = %s\n", useratt);
                    //inputcsv = optarg;
                    //printf("attribute set = %s\n", inputcsv);
                    break;
                case 'k':
                    kpflag = TRUE;
                    policy_string = strdup(optarg);
                    printf("policy = %s\n", policy_string);
                    break;
				case 'y': // userkey name
					kflag = TRUE;
					key = optarg;
                    printf("key = %s\n", key);
                    break;
                /*case 'u':
                    uflag = TRUE;
                    useratt = optarg;
                    printf("useratt csv = %s\n", useratt);
                    break;
                 */
                case 'h': // print usage
                    //print_help();
                    exit(0);
                    break;
				case '?':
					if (optopt == 'C' || optopt == 'K' || optopt == 'k' || optopt == 'u')
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

	/*if (fflag == FALSE) {
		fprintf(stderr, "No csv file error\n");
		exit(-1);
	}*/
    if (cpflag == FALSE && kpflag == FALSE) {
        fprintf(stderr, "CP-FE or KP-FE?\n");
        exit(-1);
    }
    if (cpflag == TRUE && uflag == FALSE) {
        fprintf(stderr, "No user attribute error\n");
        exit(-1);
    }
	if (kflag == FALSE) {
		fprintf(stderr, "No userkey error\n");
		exit(-1);
	}

    int (*tfel_keygen)(char *inputcsv, char *key, char *useratt);
    if (cpflag == TRUE) {
        tfel_keygen = tfel_keygen_cp;
        tfel_keygen(inputcsv, key, useratt);
    }
    else {
        tfel_keygen = tfel_keygen_kp;
        tfel_keygen(inputcsv, key, policy_string);
    }

	return 0;
}



int tfel_keygen_cp(char *inputcsv, char *key, char *useratt) {
    int d;
    FILE *fp;
    unsigned char *sk_Gamma_buf = NULL;
    tfel_pubkey *pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));
    if (pubkey == NULL) exit(-1);
    tfel_masterkey *masterkey = (tfel_masterkey*)malloc(sizeof(tfel_masterkey));
    if (masterkey == NULL) {
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        exit(-1);
    }
    
    tfel_param_G param_G;
    pairing_init(param_G.p, CURVE);
    
    importpub(pubkey, param_G);
    importsecret(masterkey, param_G);
    
    //CP-FE
    //input set of attributes from csv file
    attribute_set Delta;
    if (att_set(&Delta, pubkey->num_att, inputcsv, useratt) != 0){
        printf("att_set error\n");
        tfel_clear_sk(pubkey->num_att, masterkey);
        free(masterkey);
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        pairing_clear(param_G.p);
        exit(-1);
    }
    
    printf("att_set input end\n");
    
    d = Delta.num;
    
    
    //init kStar 共通部分
    mpz_t order;
    mpz_init(order);
    basis *kStar = NULL;
    gmp_randstate_t s;
    gmp_randinit_default(s);
    gmp_randseed_ui(s, (unsigned long)time(NULL));
    mpz_set(order, *pairing_get_order(param_G.p));
    
    
    kStar = (basis*)malloc(sizeof(basis));
    kStar->dim = d;
    if (init_kStar(kStar, d, param_G) != 0) {
    kStarERROR:
        tfel_clear_sk(pubkey->num_att, masterkey);
        free(masterkey);
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        
        free(kStar);
        gmp_randclear(s);
        mpz_clear(order);
        //free(delta);//CP
        pairing_clear(param_G.p);
        
        exit(-1);
        
    }
    //init kStar 共通部分
    
    mpz_t *delta;
    delta = (mpz_t*)malloc(sizeof(mpz_t));
    mpz_t **phi_t = NULL;
    
    gen_random(delta, s, order);
    
    phi_t = (mpz_t**)malloc(sizeof(mpz_t*)*d);
    
    if (init_phi_t(phi_t, d, s, order) != 0) {
        clear_basis(kStar);
        goto kStarERROR;
    }

    
    kStar_set_cp(*delta, phi_t, masterkey, kStar, Delta);

    

    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;

    tfel_export_sk_Gamma(NULL, 0, result_len, "%d%v%B", &(Delta.num), Delta.value, kStar);//CP
    
    printf("result_len = %zd\n", *result_len);
    if((sk_Gamma_buf = malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    tfel_export_sk_Gamma(sk_Gamma_buf, buf_len, result_len, "%d%v%B", &(Delta.num), Delta.value, kStar);
    
    //base64 encode
    size_t skLength;
    char *skBuffer;
    skBuffer = NewBase64Encode(sk_Gamma_buf, buf_len, FALSE, &skLength);
    
    fp = fopen(key, "w");
    if (fp != NULL) {
        fprintf(fp, "%s", skBuffer);
    }
    fclose(fp);
    //e(kStar_t, b_t,1) = gT^δ
    
    //free
    free(skBuffer);
    memset(sk_Gamma_buf, 0, sizeof(sk_Gamma_buf));
    free(sk_Gamma_buf);
    
    clear_phi_t(phi_t, d);

    
    tfel_clear_sk(pubkey->num_att, masterkey);
    free(masterkey);
    tfel_clear_pk(pubkey->num_att, pubkey);
    free(pubkey);
    
    clear_basis(kStar);
    free(kStar);
    gmp_randclear(s);
    mpz_clear(order);

    free(delta);

    pairing_clear(param_G.p);
    
    
    printf("KeyGen end\n");
    return 0;
}

int tfel_keygen_kp(char *inputcsv, char *key, char *policy_string) {
    int d;
    FILE *fp;
    unsigned char *sk_Gamma_buf = NULL;
    tfel_pubkey *pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));
    if (pubkey == NULL) exit(-1);
    tfel_masterkey *masterkey = (tfel_masterkey*)malloc(sizeof(tfel_masterkey));
    if (masterkey == NULL) {
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        exit(-1);
    }
    tfel_param_G param_G;
    pairing_init(param_G.p, CURVE);
    
    importpub(pubkey, param_G);
    importsecret(masterkey, param_G);
    
    //後でこの部分を関数化
    //parse input string
    policy_attribute_list *p_list = NULL;
    /*
    p_list = (policy_attribute_list*)malloc(sizeof(policy_attribute_list));
    if (p_list == NULL) {
        tfel_clear_sk(pubkey->num_att, masterkey);
        free(masterkey);
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        pairing_clear(param_G.p);
        exit(-1);
    }*/
    
    if ((p_list = parse_policy_string_to_attlist(policy_string)) == NULL) {
        tfel_clear_sk(pubkey->num_att, masterkey);
        free(masterkey);
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        pairing_clear(param_G.p);
        exit(-1);
    }
    
    free(policy_string);
    //parse input string
    
    //input csv
    attribute_list *list = malloc(sizeof(attribute_list));
    d = pubkey->num_att;
    printf("%s\n", inputcsv);
    import_att_list(d, list, inputcsv);
    //input csv
    printf("import_att_list end\n");
    
    //gen SpanProgram
    AccessStructure *structure = NULL;
    structure = (AccessStructure*)malloc(sizeof(AccessStructure));
    if (create_AccessStructurefromPolicy(structure, p_list, list) == -1) {
        printf("cannot create_AccessStructurefromPolicy\n");
        clear_att_list(list);
        free(list);
        pairing_clear(param_G.p);//encと統一
        //free(param_G);//encと統一
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        tfel_policy_clear(p_list);
        free(p_list);
        exit(-1);
    }
    adjustment_SpanProgram(structure->S);
    print_spanprogram(structure->S);
    //gen SpanProgram

    
    //init kStar 共通部分
    mpz_t order;
    mpz_init(order);
    basis *kStar = NULL;
    gmp_randstate_t s;
    gmp_randinit_default(s);
    gmp_randseed_ui(s, (unsigned long)time(NULL));
    mpz_set(order, *pairing_get_order(param_G.p));
    
    
    kStar = (basis*)malloc(sizeof(basis));
    kStar->dim = d;//dからl+1にする
    if (init_kStar(kStar, d, param_G) != 0) {
    kStarERROR:
        tfel_clear_sk(pubkey->num_att, masterkey);
        free(masterkey);
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        
        free(kStar);
        gmp_randclear(s);
        mpz_clear(order);
        //free(delta);//CP
        pairing_clear(param_G.p);
        
        exit(-1);
        
    }

    //init kStar 共通部分

    
    if(kStar_set_kp(masterkey, param_G, kStar, structure) != 0) {
        printf("kStar_set_kp error\n");
        
    }
    
    //以下は共通(free以外)
    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;
    
    //KP-FE
    tfel_serialize_ciphertext(NULL, 0, result_len, "%S%c", structure, kStar);
    printf("result_len = %zd\n", *result_len);
    if((sk_Gamma_buf = malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    tfel_serialize_ciphertext(sk_Gamma_buf, buf_len, result_len, "%S%c", structure, kStar);
    //KP-FE

    
    //base64 encode
    size_t skLength;
    char *skBuffer;
    skBuffer = NewBase64Encode(sk_Gamma_buf, buf_len, FALSE, &skLength);
    
    fp = fopen(key, "w");
    if (fp != NULL) {
        fprintf(fp, "%s", skBuffer);
    }
    fclose(fp);
    //e(kStar_t, b_t,1) = gT^δ
    
    //free
    free(skBuffer);
    memset(sk_Gamma_buf, 0, sizeof(sk_Gamma_buf));
    free(sk_Gamma_buf);

    
    tfel_clear_sk(pubkey->num_att, masterkey);
    free(masterkey);
    tfel_clear_pk(pubkey->num_att, pubkey);
    free(pubkey);
    
    clear_basis(kStar);
    free(kStar);
    gmp_randclear(s);
    mpz_clear(order);

    pairing_clear(param_G.p);
    
    
    printf("KeyGen end\n");
    return 0;
}
 

