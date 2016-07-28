/*
 * Enc.c
 *
 *  Created on: 2014/11/13
 *      Author: h_ksk
 */

#include "common.h"


#define clocktest
//#define d 20


//#define debag
int tfel_encrypt_cp(char *encfile, char *policy_string, char *listfile);
int tfel_encrypt_kp(char *encfile, char *useratt, char *listfile);


//条件式を行列に変換し、アクセス構造として生成
//その後それを引数としてEncを実行する
int main(int argc, char *argv[]) {
#ifdef clocktest
    clock_t start, end;
    
    start = clock();
    printf( "開始時間:%d\n", start );
#endif

    struct option long_opts[] = {
        {"cp", required_argument, NULL, 'c'},
        {"kp", required_argument, NULL, 'k'},
        {0, 0, 0, 0}
    };

	int oflag = FALSE, pflag = FALSE, aflag = FALSE, fflag = FALSE, cpflag = FALSE, kpflag = FALSE;
	char *encfile = NULL;
	char *listfile = NULL;
	char *inputfile = NULL;
    char *inputcsv = NULL;
	int  c, d;
	char *policy_string = NULL;
    char *useratt = "useratt.csv";

	opterr = 0;

	while ((c = getopt_long (argc, argv, "a:o:f:c:k:h", long_opts, NULL)) != -1) {

	switch (c)
	  {//caseの順序変更の必要あり
		case 'a':
			  aflag = TRUE;
			  listfile = optarg;
			  break;
		case 'o':
			  oflag = TRUE;
			  encfile = optarg;
			  break;
		case 'f':
			  fflag = TRUE;
			  inputfile = optarg;
			  break;
        case 'c':
              pflag = TRUE;
              cpflag = TRUE;
              policy_string = strdup(optarg);
              break;
        case 'k':
              kpflag = TRUE;
              useratt = optarg;
              printf("useratt csv = %s\n", useratt);
              break;
		case 'h':
			  //print_help();
			  exit(1);
		/*case '?':
			if (optopt == 'o' )
				fprintf (stderr, "Option -%o requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,
						 "Unknown option character `\\x%x'.\n", optopt);
			return 1;*/
		default:
              //print_help();
			  exit(-1);
		}
	}

	/* use default file name if not set */
	if (oflag == FALSE) {
		encfile = inputfile;
	}
    if(cpflag == FALSE && kpflag == FALSE) {
        fprintf(stderr, "CP or KP\n");
        exit(-1);
    }
    
    int (*tfel_encrypt)(char *, char *, char *); //関数ポインタの宣言
    if (cpflag == TRUE) {
        tfel_encrypt = tfel_encrypt_cp;
        tfel_encrypt(encfile, policy_string, listfile);
    }
    else if (kpflag == TRUE) {
        tfel_encrypt = tfel_encrypt_kp;
        tfel_encrypt(encfile, useratt, listfile);
    }

#ifdef clocktest
    end = clock();
    printf( "終了時間:%d\n", end );
    printf( "処理時間:%f[ms]\n", (double)(end - start)/CLOCKS_PER_SEC );
#endif
	return 0;

}


int tfel_encrypt_cp(char *encfile, char *policy_string, char *listfile) {
    int d;
    policy_attribute_list *p_list = NULL;
    if ((p_list = parse_policy_string_to_attlist(policy_string)) == NULL) {
        exit(-1);
    }

    free(policy_string);
    //parse input string
    
    //pubkey input
    tfel_pubkey *pubkey;
    pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));

    if (pubkey == NULL) {
        tfel_policy_clear(p_list);
        free(p_list);
        exit(-1);
    }
    
    tfel_param_G param_G;
    pairing_init(param_G.p, CURVE);
    importpub(pubkey, param_G);
    //pubkey input
    
    //共通
    //input csv
    attribute_list *list = malloc(sizeof(attribute_list));
    d = pubkey->num_att;
    import_att_list(d, list, listfile);
    //input csv
    printf("import_att_list end\n");
    

    //gen SpanProgram
    AccessStructure *structure = NULL;
    structure = (AccessStructure*)malloc(sizeof(AccessStructure));
    if (create_AccessStructurefromPolicy(structure, p_list, list) == -1) {
        printf("cannot create_AccessStructurefromPolicy\n");
        clear_att_list(list);
        free(list);
        pairing_clear(param_G.p);
        //free(param_G);
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        tfel_policy_clear(p_list);
        free(p_list);
        exit(-1);
    }
    adjustment_SpanProgram(structure->S);
    print_spanprogram(structure->S);
    //gen SpanProgram
    printf("created access structure\n");
    
    /*
     * 具体的な暗号化の流れ
     * 1.CP-FEの暗号化の出力c_(d+1) gT^ksi を作ってハッシュで出力
     * 2.1.の出力をセッション鍵としてファイルをAESで暗号化
     * 3.まとめてbase64エンコーディングして出力
     *
     */
    
    //gen c_i
    tfel_create_ciphertext_from_policy(pubkey, param_G, structure, encfile);
    //gen c_i
    
    //free
    tfel_clear_pk(pubkey->num_att, pubkey);
    free(pubkey);
    free(structure);
    clear_att_list(list);
    pairing_clear(param_G.p);
    //free(param_G);
    tfel_policy_clear(p_list);
    free(p_list);
    
    printf("fin\n");

    return 0;
}

int tfel_encrypt_kp(char *encfile, char *useratt, char *listfile) {
    int d;
    //pubkey input
    tfel_pubkey *pubkey;
    pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));

    if (pubkey == NULL) {
        exit(-1);
    }
    
    tfel_param_G param_G;
    pairing_init(param_G.p, CURVE);
    /* 構造的にポインタで初期化する必要なしな気が
     tfel_param_G *param_G = NULL;
     param_G = (tfel_param_G*)malloc(sizeof(tfel_param_G));
     if (param_G == NULL) {
     tfel_clear_pk(pubkey->num_att, pubkey);
     free(pubkey);
     tfel_policy_clear(test);
     free(test);
     exit(-1);
     }
     memset(param_G, 0, sizeof(tfel_param_G));
     pairing_init(param_G->p, CURVE);
     */
    importpub(pubkey, param_G);
    //pubkey input
    
    //KP-FE
    //input set of attributes from csv file
    attribute_set Delta;
    if (att_set(&Delta, pubkey->num_att, listfile, useratt) != 0){
        printf("att_set error\n");
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        pairing_clear(param_G.p);
        exit(-1);
    }
    
    printf("att_set input end\n");
    
    d = Delta.num;
    //KP-FE
    
    //共通
    //input csv
    attribute_list *list = malloc(sizeof(attribute_list));
    d = pubkey->num_att;
    import_att_list(d, list, listfile);
    //input csv
    printf("import_att_list end\n");
    
    //gen c_i
    if (tfel_create_ciphertext_from_attribute(pubkey, param_G, Delta, encfile) != 0) {
        printf("create ciphertext error\n");
        
    }
    
    //free
    tfel_clear_pk(pubkey->num_att, pubkey);
    free(pubkey);
    clear_att_list(list);
    pairing_clear(param_G.p);
    //free(param_G);
    
    printf("fin\n");

    return 0;
    
}
