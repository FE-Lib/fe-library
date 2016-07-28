/*
 * Dec.c
 *
 *  Created on: 2015/03/19
 *      Author: h_ksk
 */

#include <ctype.h>
#include "common.h"
#include "openssl/aes.h"

#define clocktest

#define MAX_ATTRIBUTE 20

typedef struct _secretkey {
    attribute_set *sk_Delta;
    AccessStructure *sk_AS;
    basis *sk_kStar;
} secretkey;

//int tfel_decrypt(char *inputfile, char *keyfile, char *output);
Element *pairing_c_k(EC_PAIRING p, rho_i *rho, EC_POINT *c, EC_POINT *k, mpz_t *alpha_i);
int search_t(rho_i *rho, attribute_set *sk_Delta);
int tfel_decrypt_kp(char *inputfile, char *keyfile, char *output);
int tfel_decrypt_cp(char *inputfile, char *keyfile, char *output);

void tokenize_inputfile(char* in, char** abe, char** aes, char** iv);
void tfel_deserialize_ciphertext_cp(AccessStructure *AS, basis *c_i, unsigned char *bin_ct_buf, size_t max_len, EC_PAIRING p);
int tfel_deserialize_ciphertext_kp(attribute_set *Delta, basis *c_i, unsigned char *bin_ct_buf, size_t max_len, EC_PAIRING p);

//#define clocktest

/*
 * pk, sk_Gamma, 暗号文を引数として復号判定した後に、復号可能なら平文を出力する
 * 復号条件を出力する関数とかあるといいかも
 */
int main(int argc, char *argv[]) {
#ifdef clocktest
    clock_t start, end;
    
    start = clock();
    printf( "開始時間:%d\n", start );
#endif
    struct option long_opts[] = {
        {"cp", no_argument, NULL, 'c'},
        {"kp", no_argument, NULL, 'k'},
        {"key", required_argument, NULL, 'y'},
        {0, 0, 0, 0}
    };

	int fflag = FALSE, kflag = FALSE, cpflag = FALSE, kpflag = FALSE;
	char *input = "input.txt", *key = "private.key";
	//char *public_params = PUBLIC_FILE".cpfe";
	char *output = NULL;//"output.txt";
	int c;

	opterr = 0;

	while ((c = getopt_long (argc, argv, "f:y:ckh", long_opts, NULL)) != -1) {

		switch (c)
		{
			case 'f': // file that holds encrypted data
                /*if (cpflag == FALSE && kpflag == FALSE) {
                    fprintf(stderr, "CP or KP\n");
                    exit(-1);
                }*/
				fflag = TRUE;
				input = optarg;
				output = (char*)malloc(strlen(input));
				strcpy(output, input);
				printf("input = %s\n", input);
                if (cpflag == TRUE) sprintf(strstr(output, "."CPFE_EXTENSION), "\0");
                if (kpflag == TRUE) sprintf(strstr(output, "."KPFE_EXTENSION), "\0");
				//sprintf(strstr(output, ".tfel"), "\0");
				break;
			case 'y': // input of private key
				kflag = TRUE;
				key = optarg;
				//debug("Private-key file = '%s'\n", key);
				break;
            case 'c':
                cpflag = TRUE;
                break;
            case 'k':
                kpflag = TRUE;
                break;
			case 'h': // print usage
				//print_help();
				exit(0);
				break;
			case '?':
				if (optopt == 'f')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				return -1;
			default:
				exit(-1);
		}
	}

	if(fflag == FALSE) {
		fprintf(stderr, "No file to decrypt!\n");
		exit(-1);
	}

	if(kflag == FALSE) {
		fprintf(stderr, "Decrypt without a key?\n");
		exit(-1);
	}
    if(cpflag == FALSE && kpflag == FALSE) {
        fprintf(stderr, "CP or KP\n");
        exit(-1);
    }
    

    int (*tfel_decrypt)(char *, char *, char *);
    if (cpflag == TRUE) tfel_decrypt = tfel_decrypt_cp;
    else if (kpflag == TRUE) tfel_decrypt = tfel_decrypt_kp;
    tfel_decrypt(input, key, output);

	free(output);
	printf("Dec fin\n");
#ifdef clocktest
    end = clock();
    printf( "終了時間:%d\n", end );
    printf( "処理時間:%f[ms]\n", (double)(end - start)/CLOCKS_PER_SEC );
#endif
	return 0;
}



//c_iとk_iをペアリングする関数
//¬記号で別々の処理する
//(v_i - x_t)も必要→とりあえず置いておこう……→一応できた？
Element *pairing_c_k(EC_PAIRING p, rho_i *rho, EC_POINT *c, EC_POINT *k, mpz_t *alpha_i) {
	int i;
	Element *result;
	result = (Element*)malloc(sizeof(Element));
	Element egg, tempegg1, tempegg2;
	element_init(egg, p->g3);
	element_init(tempegg1, p->g3);
	element_init(tempegg2, p->g3);
	element_init(*result, p->g3);
	mpz_t temp1;
	mpz_init(temp1);
	mpz_t temp2;
	mpz_init(temp2);
	mpz_t order;
	mpz_init(order);
	mpz_set(order, *pairing_get_order(p));
	element_set_one(*result);

	if (alpha_i == NULL && rho == NULL) { //e(c_0, k_0)
			for (i = 0; i < 5; i++) {
				pairing_map(tempegg1, c[i], k[i], p);
				element_mul(tempegg2, tempegg1, *result);
				element_set(*result, tempegg2);
			}
	}
    else if (mpz_cmp_ui(*alpha_i, 0) == 0) {//return 1
    }
	else if (rho->is_negated == FALSE) {
			for (i = 0; i < 7; i++) {
				pairing_map(tempegg1, c[i], k[i], p);
				element_mul(tempegg2, tempegg1, *result);
				element_set(*result, tempegg2);
			}
			element_pow(tempegg1, *result, *alpha_i);
			element_set(*result, tempegg1);
	}
	else { //is_negated == TRUE
			for (i = 0; i < 7; i++) {
				pairing_map(tempegg1, c[i], k[i], p);
				element_mul(tempegg2, tempegg1, *result);
				element_set(*result, tempegg2);
			}
		mpz_set_ui(temp1, rho->v_t[0]); //v_i - x_t
		mpz_invert(temp2, temp1, order);
		mpz_mul(temp1, temp2, *alpha_i); // alpha_i / (v_i - x_t)
		mpz_mod(*alpha_i, temp1, order);
		element_pow(tempegg1, *result, *alpha_i);
		element_set(*result, tempegg1);
	}

    mpz_clear(order);
    mpz_clear(temp2);
    mpz_clear(temp1);
	element_clear(egg);
	element_clear(tempegg1);
	element_clear(tempegg2);

	return result;
}

//rho(i)->v_tのtをsk_Delta->valueから探してtを返す関数
int search_t(rho_i *rho, attribute_set *sk_Delta) {
	v_vector *v_ptr;
	v_ptr = sk_Delta->value;
	while (v_ptr != NULL) {
		if (rho->t == v_ptr->t) return (v_ptr->t+1);
		else v_ptr = v_ptr->next;
	}

	return 0;
}


int tfel_decrypt_kp(char *inputfile, char *keyfile, char *output) {
    int i;
    FILE *fp;
    //pubkey input //共通
    tfel_pubkey *pubkey = NULL;
    pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));
    if (pubkey == NULL) return -1;
    tfel_param_G *param_G;
    param_G = (tfel_param_G*)malloc(sizeof(tfel_param_G));
    if (param_G == NULL) {
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        return -1;
    }
    memset(param_G, 0, sizeof(tfel_param_G));
    pairing_init(param_G->p, CURVE);
    importpub(pubkey, *param_G);
    //pubkey input

    //KP
    secretkey sk_S;
    sk_S.sk_Delta = NULL;
    sk_S.sk_AS = (AccessStructure*)malloc(sizeof(AccessStructure));
    sk_S.sk_kStar = (basis*)malloc(sizeof(basis));
    import_sk_S(sk_S.sk_AS, sk_S.sk_kStar, *param_G, keyfile);
    //KP
    
    
    //ciphertext input //共通
    char *input_buf = NULL;//,*keyfile_buf = NULL;
    char *aes_blob64 = NULL, *abe_blob64 = NULL, *iv_blob64 = NULL;
    ssize_t input_len;
    size_t key_len;
    
    fp = fopen(inputfile, "r");
    if(fp != NULL) {
        if((input_len = read_file(fp, &input_buf)) > 0) {
            tokenize_inputfile(input_buf, &abe_blob64, &aes_blob64, &iv_blob64);
            if(aes_blob64 == NULL || abe_blob64 == NULL || iv_blob64 == NULL) {
                fprintf(stderr, "Input file either not well-formed or not encrypted.\n");
                
                fclose(fp);
                return -1;
            }
            
            free(input_buf);
        }
    }
    else {
        fprintf(stderr, "Could not load input file: %s\n", inputfile);
        return FALSE;
    }
    fclose(fp);
    //ciphertext input
    
    //decode ciphertext //共通
    tfel_ciphertext ct;
    memset(&ct, 0, sizeof(tfel_ciphertext));
    size_t abeLength;
    unsigned char *data = NewBase64Decode((const char *) abe_blob64, strlen(abe_blob64), &abeLength);
    ct.data = data;
    ct.data_len = abeLength;
    ct.max_len = abeLength;
    //decode ciphertext
    
    //deserialize ciphertext
    printf("abe_blob64 = %zd\n", strlen(abe_blob64));
     printf("abeLength = %zd\n", abeLength);
     printf("ct.data = %s\n", ct.data);
     printf("ct.data_len = %zd\n", ct.data_len);
     printf("ct.max_len = %zd\n", ct.max_len);
    
    basis *c_i = NULL;
    c_i = (basis*)malloc(sizeof(basis));
    if (c_i == NULL){
        //error処理
    }
    
    //KP
    attribute_set *Delta = NULL;
    Delta = (attribute_set*)malloc(sizeof(attribute_set));
    if (Delta == NULL) {
        //解放処理
    }
    if (tfel_deserialize_ciphertext_kp(Delta, c_i, ct.data, ct.max_len, param_G->p) != 0) {
        //error処理
    }
    //KP
    
    //deserialize ciphertext
    
    
    
    //decode iv
    size_t ivLength;
    char *ivec = NewBase64Decode((const char *) iv_blob64, strlen(iv_blob64), &ivLength);
    //debug("IV: ");
    //print_buffer_as_hex((uint8 *) ivec, AES_BLOCK_SIZE);
    //decode iv
    
    //decode aes
    /* decode the aesblob64 */
    size_t aesLength;
    char *aesblob = NewBase64Decode((const char *) aes_blob64, strlen(aes_blob64), &aesLength);
    //printf("sizeof(aesblob) = %zd\n", aesLength);
    //decode aes
    
    
    printf("check\n");
    AccessStructure *aAS;

    print_spanprogram(sk_S.sk_AS->S);
    aAS = check_attribute_to_matrix(Delta, sk_S.sk_AS);

    /*if (check_rank_of_matrix(aAS->S) != 0) {
        //エラー処理
        return -1;
    }*/
    
    //alpha_iを生成
    mpz_t order;
    mpz_init(order);
    mpz_set(order, *pairing_get_order(param_G->p));
    mpz_t *alpha_i;
    mpz_t temp;
    mpz_init(temp);
    Element *K;
    Element *temp_E;
    Element temp_0;
    element_init(temp_0, param_G->p->g3);
    //element_set_zero(temp_0);
    //element_init(K, param_G->p->g3);
    
    alpha_i = calc_alpha_i(aAS, order);

    int t; //search_tで使用
    //rho_i *r_ptr = sk_S.sk_AS->rho;
    rho_i *r_ptr = aAS->rho;
    
    //KP
    for (i = 0; i < aAS->num_policy+1; i++) { //generate K
        //for (i = 0; i < aAS->S->row+1; i++) { //generate K こっちのほうがいい気がする
        if (i == 0) {
            //K = pairing_c_k(param_G->p, NULL, sk_S.sk_kStar->M[0], c_i->M[0], NULL);
            K = pairing_c_k(param_G->p, NULL, c_i->M[0], sk_S.sk_kStar->M[0], NULL);
        }
        else {
            t = search_t(r_ptr, Delta); //r_ptrからtを持ってくる関数
            
            temp_E = pairing_c_k(param_G->p, r_ptr, c_i->M[t], sk_S.sk_kStar->M[i], &alpha_i[i-1]);
            
            element_mul(temp_0, *temp_E, *K);
            element_set(*K, temp_0);
            element_clear(*temp_E);
            free(temp_E);
            r_ptr = r_ptr->next;
        }
    }
    //KP
    printf("K generate\n");
    
    
    //Kのバイト列を16ビットのハッシュに
    key_len = element_get_oct_length(*K); // size of K
    unsigned char *K_oct;
    K_oct = (unsigned char*)malloc(sizeof(unsigned char)*key_len);
    element_to_oct(K_oct, &key_len, *K); // bytes of K
    
    unsigned char *session_key;
    session_key = (unsigned char *)malloc(sizeof(unsigned char)*16);
    //int d_len;
    
    hash_to_bytes(K_oct, key_len, SESSION_KEY_LEN, session_key, 2);
    //Kのバイト列を16ビットのハッシュに
    
    //復号
    AES_KEY sk;
    //char aes_result[aesLength+1];
    char *aes_result;
    aes_result = (char*)malloc(sizeof(char)*aesLength+1);
    AES_set_decrypt_key((uint8 *) session_key, 8*SESSION_KEY_LEN, &sk);
    memset(aes_result, 0, aesLength+1);
    AES_cbc_encrypt((uint8 *) aesblob, (uint8 *) aes_result, aesLength, &sk, (uint8 *) ivec, AES_DECRYPT);
    char magic[strlen(MAGIC)+1];
    memset(magic, 0, strlen(MAGIC)+1);
    strncpy(magic, aes_result, strlen(MAGIC));
    
    
    if(strcmp(magic, MAGIC) == 0) {
        //printf("Recovered magic: '%s'\n", magic);
        //printf("Plaintext: %s\n", (char *) (aes_result + strlen(MAGIC)));
        if ((fp = fopen(output, "w")) == NULL) {
            fprintf(stderr, "output open error\n");
        }
        else {
            fprintf(fp, "%s\n", (char*)(aes_result + strlen(MAGIC)));
            fclose(fp);
        }
        //magic_failed = FALSE;
    }
    else {
        printf("error decryption\n");
        //printf(stderr, "ERROR: ABE decryption unsuccessful!!\n");
        //magic_failed = TRUE;
    }
    //復号
    
    free(aesblob);
    free(aes_blob64);
    free(ivec);
    free(iv_blob64);
    free(data);
    free(abe_blob64);
    free(aes_result);
    //free(&input_buf);
    free(session_key);
    free(K_oct);
    element_clear(*K);
    free(K);
    if (aAS != NULL) {
        for (i = 0; i < aAS->S->row; i++) {
            mpz_clear(alpha_i[i]);
        }
        free(alpha_i);
        AccessStructure_clear(aAS);//error
    }
    element_clear(temp_0);
    mpz_clear(order);
    mpz_clear(temp);
    
    for (i = 0; i < c_i->dim; i++) { //memsetとか追加？
        free(c_i->M[i]);
    }
    free(c_i->M);
    free(c_i);
    
    return 0;
}

int tfel_decrypt_cp(char *inputfile, char *keyfile, char *output) {
    int i;
    FILE *fp;
    //pubkey input //共通
    tfel_pubkey *pubkey = NULL;
    pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));
    if (pubkey == NULL) return -1;
    tfel_param_G *param_G;
    param_G = (tfel_param_G*)malloc(sizeof(tfel_param_G));
    if (param_G == NULL) {
        tfel_clear_pk(pubkey->num_att, pubkey);
        free(pubkey);
        return -1;
    }
    memset(param_G, 0, sizeof(tfel_param_G));
    pairing_init(param_G->p, CURVE);
    importpub(pubkey, *param_G);
    //pubkey input
    
    
    //sk_Gamma input //CP
    secretkey sk_Gamma;
    sk_Gamma.sk_Delta = (attribute_set*)malloc(sizeof(attribute_set));
    sk_Gamma.sk_AS = NULL;
    sk_Gamma.sk_kStar = (basis*)malloc(sizeof(basis));
    import_sk(sk_Gamma.sk_Delta, sk_Gamma.sk_kStar, *param_G, keyfile);
    //sk_Gamma input

    
    //ciphertext input //共通
    char *input_buf = NULL;//,*keyfile_buf = NULL;
    char *aes_blob64 = NULL, *abe_blob64 = NULL, *iv_blob64 = NULL;
    ssize_t input_len;
    size_t key_len;
    
    fp = fopen(inputfile, "r");
    if(fp != NULL) {
        if((input_len = read_file(fp, &input_buf)) > 0) {
            tokenize_inputfile(input_buf, &abe_blob64, &aes_blob64, &iv_blob64);
            if(aes_blob64 == NULL || abe_blob64 == NULL || iv_blob64 == NULL) {
                fprintf(stderr, "Input file either not well-formed or not encrypted.\n");
                
                fclose(fp);
                return -1;
            }
            
            free(input_buf);
        }
    }
    else {
        fprintf(stderr, "Could not load input file: %s\n", inputfile);
        return FALSE;
    }
    fclose(fp);
    //ciphertext input
    
    //decode ciphertext //共通
    tfel_ciphertext ct;
    memset(&ct, 0, sizeof(tfel_ciphertext));
    size_t abeLength;
    unsigned char *data = NewBase64Decode((const char *) abe_blob64, strlen(abe_blob64), &abeLength);
    ct.data = data;
    ct.data_len = abeLength;
    ct.max_len = abeLength;
    //decode ciphertext
    
    //deserialize ciphertext
    /*printf("abe_blob64 = %zd\n", strlen(abe_blob64));
     printf("abeLength = %zd\n", abeLength);
     printf("ct.data = %s\n", ct.data);
     printf("ct.data_len = %zd\n", ct.data_len);
     printf("ct.max_len = %zd\n", ct.max_len);*/
    
    basis *c_i = NULL;
    c_i = (basis*)malloc(sizeof(basis));
    if (c_i == NULL){
        //error処理
    }

    AccessStructure *AS = NULL;
    AS = (AccessStructure*)malloc(sizeof(AccessStructure));
    tfel_deserialize_ciphertext_cp(AS, c_i, ct.data, ct.max_len, param_G->p);
    
    //deserialize ciphertext
    
    
    
    //decode iv
    size_t ivLength;
    char *ivec = NewBase64Decode((const char *) iv_blob64, strlen(iv_blob64), &ivLength);
    //debug("IV: ");
    //print_buffer_as_hex((uint8 *) ivec, AES_BLOCK_SIZE);
    //decode iv
    
    //decode aes
    /* decode the aesblob64 */
    size_t aesLength;
    char *aesblob = NewBase64Decode((const char *) aes_blob64, strlen(aes_blob64), &aesLength);
    //printf("sizeof(aesblob) = %zd\n", aesLength);
    //decode aes
    
    
    
    //拡大係数行列のチェック
    printf("check\n");
    AccessStructure *aAS;

    aAS = check_attribute_to_matrix(sk_Gamma.sk_Delta, AS); //errorならNULLを返す
    
    
    //alpha_iを生成
    mpz_t order;
    mpz_init(order);
    mpz_set(order, *pairing_get_order(param_G->p));
    mpz_t *alpha_i;
    mpz_t temp;
    mpz_init(temp);
    Element *K;
    Element *temp_E;
    Element temp_0;
    element_init(temp_0, param_G->p->g3);

    alpha_i = calc_alpha_i(aAS, order);
    
    
    
    rho_i *r_ptr;
    r_ptr = aAS->rho;
    
    int t; //search_tで使用
    
    for (i = 0; i < aAS->num_policy+1; i++) { //generate K
        if (i == 0) {
            K = pairing_c_k(param_G->p, NULL, c_i->M[0], sk_Gamma.sk_kStar->M[0], NULL);
        }
        else {
            t = search_t(r_ptr, sk_Gamma.sk_Delta); //r_ptrからtを持ってくる関数
            temp_E = pairing_c_k(param_G->p, r_ptr, c_i->M[i], sk_Gamma.sk_kStar->M[t], &alpha_i[i-1]);
            //temp_E = pairing_c_k(param_G->p, r_ptr, c_i->M[t], sk_Gamma.sk_kStar->M[i], &alpha_i[i-1]);
            
            element_mul(temp_0, *temp_E, *K);
            element_set(*K, temp_0);
            element_clear(*temp_E);
            free(temp_E);
            r_ptr = r_ptr->next;
        }
    }
    //printf("K generate\n");
    
    
    //Kのバイト列を16ビットのハッシュに
    key_len = element_get_oct_length(*K); // size of K
    unsigned char *K_oct;
    K_oct = (unsigned char*)malloc(sizeof(unsigned char)*key_len);
    element_to_oct(K_oct, &key_len, *K); // bytes of K
    
    unsigned char *session_key;
    session_key = (unsigned char *)malloc(sizeof(unsigned char)*16);
    //int d_len;
    
    hash_to_bytes(K_oct, key_len, SESSION_KEY_LEN, session_key, 2);
    //Kのバイト列を16ビットのハッシュに
    
    //復号
    AES_KEY sk;
    //char aes_result[aesLength+1];
    char *aes_result;
    aes_result = (char*)malloc(sizeof(char)*aesLength+1);
    AES_set_decrypt_key((uint8 *) session_key, 8*SESSION_KEY_LEN, &sk);
    memset(aes_result, 0, aesLength+1);
    AES_cbc_encrypt((uint8 *) aesblob, (uint8 *) aes_result, aesLength, &sk, (uint8 *) ivec, AES_DECRYPT);
    char magic[strlen(MAGIC)+1];
    memset(magic, 0, strlen(MAGIC)+1);
    strncpy(magic, aes_result, strlen(MAGIC));
    
    
    if(strcmp(magic, MAGIC) == 0) {
        //printf("Recovered magic: '%s'\n", magic);
        //printf("Plaintext: %s\n", (char *) (aes_result + strlen(MAGIC)));
        if ((fp = fopen(output, "w")) == NULL) {
            fprintf(stderr, "output open error\n");
        }
        else {
            fprintf(fp, "%s\n", (char*)(aes_result + strlen(MAGIC)));
            fclose(fp);
        }
        //magic_failed = FALSE;
    }
    else {
        printf("error decryption\n");
        //printf(stderr, "ERROR: ABE decryption unsuccessful!!\n");
        //magic_failed = TRUE;
    }
    //復号
    
    free(aesblob);
    free(aes_blob64);
    free(ivec);
    free(iv_blob64);
    free(data);
    free(abe_blob64);
    free(aes_result);
    //free(&input_buf);
    free(session_key);
    free(K_oct);
    element_clear(*K);
    free(K);
    if (aAS != NULL) {
        for (i = 0; i < aAS->S->row; i++) {
            mpz_clear(alpha_i[i]);
        }
        free(alpha_i);
        AccessStructure_clear(aAS);//error
    }
    element_clear(temp_0);
    mpz_clear(order);
    mpz_clear(temp);
    
    for (i = 0; i < c_i->dim; i++) { //memsetとか追加？
        free(c_i->M[i]);
    }
    free(c_i->M);
    free(c_i);
    
    Spanprogram_clear(AS->S);
    free(AS);
    
    //AccessStructure_clear(AS);//すでにAS->rhoがAccessStructure_clear(aAS)により解放されているため
    
    return 0;
}


//暗号文の分割
//abe,aes,iv部分に分ける
void tokenize_inputfile(char* in, char** abe, char** aes, char** iv)
{
    ssize_t abe_len, aes_len, iv_len;
    char delim[] = ":";
    char *token = strtok(in, delim);
    while (token != NULL) {
        if(strcmp(token, ABE_TOKEN) == 0) {
            token = strtok(NULL, delim);
            abe_len = strlen(token);
            if((*abe = (char *) malloc(abe_len+1)) != NULL) {
                strncpy(*abe, token, abe_len);
            }
        }
        else if(strcmp(token, AES_TOKEN) == 0) {
            token = strtok(NULL, delim);
            aes_len = strlen(token);
            if((*aes = (char *) malloc(aes_len+1)) != NULL) {
                strncpy(*aes, token, aes_len);
            }
        }
        else if(strcmp(token, IV_TOKEN) == 0) {
            token = strtok(NULL, delim);
            iv_len = strlen(token);
            if((*iv = (char *) malloc(iv_len+1)) != NULL) {
                strncpy(*iv, token, iv_len);
            }
        }
        token = strtok(NULL, delim);
    }
}

/*
 * AS, c_iの順にシリアライズされている
 * まずint*3(num_policy, M->row, M->column)
 * その後、行列M,rho(i)
 * 最後にc_i
 */
void tfel_deserialize_ciphertext_cp(AccessStructure *AS, basis *c_i, unsigned char *bin_ct_buf, size_t max_len, EC_PAIRING p) {
    int i, j, t;
    unsigned char *buf_ptr = NULL;
    size_t buf_len;
    size_t *result_len = NULL;
    result_len = &buf_len;
    *result_len = 0;
    buf_ptr = bin_ct_buf;
    size_t length;
    
    //引数の初期化
    init_AccessStructure(AS);
    
    //num_policy, 行列のrow,columnのdeserialize
    AS->num_policy = *((int*)buf_ptr);
    *result_len += sizeof(int);
    buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
    AS->S->row = *((int*)buf_ptr);
    *result_len += sizeof(int);
    buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
    AS->S->column = *((int*)buf_ptr);
    *result_len += sizeof(int);

    //Mのdeserialize
    char *mpz_temp;
    // 不具合あったら下の0428のコメント解除して個々の部分消す↓
    mpz_temp = (char*)malloc(sizeof(char)*MAX_STRING);
    
    AS->S->M = (mpz_t**)malloc(sizeof(mpz_t*)*AS->S->row);
    for (i = 0; i < AS->S->row; i++) {
        AS->S->M[i] = (mpz_t*)malloc(sizeof(mpz_t)*AS->S->column);
        for (j = 0; j < AS->S->column; j++) {
            buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
            memset(mpz_temp, '\0', sizeof(char)*MAX_STRING);//4はEnc.hのシリアライズの方に合わせてる
            strncpy(mpz_temp, (char*)buf_ptr, MAX_STRING); //1は変えたほうがいいかも
            mpz_init_set_str(AS->S->M[i][j], mpz_temp, 16);
            *result_len += sizeof(char)*MAX_STRING;
        }
    }
    free(mpz_temp);

    rho_i *rho_ptr;
    rho_ptr = (rho_i*)malloc(sizeof(rho_i));
    init_rho_i(rho_ptr);
    AS->rho = rho_ptr;
    for (i = 0; i < AS->num_policy; i++) { //ここの記述だるすぎでしょ……
        buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
        rho_ptr->t = *((int*)buf_ptr);
        buf_ptr += sizeof(int);
        rho_ptr->v_t[0] = *((int*)buf_ptr);
        buf_ptr += sizeof(int);
        rho_ptr->v_t[1] = *((int*)buf_ptr);
        buf_ptr += sizeof(int);
        rho_ptr->is_negated = *(Bool*)buf_ptr;
        buf_ptr += sizeof(int);
        *result_len += sizeof(int)*3 + sizeof(Bool);
        if (i < AS->num_policy -1) {
            rho_ptr->next = (rho_i*)malloc(sizeof(rho_i));
            init_rho_i(rho_ptr->next);
            rho_ptr = rho_ptr->next;
        }
    }
    rho_ptr->next = NULL;
    rho_ptr = AS->rho;
    
    //c(i)のdeserialize
    c_i->dim = AS->num_policy+1;
    c_i->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i->dim);
    for(i = 0; i < c_i->dim; i++) {
        //printf("i = %d\n", i);
        if(*(int*)result_len > max_len) {
            printf("import c(i) error\n");
            exit(1);
        }
        if(i == 0) t = 5;
        else t = 7;
        c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*t);
        for(j = 0; j < t; j++) {
            point_init(c_i->M[i][j], p->g1);
            //printf("j = %d\n", j);
            buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
            length = *(int*)buf_ptr;
            //printf("length = %zd\n", length);
            *result_len += sizeof(int);
            buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
            point_from_oct(c_i->M[i][j], buf_ptr, length);
            *result_len += length;
        }
    }
    
    return;
}


int tfel_deserialize_ciphertext_kp(attribute_set *Delta, basis *c_i, unsigned char *bin_ct_buf, size_t max_len, EC_PAIRING p) {
    int i, j, t;
    unsigned char *buf_ptr = NULL;
    size_t buf_len;
    size_t *result_len = NULL;
    result_len = &buf_len;
    *result_len = 0;
    buf_ptr = bin_ct_buf;
    size_t length;
    
    /*
     KPでやること
     Deltaの初期化→Delta->valueを作るためにDelta.numが必要なので最初にdを引き出す
     その後、Delta->valueをmallocしvalueを引き出す
     */
    //dをつくる
    v_vector *v_ptr = NULL;
    v_ptr = (v_vector*)malloc(sizeof(v_vector));
    if (v_ptr == NULL) return -1;
    Delta->value = v_ptr;
    Delta->num = *((int*)buf_ptr);
    *result_len += sizeof(int);
    //x_tを引き出す
    buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
    for (i = 0; i < Delta->num; i++) {
        init_vector(v_ptr, i);
        v_ptr->x_t[1] = *((int*)buf_ptr);
        *result_len += sizeof(int);
        buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
        v_ptr->next = (v_vector*)malloc(sizeof(v_vector));
        if (v_ptr->next == NULL) {
            clear_att_set_value(Delta->value);
            return -1;
        }
        if (i == Delta->num-1) {
            free(v_ptr->next);
            v_ptr->next = NULL;
        }
        else v_ptr = v_ptr->next;
    }
    
    //c(i)のdeserialize
    c_i->dim = Delta->num+1;
    c_i->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i->dim);
    if (c_i->M == NULL) {
        //error処理
    }
    for(i = 0; i < c_i->dim; i++) {
        //printf("i = %d\n", i);
        if(*(int*)result_len > max_len) {
            printf("import c(i) error\n");
            exit(1);
        }
        if(i == 0) t = 5;
        else t = 7;
        c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*t);
        for(j = 0; j < t; j++) {
            point_init(c_i->M[i][j], p->g1);
            //printf("j = %d\n", j);
            buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
            length = *(int*)buf_ptr;
            //printf("length = %zd\n", length);
            *result_len += sizeof(int);
            buf_ptr = (unsigned char*)(bin_ct_buf + *result_len);
            point_from_oct(c_i->M[i][j], buf_ptr, length);
            *result_len += length;
        }
    }
    
    return 0;
}



