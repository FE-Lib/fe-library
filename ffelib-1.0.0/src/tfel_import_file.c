/*
 * import_file.c
 *
 *  Created on: 2014/07/21
 *      Author: h_ksk
 */


#include "tfel_matrix.h"
#include "base64.h"
#include "tfel_spanprogram.h"
#include "tfelib.h"
#include "tfel_attribute.h"

#define MAX_LEN 300000



void init_publickey(tfel_pubkey *pk, int num_att, EC_PAIRING p);
size_t open_publickey(unsigned char* public_params_buf);
void import_publickey(tfel_pubkey *pk, unsigned char *bin_public_buf, int *num_att, size_t max_len);
void init_masterkey(tfel_masterkey *mk, int num_att, EC_PAIRING p);
size_t open_masterkey(unsigned char* secret_params_buf);
void import_masterkey(tfel_masterkey *mk, unsigned char *bin_secret_buf, int *num_att, size_t max_len);
void importpub(tfel_pubkey *pk, tfel_param_G param_G);
void importsecret(tfel_masterkey *mk, tfel_param_G param_G);
size_t open_sk(unsigned char* sk_buf, char *keyname);
void init_secretkey(basis *kStar, int num_att, EC_PAIRING p);
void import_secretkey(attribute_set *Delta, basis *kStar, unsigned char *bin_sk_buf, size_t max_len, tfel_param_G param_G);
void import_sk(attribute_set *Delta, basis *kStar, tfel_param_G param_G, char *keyname);
void import_sk_S(AccessStructure *AS, basis *kStar, tfel_param_G param_G, char *keyname);
void buf_to_sk_S(AccessStructure *AS, basis *kStar, unsigned char *bin_sk_buf, size_t max_len, tfel_param_G param_G);


void init_publickey(tfel_pubkey *pk, int num_att, EC_PAIRING p) {
    int i, j, k;
	pk->num_att = num_att;
	pk->Bhat = (basis*)malloc(sizeof(basis)*num_att);
	element_init(pk->param_n.gT, p->g3);
	for(i = 0; i < num_att; i++) {

		pk->Bhat[i].M = (EC_POINT**)malloc(sizeof(EC_POINT*)*3);
		for(j = 0; j < 3; j++) {
			if(i == 0) {
				pk->Bhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);
				pk->Bhat[i].dim = 5;
				for(k = 0; k < 5; k++) {
					point_init(pk->Bhat[i].M[j][k], p->g1);
				}
			}
			else {
				pk->Bhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);
				pk->Bhat[i].dim = 7;
				for(k = 0; k < 7; k++) {
				point_init(pk->Bhat[i].M[j][k], p->g1);
				}
			}
		}
	}

	return;
}

size_t open_publickey(unsigned char* public_params_buf) {
	char c;
	size_t public_len = 0;
	FILE *fp;
	fp = fopen(PUBLIC_FILE"."EXTENSION, "r");
	if (fp != NULL) {
		while (1) {
			c = fgetc(fp);
			if (c != EOF) {
				public_params_buf[public_len] = c;
				public_len++;
			}
			else {
				public_params_buf[public_len] = '\0';
				break;
			}
		}
	}

	fclose(fp);
	return public_len;
}

//引数にEC_PAIRING pを追加
void import_publickey(tfel_pubkey *pk, unsigned char *bin_public_buf, int *num_att, size_t max_len) {//, tfel_pubkey pubk) {
    int i, j, k;
	unsigned char *buf_ptr;
	size_t buf_len;
	size_t *result_len;
	result_len = &buf_len;
	*result_len = 0;
	buf_ptr = bin_public_buf;

	*num_att = *((int*)buf_ptr);
	*result_len += sizeof(int);

	size_t length;

	buf_ptr = (unsigned char*)(bin_public_buf + *result_len);
	int el_length = *(int*)buf_ptr;
	*result_len += sizeof(el_length);
	buf_ptr = (unsigned char*)(bin_public_buf + *result_len);

	Element gT;
	//element_init(gT, pubk.param_n.param_V->p->g3); //error　param_Vをエクスポートしてない そのままECBN254使う
	EC_PAIRING p_temp;					//
	pairing_init(p_temp, CURVE);	// あとでちゃんとエクスポートしたやつからとってくるようにする
	element_init(gT, p_temp->g3);		//
	element_from_oct(gT, buf_ptr, (size_t)el_length);
	/*printf("reconstructed ");
	element_printf(gT);*/
	*result_len += el_length;
	element_set(pk->param_n.gT, gT);

	//element_clear(gT);//なぜクリア
	buf_ptr = (unsigned char*)(bin_public_buf + *result_len);
	//%B入れたら解除
	for(i = 0; i < *num_att; i++) {
		if(*(int*)result_len > max_len) {
			printf("import publickey error\n");
			exit(1);
		}

		for(j = 0; j < 3; j++) {
			if(i == 0) {
				for(k = 0; k < 5; k++) {
					buf_ptr = (unsigned char*)(bin_public_buf + *result_len);
					length = *(int*)buf_ptr;
					*result_len += sizeof(int);
					buf_ptr = (unsigned char*)(bin_public_buf + *result_len);
					point_from_oct(pk->Bhat[i].M[j][k], buf_ptr, length);
					*result_len += length;
				}
			}
			else {
				for(k = 0; k < 7; k++) {
					buf_ptr = (unsigned char*)(bin_public_buf + *result_len);
					length = *(int*)buf_ptr;
					*result_len += sizeof(int);
					buf_ptr = (unsigned char*)(bin_public_buf + *result_len);
					point_from_oct(pk->Bhat[i].M[j][k], buf_ptr, length);
					*result_len += length;
				}
			}
		}
	}
	return;
}

void init_masterkey(tfel_masterkey *mk, int num_att, EC_PAIRING p) {
    int i, j, k;
	int t;
	mk->BStarhat = (basis*)malloc(sizeof(basis)*num_att);
	for(i = 0; i < num_att; i++) {
		if(i == 0) t = 3;
		else t = 4;

		mk->BStarhat[i].M = (EC_POINT**)malloc(sizeof(EC_POINT*)*t);
		for(j = 0; j < t; j++) {
			if(i == 0) {
				mk->BStarhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);
				mk->BStarhat[i].dim = 5;
				for(k = 0; k < 5; k++) {
					point_init(mk->BStarhat[i].M[j][k], p->g2);
				}
			}
			else {
				mk->BStarhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);
				mk->BStarhat[i].dim = 7;
				for(k = 0; k < 7; k++) {
				point_init(mk->BStarhat[i].M[j][k], p->g2);
				}
			}
		}
	}
	return;
}

size_t open_masterkey(unsigned char* secret_params_buf) {
	char c;
	size_t secret_len = 0;
	FILE *fp;
	fp = fopen(SECRET_FILE"."EXTENSION, "r");
	if (fp != NULL) {
		while (1) {
			c = fgetc(fp);
			if (c != EOF) {
				secret_params_buf[secret_len] = c;
				secret_len++;
			}
			else {
				secret_params_buf[secret_len] = '\0';
				break;
			}
		}
	}
	fclose(fp);
	return secret_len;
}

void import_masterkey(tfel_masterkey *mk, unsigned char *bin_secret_buf, int *num_att, size_t max_len) {
    int i, j, k;
	unsigned char *buf_ptr;
	size_t buf_len;
	size_t *result_len;
	result_len = &buf_len;
	*result_len = 0;
	buf_ptr = bin_secret_buf;

	*num_att = *((int*)buf_ptr);
	*result_len += sizeof(int);

	int t;
	size_t length;

	for(i = 0; i < *num_att; i++) {
		if(*(int*)result_len > max_len) {
			printf("import masterkey error\n");
			exit(1);
		}
		if(i == 0) t = 3;
		else t = 4;
		for(j = 0; j < t; j++) {
			if(i == 0) {
				for(k = 0; k < 5; k++) {
					buf_ptr = (unsigned char*)(bin_secret_buf + *result_len);
					length = *(int*)buf_ptr;
					*result_len += sizeof(int);
					buf_ptr = (unsigned char*)(bin_secret_buf + *result_len);
					point_from_oct(mk->BStarhat[i].M[j][k], buf_ptr, length);
					*result_len += length;
				}
			}
			else {
				for(k = 0; k < 7; k++) {
					buf_ptr = (unsigned char*)(bin_secret_buf + *result_len);
					length = *(int*)buf_ptr;
					*result_len += sizeof(int);
					buf_ptr = (unsigned char*)(bin_secret_buf + *result_len);
					point_from_oct(mk->BStarhat[i].M[j][k], buf_ptr, length);
					*result_len += length;
				}
			}
		}
	}
	return;
}

void importpub(tfel_pubkey *pk, tfel_param_G param_G) {
	//tfel_pubkey pk;
	unsigned char public_params_buf[MAX_LEN];
	size_t serialized_len = 0;
	size_t public_len = 0;
	//file open
	public_len = open_publickey(public_params_buf);

	//base64 decode
	unsigned char *bin_public_buf = NewBase64Decode((const char*)public_params_buf, public_len, &serialized_len);

	int num_att = 0;
	unsigned char *buf_ptr;
	size_t buf_len;
	size_t *result_len;
	result_len = &buf_len;
	*result_len = 0;

	buf_ptr = bin_public_buf;

	num_att = *((int*)buf_ptr);
	*result_len += sizeof(int);

	//Bhatの初期化
	init_publickey(pk, num_att, param_G.p);

	//public_key import
	import_publickey(pk, bin_public_buf, &num_att, public_len);//, pubk);

	return;

}

void importsecret(tfel_masterkey *mk, tfel_param_G param_G) {
	//tfel_masterkey mk;
	unsigned char secret_params_buf[300000];
	size_t serialized_len = 0;
	size_t secret_len = 0;

	//file open
	secret_len = open_masterkey(secret_params_buf);

	//base64 decode
	unsigned char *bin_secret_buf = NewBase64Decode((const char*)secret_params_buf, secret_len, &serialized_len);

	int num_att = 0;
	unsigned char *buf_ptr;
	size_t buf_len;
	size_t *result_len;
	result_len = &buf_len;
	*result_len = 0;

	buf_ptr = bin_secret_buf;

	num_att = *((int*)buf_ptr);
	*result_len += sizeof(int);


	//BStarhatの初期化
	init_masterkey(mk, num_att, param_G.p);

	//secret_key import
	import_masterkey(mk, bin_secret_buf, &num_att, secret_len);


	return;
}

size_t open_sk(unsigned char* sk_buf, char *keyname) {
	char c;
	size_t sk_len = 0;
	FILE *fp;
	fp = fopen(keyname, "r");
    if (fp != NULL) {
		while (1) {
			c = fgetc(fp);
			if (c != EOF) {
				sk_buf[sk_len] = c;
				sk_len++;
			}
			else {
				sk_buf[sk_len] = '\0';
				break;
			}
		}
	}
	fclose(fp);
	return sk_len;
}

void init_secretkey(basis *kStar, int num_att, EC_PAIRING p) {
    int i, j;
	int t;
	//kStar = (basis*)malloc(sizeof(basis));
	kStar->dim = num_att;
	kStar->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*num_att);

	for(i = 0; i < num_att; i++) {
		if(i == 0) t = 5;
		else t = 7;

		kStar->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*t);
		for(j = 0; j < t; j++) {
			point_init(kStar->M[i][j], p->g2);
		}
	}

	return;
}

void import_secretkey(attribute_set *Delta, basis *kStar, unsigned char *bin_sk_buf, size_t max_len, tfel_param_G param_G) {
    int i, j;
    unsigned char *buf_ptr;
	size_t buf_len;
	size_t *result_len;
	result_len = &buf_len;
	*result_len = 0;
	buf_ptr = bin_sk_buf;

	Delta->num = *((int*)buf_ptr);
	*result_len += sizeof(int);

	v_vector* vector_ptr;
	Delta->value = (v_vector*)malloc(sizeof(v_vector));
	vector_ptr = Delta->value;

	for (i = 0; i < Delta->num; i++) {
		if(i != 0) {
			vector_ptr->next = (v_vector*)malloc(sizeof(v_vector));
			vector_ptr = vector_ptr->next;
		}
		buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
		init_vector(vector_ptr, i);
		vector_ptr->x_t[1] = *((int*)buf_ptr);
		*result_len += sizeof(int);
		//vector_ptr->next = (v_vector*)malloc(sizeof(v_vector));
		//vector_ptr = vector_ptr->next;
	}
	printf("buf = %d\n", *((int*)result_len));

	int t;
	size_t length;

	//init kStar, Delta
	init_secretkey(kStar, Delta->num, param_G.p);


	for(i = 0; i < Delta->num; i++) {
		if(*(int*)result_len > max_len) {
			printf("import secretkey error 1\n");
			exit(1);
		}
		if(i == 0) t = 5;
		else t = 7;
		for(j = 0; j < t; j++) {
			buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
			length = *(int*)buf_ptr;
			*result_len += sizeof(int);
			buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
			point_from_oct(kStar->M[i][j], buf_ptr, length);
			*result_len += length;
		}
	}

	return;
}

void import_sk(attribute_set *Delta, basis *kStar, tfel_param_G param_G, char *keyname) {
	unsigned char sk_buf[300000];
	size_t serialized_len = 0;
	size_t sk_len = 0;

	//file open
	sk_len = open_sk(sk_buf, keyname);

	//base64 decode
	unsigned char *bin_sk_buf = NewBase64Decode((const char*)sk_buf, sk_len, &serialized_len);

	unsigned char *buf_ptr;
	size_t buf_len;
	size_t *result_len;
	result_len = &buf_len;
	*result_len = 0;

	buf_ptr = bin_sk_buf;


	//BStarhatの初期化
	//kStar = (basis*)malloc(sizeof(basis)*Delta->num);
	//init_secretkey(kStar, Delta->num, param_G.p);


	//secret_key import
	import_secretkey(Delta, kStar, bin_sk_buf, sk_len, param_G);
	printf("import_secretkey end\n");


	return;
}

void import_sk_S(AccessStructure *AS, basis *kStar, tfel_param_G param_G, char *keyname) {
    unsigned char sk_buf[300000];
    size_t serialized_len = 0;
    size_t sk_len = 0;
    
    //file open
    sk_len = open_sk(sk_buf, keyname);

    //base64 decode
    unsigned char *bin_sk_buf = NewBase64Decode((const char*)sk_buf, sk_len, &serialized_len);
    
    unsigned char *buf_ptr;
    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;
    
    buf_ptr = bin_sk_buf;
    
    init_AccessStructure(AS);
    
    
    //secret_key import
    buf_to_sk_S(AS, kStar, bin_sk_buf, sk_len, param_G);
    printf("import_secretkey end\n");
    
    
    return;
}

void buf_to_sk_S(AccessStructure *AS, basis *kStar, unsigned char *bin_sk_buf, size_t max_len, tfel_param_G param_G) {
    int i, j;
    unsigned char *buf_ptr = NULL;
    size_t buf_len;
    size_t *result_len = NULL;
    result_len = &buf_len;
    *result_len = 0;
    buf_ptr = bin_sk_buf;

    AS->num_policy = *((int*)buf_ptr);
    *result_len += sizeof(int);
    buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
    AS->S->row = *((int*)buf_ptr);
    *result_len += sizeof(int);
    buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
    AS->S->column = *((int*)buf_ptr);
    *result_len += sizeof(int);
    
    //Mのdeserialize
    char *mpz_temp = NULL;
    mpz_temp = (char*)malloc(sizeof(char)*MAX_STRING);
    
    AS->S->M = (mpz_t**)malloc(sizeof(mpz_t*)*AS->S->row);
    for (i = 0; i < AS->S->row; i++) {
        AS->S->M[i] = (mpz_t*)malloc(sizeof(mpz_t)*AS->S->column);
        for (j = 0; j < AS->S->column; j++) {
            buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
            memset(mpz_temp, '\0', sizeof(char)*MAX_STRING);
            strncpy(mpz_temp, (char*)buf_ptr, MAX_STRING);
            mpz_init_set_str(AS->S->M[i][j], mpz_temp, 16);
            *result_len += sizeof(char)*MAX_STRING;
        }
    }
    free(mpz_temp);
    
    rho_i *rho_ptr = NULL;
    rho_ptr = (rho_i*)malloc(sizeof(rho_i));
    init_rho_i(rho_ptr);
    AS->rho = rho_ptr;
    for (i = 0; i < AS->num_policy; i++) { //ここの記述だるすぎでしょ……
        buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
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
    
    
    //printf("buf = %d\n", *((int*)result_len));
    
    int t;
    size_t length;
    
    //init kStar, Delta
    init_secretkey(kStar, AS->num_policy+1, param_G.p);//+1しなくていい？
    
    
    for(i = 0; i < AS->num_policy+1; i++) {
        if(*(int*)result_len > max_len) {
            printf("import secretkey error\n");
            exit(1);
        }
        if(i == 0) t = 5;
        else t = 7;
        for(j = 0; j < t; j++) {
            buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
            length = *(int*)buf_ptr;
            *result_len += sizeof(int);
            buf_ptr = (unsigned char*)(bin_sk_buf + *result_len);
            point_from_oct(kStar->M[i][j], buf_ptr, length);
            *result_len += length;
        }
    }
    
    return;
}
