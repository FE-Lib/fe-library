//
//  tfel_dpvs.c
//  
//
//  Created by h_ksk on 2015/12/15.
//
//
//#include <stdlib.h>

#include "tfel_dpvs.h"
#include "tfel_matrix.h"
#include "tfel_export_file.h"
#include "util.h"


#define PUBLIC_PARAMS "public_params.tfel"
#define SECRET_PARAMS "secret_params.tfel"

void tfel_gen_ob(uint32 d, tfel_vector_n *vec_n); //generate orthonormal basis
tfel_param_G *tfel_gen_bpg(); //generate bilinear pairing groups
void tfel_clear_bpg(tfel_param_G *param_G); //clear bilinear pairing group
tfel_param_V tfel_gen_dpvs(uint32 d, tfel_param_G *param_G); //generate dual pairing vector spaces
void tfel_clear_dpvs(uint32 d, tfel_vector_n *vec_n, tfel_param_V *param_V);


//from KeyGen.c
void clear_phi_t(mpz_t **phi_t, int d);
int init_phi_t(mpz_t **phi_t, int d,gmp_randstate_t s,mpz_t order);

void alocate_basis(basis *B, EC_GROUP ec);
void clear_basis(basis *B);
int init_kStar(basis *kStar, int d, tfel_param_G param_G);
void kStar_set_cp(mpz_t delta, mpz_t **phi, tfel_masterkey *masterkey, basis *kStar, attribute_set Delta);
int kStar_set_kp(tfel_masterkey *masterkey, tfel_param_G param_G, basis *kStar, AccessStructure *AS);

int c_i_set_cp(tfel_pubkey pubkey, tfel_param_G param_G, basis *c_i, Element *c_d1, AccessStructure *AS);
int c_i_set_kp(tfel_pubkey pubkey, tfel_param_G param_G, basis *c_i, Element *c_d1, attribute_set Delta);


//generate orthonormal basis
void tfel_gen_ob(uint32 d, tfel_vector_n *vec_n) {
    int t, i, j, k;
    tfel_pubkey pk;
    tfel_masterkey sk;
    unsigned char *pk_buf = NULL;
    unsigned char *sk_buf = NULL;
    tfel_param_n param_n;
    tfel_param_G *param_G;
    tfel_param_V *param_V;
    param_G = tfel_gen_bpg();
    if((param_V = (tfel_param_V*)malloc(sizeof(tfel_param_V)*d)) == NULL) {
        perror("malloc failed.");
        tfel_clear_bpg(param_G);
        exit(1);
    }
    
    Element gT, tempgT;
    element_init(gT, param_G->p->g3);
    element_init(tempgT, param_G->p->g3);
    mpz_t temp, psi, order;
    gmp_randstate_t s, r;
    mpz_init(temp);
    mpz_init(psi);
    mpz_init(order);
    
    gmp_randinit_default(s);
    mpz_set(order, *pairing_get_order(param_G->p));
    mpz_urandomm(psi, s, order);
    
    gmp_randinit_default(r);
    gmp_randseed_ui(r, (unsigned long)time(NULL));
    
    matrix *Xi, *theta;
    
    basis *B_t, *B_tStar;
    B_t = (basis*)malloc(sizeof(basis)*d);
    B_tStar = (basis*)malloc(sizeof(basis)*d);
    
    for (t = 0; t < d; t++) {
        int N_t;
        if(t == 0) N_t = 5;
        else N_t = 3 * vec_n->n[t] + 1;
        
        
        param_V[t] = tfel_gen_dpvs(N_t, param_G);
        
        
        Xi = tfel_gen_general_linear_groups(N_t, param_G->p, r); //generate general linear groups
        theta = tfel_matrix_copy(Xi);
        theta = tfel_transpose(theta);
        theta = tfel_invert(theta, param_G->p);
        
        for(i = 0; i < N_t; i++) {
            for(j = 0; j < N_t; j++) {
                mpz_mul(temp, psi, theta->M[i][j]);
                mpz_set(theta->M[i][j], temp);
            }
        }
        
        
        B_t[t] = tfel_linear_transformation(Xi, param_V[t].A, param_G->p->g1);
        B_tStar[t] = tfel_linear_transformation(theta, param_V[t].AStar, param_G->p->g2);
        
    }


    
    pairing_map(tempgT, param_G->g1, param_G->g2, param_G->p);
    element_pow(gT, tempgT, psi);
    
    memset(&pk, 0, sizeof(tfel_pubkey));
    memset(&sk, 0, sizeof(tfel_masterkey));
    memset(&param_n, 0, sizeof(tfel_param_n));
    element_init(param_n.gT, param_G->p->g3);
    element_set(param_n.gT, gT);
    
    param_n.param_V = param_V;
    
    
    //output pk
    pk.num_att = d;
    pk.param_n = param_n;
    pk.Bhat = (basis*)malloc(sizeof(basis)*d);
    for(i = 0; i < d; i++) {
        pk.Bhat[i].M = (EC_POINT**)malloc(sizeof(EC_POINT*)*3);
        for(j = 0; j < 3; j++) {
            if(i == 0) {
                pk.Bhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);
                pk.Bhat[i].dim = 5;
                for(k = 0; k < 5; k++) {
                    point_init(pk.Bhat[i].M[j][k], param_G->p->g1);
                    point_set(pk.Bhat[i].M[j][k], B_t[i].M[2*j][k]);
                }
            }
            else {
                pk.Bhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);
                pk.Bhat[i].dim = 7;
                for(k = 0; k < 7; k++) {
                    point_init(pk.Bhat[i].M[j][k], param_G->p->g1);
                    switch(j) {
                        case 0:
                            point_set(pk.Bhat[i].M[j][k], B_t[i].M[0][k]);
                            break;
                        case 1:
                            point_set(pk.Bhat[i].M[j][k], B_t[i].M[1][k]);
                            break;
                        case 2:
                            point_set(pk.Bhat[i].M[j][k], B_t[i].M[6][k]);
                            break;
                    }
                }
            }
        }
    }
    
    
    
    //output sk
    sk.BStarhat = (basis*)malloc(sizeof(basis)*d);
    for(i = 0; i < d; i++) {
        if(i == 0) t = 3;
        else t = 4;
        
        sk.BStarhat[i].M = (EC_POINT**)malloc(sizeof(EC_POINT*)*t);
        for(j = 0; j < t; j++) {
            if(i == 0) {
                sk.BStarhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);
                sk.BStarhat[i].dim = 5;
                for(k = 0; k < 5; k++) {
                    point_init(sk.BStarhat[i].M[j][k], param_G->p->g2);
                    switch(j) {
                        case 0:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[0][k]);
                            break;
                        case 1:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[2][k]);
                            break;
                        case 2:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[3][k]);
                            break;
                    }
                }
            }
            else {
                sk.BStarhat[i].M[j] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);
                sk.BStarhat[i].dim = 7;
                for(k = 0; k < 7; k++) {
                    point_init(sk.BStarhat[i].M[j][k], param_G->p->g2);
                    switch(j) {
                        case 0:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[0][k]);
                            break;
                        case 1:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[1][k]);
                            break;
                        case 2:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[4][k]);
                            break;
                        case 3:
                            point_set(sk.BStarhat[i].M[j][k], B_tStar[i].M[5][k]);
                            break;
                    }
                }
            }
        }
    }
#ifdef debag
    printf("param_G.curve = %s\n", curve_get_name(param_G->g1->ec));
    printf("param_G.curve = %s\n", curve_get_name(param_G->g2->ec));
#endif
    
    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;
    
    //export public_params
    tfel_export_public_params(NULL, 0, result_len, "%d%n%B", &(pk.num_att), &(pk.param_n), pk.Bhat);
    if((pk_buf = malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    tfel_export_public_params(pk_buf, buf_len, result_len, "%d%n%B", &(pk.num_att), &(pk.param_n), pk.Bhat);
    
    //base64 encode
    size_t publicLength;
    char *publicBuffer;
    publicBuffer = NewBase64Encode(pk_buf, buf_len, FALSE, &publicLength);
    
    FILE *fp;
    //fp = fopen("public_params.tfel", "w");
    fp = fopen(PUBLIC_PARAMS, "w");
    if (fp != NULL) {
        fprintf(fp, "%s", publicBuffer);
    }
    
    //export secret_params
    *result_len = 0;
    tfel_export_secret_params(NULL, 0, result_len, "%d%B", &(pk.num_att),  sk.BStarhat);
    if((sk_buf = malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    tfel_export_secret_params(sk_buf, buf_len, result_len, "%d%B", &(pk.num_att), sk.BStarhat);
    
    //base64 encode
    size_t secretLength;
    char *secretBuffer;
    secretBuffer = NewBase64Encode(sk_buf, buf_len, FALSE, &secretLength);
    //printf("secret_params '%s'\n", secretBuffer);
    
    
    //fp = fopen("secret_params.tfel", "w");
    fp = fopen(SECRET_PARAMS, "w");
    if (fp != NULL) {
        fprintf(fp, "%s", secretBuffer);
    }
    fclose(fp);
    
    
    
    free(secretBuffer);
    free(sk_buf);
    free(pk_buf);
    //free pk
    tfel_clear_pk(pk.num_att, &pk);
    //free sk
    tfel_clear_sk(pk.num_att, &sk);
    
    
    clear_basis(B_tStar);
    free(B_tStar);
    clear_basis(B_t);
    free(B_t);
    tfel_matrix_clear(Xi);
    tfel_matrix_clear(theta);
    mpz_clear(order);
    mpz_clear(psi);
    mpz_clear(temp);
    gmp_randclear(r);
    gmp_randclear(s);
    element_clear(tempgT);
    element_clear(gT);
    
    tfel_clear_dpvs(d, vec_n, param_V);
    tfel_clear_bpg(param_G);
    
    return;
}

//generate bilinear pairing groups
tfel_param_G *tfel_gen_bpg() {
    tfel_param_G *param_G;
    if((param_G = (tfel_param_G*)malloc(sizeof(tfel_param_G))) == NULL) {
        perror("malloc failed.");
        return NULL;
    }
    memset(param_G, 0, sizeof(tfel_param_G));
    pairing_init(param_G->p, CURVE);
    point_init(param_G->g1, param_G->p->g1);
    point_init(param_G->g2, param_G->p->g2);
    point_random(param_G->g1);
    point_random(param_G->g2);
    
    return param_G;
}

void tfel_clear_bpg(tfel_param_G *param_G) {
    point_clear(param_G->g1);
    point_clear(param_G->g2);
    pairing_clear(param_G->p);
    free(param_G);
    
    return;
}

//generate dual pairing vector spaces
tfel_param_V tfel_gen_dpvs(uint32 d, tfel_param_G *param_G) {
    int i, j;
    tfel_param_V param_V;
    pairing_init(param_V.p, CURVE);
    //param_V.A.M = (EC_POINT**)malloc(sizeof(EC_POINT*)*d);
    if((param_V.A.M = (EC_POINT**)malloc(sizeof(EC_POINT*)*d)) == NULL) {
        perror("malloc failed.");
        return;
    }
    param_V.A.dim = d;
    if((param_V.AStar.M = (EC_POINT**)malloc(sizeof(EC_POINT*)*d)) == NULL) {
        free(param_V.A.M);
        perror("malloc failed.");
        return;
    }
    
    param_V.AStar.dim = d;
    
    
    for(i = 0; i < d; i++) {
        param_V.A.M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*d);
        param_V.AStar.M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*d);
        for(j = 0; j < d; j++) {
            point_init(param_V.A.M[i][j], param_G->p->g1);
            point_init(param_V.AStar.M[i][j], param_G->p->g2);
        }
    }
    
    for(i = 0; i < d; i++) {
        for(j = 0; j < d; j++) {
            if(i == j) {
                point_set(param_V.A.M[i][j], param_G->g1);
                point_set(param_V.AStar.M[i][j], param_G->g2);
                continue;
            }
            point_set_infinity(param_V.A.M[i][j]);
            point_set_infinity(param_V.AStar.M[i][j]);
        }
    }
    
    return param_V;
}

void tfel_clear_dpvs(uint32 d, tfel_vector_n *vec_n, tfel_param_V *param_V) {
    int i, j, k;
    int N_t;
    for(i = 0; i < d; i++) {
        if (i == 0) N_t = 5;
        else N_t = 3 * vec_n->n[i] + 1;
        
        for (j = 0; j < N_t;j++) {
            for (k = 0; k < N_t; k++) {
                
                point_clear(param_V[i].AStar.M[j][k]);
                point_clear(param_V[i].A.M[j][k]);
            }
            free(param_V[i].AStar.M[j]);
            free(param_V[i].A.M[j]);
        }
        free(param_V[i].AStar.M);
        free(param_V[i].A.M);
    }
    free(param_V);
}



//clear phi_t[i]
void clear_phi_t(mpz_t **phi_t, int d) {
    int i;
    for (i = 0; i < d; i++) {
        if (i == 0) {
            mpz_clear(*phi_t[i]);
            free(phi_t[i]);
            continue;
        }
        mpz_clear(phi_t[i][0]);
        mpz_clear(phi_t[i][1]);
        free(phi_t[i]);
    }
    
    return;
}



int init_phi_t(mpz_t **phi_t, int d,gmp_randstate_t s,mpz_t order) {
    int i;
    
    if (phi_t == NULL) return -1;
    for (i = 0; i < d; i++) {
        if (i == 0) {
            phi_t[i] = (mpz_t*)malloc(sizeof(mpz_t));
            if (phi_t[i] == NULL) {
                clear_phi_t(phi_t, i);
                return -1;
            }
            gen_random(phi_t[0], s, order);
        }
        else {
            phi_t[i] = (mpz_t*)malloc(sizeof(mpz_t)*2);
            if (phi_t[i] == NULL) {
                clear_phi_t(phi_t, i);
                return -1;
            }
            gen_random(&phi_t[i][0], s, order);
            gen_random(&phi_t[i][1], s, order);
        }
    }
    return 0;
}


void alocate_basis(basis *B, EC_GROUP ec) {
    int i, j;
    if (B->dim <= 0) {
        printf("dimension error\n");
        exit(-1);
    }
    else {
        B->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*B->dim);
        for (i = 0; i < B->dim; i++) {
            B->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*B->dim);
            if (B->M[i] == NULL) {
                int h;
                printf("basis malloc error\n");
                for (h = 0; h < B->dim; h++) {
                    if (B->M[h] != NULL) free(B->M[h]);
                }
                return;
            }
            
            for (j = 0; j < B->dim; j++) {
                point_init(B->M[i][j], ec);
            }
        }
    }
    return;
}

void clear_basis(basis *B) {
    int i;
    for (i = 0; i < B->dim; i++) {
        free(B->M[i]);
    }
    free(B->M);
    return;
}


int init_kStar(basis *kStar, int d, tfel_param_G param_G) {
    int i, j, k;
    kStar->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*d);//共通
    if (kStar->M == NULL) {
        return -1;
    }
    for (i = 0; i < kStar->dim; i++) {
        if (i == 0) {
            kStar->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);
            if (kStar->M[i] == NULL) {
                free(kStar->M);
                return -1;
            }
            for (j = 0; j < 5; j++) {
                point_init(kStar->M[i][j], param_G.p->g2);
            }
        }
        else {
            kStar->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);
            if (kStar->M[i] == NULL) {
                for (j == 0; j < i; j++) {
                    int n;
                    if (j == 0) n = 5;
                    else n = 7;
                    for (k == 0; k < n; k++) {
                        point_clear(kStar->M[j][k]);
                    }
                    free(kStar->M[j]);
                }
                return -1;
            }
            for (j = 0; j < 7; j++) {
                point_init(kStar->M[i][j], param_G.p->g2);
            }
        }
    }
    
    return 0;
}


//ECBN_254以外にも対応させねば……
//公開鍵にpの情報入れたらこれの引数にpubkey追加
//属性集合Deltaを引数に入れる←おｋ
//point_initのecが違うかも、g2のカーブを入れる
//引数にparam_G入れたほうがいい→point_initにparam_G->p->g2入れる
void kStar_set_cp(mpz_t delta, mpz_t **phi, tfel_masterkey *masterkey, basis *kStar, attribute_set Delta) {
    int i, j, k;
    int d = kStar->dim;
    mpz_t temp_mpz;
    mpz_init(temp_mpz);
    EC_POINT temp1, temp2;
    EC_GROUP ec;
    //curve_init(ec, "ec_bn254_tw");
    curve_init(ec, masterkey->BStarhat->M[0][0]->ec->curve_name); //これはさすがに……
    
    v_vector *v_ptr = NULL;
    v_ptr = Delta.value;
    
    
    //研究ノートP81参照
    //masterkey.BStarhatのMは使用する分しか入ってないので注意
    for (i = 0; i < d; i++) {
        point_init(temp1, ec);
        point_init(temp2, ec);
        point_set_infinity(temp1);
        point_set_infinity(temp2); //初期化
        if (i == 0) {//t = 0
            for (j = 0; j < 5; j++) {
                for (k = 0; k < 3; k++) {
                    switch(k) {
                        case 0:
                            point_mul(temp1, delta, masterkey->BStarhat[i].M[k][j]);
                            break;
                        case 1:
                            point_add(kStar->M[i][j], temp1, masterkey->BStarhat[i].M[k][j]);
                            break;
                        case 2:
                            point_mul(temp1, phi[0][0], masterkey->BStarhat[i].M[k][j]);
                            point_add(temp2, temp1, kStar->M[i][j]);
                            point_set(kStar->M[i][j], temp2);
                            break;
                    }
                }
            }
        }
        else {
            //t \in Deltta
            if (v_ptr == NULL) { //Deltaが上手く行ってない場合
                printf("v_ptr error\n");
                exit(-1);
            }
            for (j = 0; j < 7; j++) {
                for (k = 0; k < 4; k++) {
                    switch(k) {
                        case 0:
                            point_mul(temp1, delta, masterkey->BStarhat[i].M[k][j]);
                            break;
                        case 1:
                            mpz_mul_ui(temp_mpz, delta, v_ptr->x_t[1]);
                            point_mul(kStar->M[i][j], temp_mpz, masterkey->BStarhat[i].M[k][j]);
                            point_add(temp2, kStar->M[i][j], temp1);
                            break;
                        case 2:
                            point_mul(temp1, phi[i][0], masterkey->BStarhat[i].M[k][j]);
                            point_add(kStar->M[i][j], temp1, temp2);
                            break;
                        case 3:
                            point_mul(temp1, phi[i][1], masterkey->BStarhat[i].M[k][j]);
                            point_add(temp2, temp1, kStar->M[i][j]);
                            point_set(kStar->M[i][j], temp2);
                            break;
                    }
                }
            }
            v_ptr = v_ptr->next;
        }
        point_clear(temp1);
        point_clear(temp2);
    }
    
    
    mpz_clear(temp_mpz);
    curve_clear(ec);
    
    return;
}


//KP-FE用のkeygenでのkStar生成
int kStar_set_kp(tfel_masterkey *masterkey, tfel_param_G param_G, basis *kStar, AccessStructure *AS) {
    /*
     * f←F_q^r, s^T := M・f, s_0 := 1・f, eta_0,eta_i,theta_i,xi←F_q(i = 1,...,l)
     */
    int i, j, k;
    int l, r;
    l = AS->S->row; //row of matrix
    r = AS->S->column; //column of matrix
    
    mpz_t *fv = NULL; //f←F_q^r
    mpz_t *sv = NULL; //:= (s_1,..., s_l) := M・f
    mpz_t s_0, eta_0, xi; //s_0, eta_0, xi
    mpz_t **eta_i = NULL, *theta_i = NULL; //eta_i, theta_i (i = 1,...,l)
    
    mpz_t temp1, temp2, temp3;
    
    //malloc variables
    fv = (mpz_t*)malloc(sizeof(mpz_t)*r);
    if (fv == NULL) {
        printf("fv malloc error\n");
        return -1;
    }
    sv = (mpz_t*)malloc(sizeof(mpz_t)*l);
    if (sv == NULL) {
        printf("sv malloc error\n");
        free(fv);
        return -1;
    }
    eta_i = (mpz_t**)malloc(sizeof(mpz_t*)*l);
    if (eta_i == NULL) {
        printf("eta_i malloc error\n");
        free(fv);
        free(sv);
        return -1;
    }
    for (i = 0; i < l; i++) {
        eta_i[i] = (mpz_t*)malloc(sizeof(mpz_t)*2);
    }
    
    theta_i = (mpz_t*)malloc(sizeof(mpz_t)*l);
    if (theta_i == NULL) {
        printf("eta_i malloc error\n");
        free(fv);
        free(sv);
        free(eta_i);
        return -1;
    }
    //malloc variables
    
    //init pairing
    mpz_t order;
    gmp_randstate_t s;
    mpz_init(order);
    gmp_randinit_default(s);
    gmp_randseed_ui(s, (unsigned long)time(NULL));
    mpz_set(order, *pairing_get_order(param_G.p));
    //init pairing
    
    //randomize variables (fv, eta_i, theta_i, eta_0, xi)
    for (i = 0; i < r; i++) {
        mpz_init(fv[i]);
        gen_random(&fv[i], s, order);
        //mpz_set_ui(fv[i], 1);
    }
    for (i = 0; i < l; i++) {
        mpz_init(eta_i[i][0]);
        mpz_init(eta_i[i][1]);
        mpz_init(theta_i[i]);
        gen_random(&eta_i[i][0], s, order);
        gen_random(&eta_i[i][1], s, order);
        gen_random(&theta_i[i], s, order);
        //mpz_set_ui(theta_i[i], 1); //後で消去
        //gmp_printf("theta[%d] = %Zd\n", i, theta_i[i]);
    }
    mpz_init(eta_0);
    mpz_init(xi);
    gen_random(&eta_0, s, order);
    //gen_random(&xi, s, order);
    mpz_set_ui(xi, 1);
    //gmp_printf("xi = %Zd\n", xi);
    //randomize variables
    
    //generate s_0 := f_1+...+f_r;
    mpz_init(s_0);
    mpz_init(temp1);
    mpz_init(temp2);
    for (i = 0; i < r; i++) {
        mpz_add(temp2, temp1, fv[i]);
        mpz_mod(temp1, temp2, order);
    }
    mpz_set(s_0, temp1);
    //gmp_printf("aa s_0 = %Zd\n", temp1);//debag用
    //generate s_0
    
    //generate sv := M・fv
    for (i = 0; i < l; i++) {
        mpz_init(sv[i]);
        mpz_init(temp1);
        mpz_init(temp2);
        mpz_init(temp3);
        for (j = 0; j < r; j++) {
            mpz_mul(temp1, AS->S->M[i][j], fv[j]);
            mpz_add(temp3, temp1, temp2);
            mpz_set(temp2, temp3);
        }
        mpz_mod(temp3, temp2, order);
        mpz_set(sv[i], temp3);
        //mpz_set_ui(sv[0], 1);
        //gmp_printf("sv[%d] = %Zd\n", i, sv[i]);
    }
    //generate sv := M・fv
    
    //int i, j, k;
    //int l = c_i->dim+1;
    EC_POINT tmp_p1;
    point_init(tmp_p1, param_G.p->g2);
    EC_POINT tmp_p2;
    point_init(tmp_p2, param_G.p->g2);
    
    rho_i *rho_ptr = NULL;
    rho_ptr = AS->rho;
    
    
    //KeyGen時と同様の操作、研究ノートP81参照
    for (i = 0; i < l+1; i++) {
        mpz_init(temp1);
        mpz_init(temp2);
        point_set_infinity(tmp_p1);
        point_set_infinity(tmp_p2); //初期化
        if (i == 0) {//k_0
            //gmp_printf("s_0 = %Zd\n", s_0);//debag用
            mpz_neg(temp1, s_0);
            mpz_mod(temp2, temp1, order);
            mpz_set(temp1, temp2);
            //mpz_invert(temp1, s_0, order); // -s_0
            //gmp_printf("-s_0 = %Zd\n", temp1);//debag用
            for (j = 0; j < 5; j++) {
                for (k = 0; k < 3; k++) {
                    switch(k) {
                        case 0:
                            point_mul(tmp_p1, temp1, masterkey->BStarhat[i].M[k][j]);
                            break;
                        case 1:
                            point_add(kStar->M[i][j], tmp_p1, masterkey->BStarhat[i].M[k][j]);
                            break;
                        case 2:
                            point_mul(tmp_p1, eta_0, masterkey->BStarhat[i].M[k][j]);
                            point_add(tmp_p2, tmp_p1, kStar->M[i][j]);
                            point_set(kStar->M[i][j], tmp_p2);
                            break;
                    }
                }
            }
        }
        else {
            //rho(0)~rho(l-1)
            //iは1~l
            if (rho_ptr == NULL) {
                printf("rho_ptr error\n");
                exit(-1);
            }
            /*if文でrho_i->is_negated分岐*/
            if (rho_ptr->is_negated == TRUE) { //rho(i) = ¬(t, v_i)
                mpz_mul_ui(temp1, sv[i-1], rho_ptr->v_t[0]); //s_i*v_i
                mpz_mod(temp2, temp1, order);
                mpz_set(temp1, temp2);
                mpz_neg(temp2, sv[i-1]);
                mpz_mod(sv[i-1], temp2, order);
                mpz_set(temp2, sv[i-1]);//-s_i
                //gmp_printf("-s_%d = %Zd\n", temp2);
            }
            else { //rho(i) = (t, v_i)
                //gmp_printf("-theta_i = %Zd\n", theta_i[i-1]);
                mpz_mul_ui(temp2, theta_i[i-1], rho_ptr->v_t[0]); //theta_i * v_i
                mpz_add(temp1, sv[i-1], temp2); //s_i+theta_i*v_i
                mpz_mod(temp2, temp1, order);
                mpz_set(temp1, temp2);
                mpz_neg(temp2, theta_i[i-1]);
                mpz_mod(theta_i[i-1], temp2, order);
                mpz_set(temp2, theta_i[i-1]);
            }
            /*if文でrho_i->is_negated分岐*/
            printf("t = %d\n", rho_ptr->t+1);
            for (j = 0; j < 7; j++) {
                for (k = 0; k < 4; k++) {
                    switch(k) {
                        case 0:
                            point_mul(tmp_p1, temp1, masterkey->BStarhat[rho_ptr->t+1].M[k][j]);
                            break;
                        case 1:
                            point_mul(kStar->M[i][j], temp2, masterkey->BStarhat[rho_ptr->t+1].M[k][j]);
                            point_add(tmp_p2, kStar->M[i][j], tmp_p1);
                            break;
                        case 2:
                            point_mul(tmp_p1, eta_i[i-1][0], masterkey->BStarhat[rho_ptr->t+1].M[k][j]);
                            point_add(kStar->M[i][j], tmp_p1, tmp_p2);
                            break;
                        case 3:
                            point_mul(tmp_p1, eta_i[i-1][1], masterkey->BStarhat[rho_ptr->t+1].M[k][j]);
                            point_add(tmp_p2, kStar->M[i][j], tmp_p1);
                            point_set(kStar->M[i][j], tmp_p2);
                            //point_add(kStar->M[i][j], tmp_p1, tmp_p2);
                            break;
                    }
                }
            }
            rho_ptr = rho_ptr->next;
        }
    }
    
    
    //debag
    for (i = 0; i < kStar->dim; i++) {
        int A;
        if (i == 0) {
            A = 5;
        }
        else {
            A = 7;
        }
        for (j = 0; j < A; j++) {
            printf("%d ", point_is_infinity(kStar->M[i][j]));
        }
        printf("\n");
    }
    //debag
    
    
    //sk_Sとc_iのチェック
    //#define debag2
#ifdef debug2
    printf("debag\n");
    
    //pubkey input //共通
    tfel_pubkey *pubkey = NULL;
    pubkey = (tfel_pubkey*)malloc(sizeof(tfel_pubkey));
    if (pubkey == NULL) return -1;
    //tfel_param_G *param_G;
    /*param_G = (tfel_param_G*)malloc(sizeof(tfel_param_G));
     if (param_G == NULL) {
     tfel_clear_pk(pubkey->num_att, pubkey);
     free(pubkey);
     return -1;
     }*/
    //memset(param_G, 0, sizeof(tfel_param_G));
    //pairing_init(param_G->p, CURVE);
    importpub(pubkey, param_G);
    //pubkey input
    
    
    tfel_masterkey *masterkey2;
    masterkey2 = (tfel_masterkey*)malloc(sizeof(tfel_masterkey));
    importsecret(masterkey, param_G);
    //pk,sk check
    Element egg, tempegg1, tempegg2, eggxi;
    element_init(egg, param_G.p->g3);
    element_init(tempegg1, param_G.p->g3);
    element_init(tempegg2, param_G.p->g3);
    element_init(eggxi, param_G.p->g3);
    element_set_one(egg);
    element_set_zero(tempegg2);
    mpz_t omega, tempz;
    mpz_init(omega);
    mpz_t s_0neg;
    mpz_init(s_0neg);
    mpz_init(tempz);
    
    gmp_printf("theta_i[0] = %Zd\n", theta_i[0]);
    for(i = 1;i < 6; i++) {
        //i = 1;
        element_set_one(egg);
        mpz_mul_ui(tempz, theta_i[i-1], 2);
        mpz_add(s_0neg, sv[i-1], tempz);
        mpz_mod(tempz, s_0neg, order);
        mpz_set(s_0neg, tempz);
        mpz_invert(s_0neg, theta_i[i-1], order);
        element_pow(eggxi, pubkey->param_n.gT, s_0neg);
        
        for(j = 0; j < 7; j++) {
            //pairing_map(tempegg1, kStar->M[i][j], masterkey2->BStarhat[i].M[0][j], param_G.p);
            pairing_map(tempegg1, pubkey->Bhat[i].M[0][j], kStar->M[i][j], param_G.p);
            element_mul(tempegg2, tempegg1, egg);
            element_set(egg, tempegg2);
        }
        
        element_pow(tempegg2, egg, s_0neg);
        element_pow(tempegg2, egg, xi);
        element_set(egg, tempegg2);
        printf("element_cmp(gT, egg) = %d\n", element_cmp(eggxi, egg));
        //printf("element_is_zero = %d\n", element_is_zero(egg));
    }
    
    //gT = e(b_ti, b_ti*)をチェック
    element_clear(egg);
    element_clear(tempegg1);
    element_clear(tempegg2);
    free(masterkey);
    mpz_clear(s_0neg);
    mpz_clear(tempz);
    printf("debag2 fin\n");
    //pk,sk check
#endif
    
    
    
    
    
    /*
     //generate c_(d+1) := gT^xi
     element_pow(*c_d1, pubkey.param_n.gT, xi);
     //generate c_(d+1) := gT^xi
     */
    //メモリ解放
    for (i = 0; i < r; i++) {
        mpz_clear(fv[i]);
        mpz_clear(sv[i]);
    }
    for (i = 0; i < l; i++) {
        mpz_clear(eta_i[i][0]);
        mpz_clear(eta_i[i][1]);
        mpz_clear(theta_i[i]);
    }
    mpz_clear(eta_0);
    mpz_clear(xi);
    mpz_clear(order);
    mpz_clear(s_0);
    mpz_clear(temp1);
    mpz_clear(temp2);
    mpz_clear(temp3);
    point_clear(tmp_p1);
    point_clear(tmp_p2);
    
    free(fv);
    free(sv);
    for (i = 0; i < l; i++) {
        free(eta_i[i]);
    }
    free(eta_i);
    free(theta_i);
    
    return 0;
}


//KeyGen.cのkStar_set関数をちょっと変えて利用→かなり変わっちゃったので後でkStar_setと統一させる
//c(i)を作る関数
int c_i_set_cp(tfel_pubkey pubkey, tfel_param_G param_G, basis *c_i, Element *c_d1, AccessStructure *AS) {
    /*
     * f←F_q^r, s^T := M・f, s_0 := 1・f, eta_0,eta_i,theta_i,xi←F_q(i = 1,...,l)
     */
    int i, j, k;
    int l, r;
    l = AS->S->row; //row of matrix
    r = AS->S->column; //column of matrix
    
    mpz_t *fv = NULL; //f←F_q^r
    mpz_t *sv = NULL; //:= (s_1,..., s_l) := M・f
    mpz_t s_0, eta_0, xi; //s_0, eta_0, xi
    mpz_t *eta_i = NULL, *theta_i = NULL; //eta_i, theta_i (i = 1,...,l)
    
    mpz_t temp1, temp2, temp3;
    
    //malloc variables
    fv = (mpz_t*)malloc(sizeof(mpz_t)*r);
    if (fv == NULL) {
        printf("fv malloc error\n");
        return -1;
    }
    sv = (mpz_t*)malloc(sizeof(mpz_t)*l);
    if (sv == NULL) {
        printf("sv malloc error\n");
        free(fv);
        return -1;
    }
    eta_i = (mpz_t*)malloc(sizeof(mpz_t)*l);
    if (eta_i == NULL) {
        printf("eta_i malloc error\n");
        free(fv);
        free(sv);
        return -1;
    }
    theta_i = (mpz_t*)malloc(sizeof(mpz_t)*l);
    if (eta_i == NULL) {
        printf("eta_i malloc error\n");
        free(fv);
        free(sv);
        free(eta_i);
        return -1;
    }
    //malloc variables
    
    //init pairing
    mpz_t order;
    gmp_randstate_t s;
    mpz_init(order);
    gmp_randinit_default(s);
    gmp_randseed_ui(s, (unsigned long)time(NULL));
    mpz_set(order, *pairing_get_order(param_G.p));
    //init pairing
    
    //randomize variables (fv, eta_i, theta_i, eta_0, xi)
    for (i = 0; i < r; i++) {
        mpz_init(fv[i]);
        gen_random(&fv[i], s, order);
        //mpz_set_ui(fv[i], 1);
    }
    for (i = 0; i < l; i++) {
        mpz_init(eta_i[i]);
        mpz_init(theta_i[i]);
        gen_random(&eta_i[i], s, order);
        gen_random(&theta_i[i], s, order);
        //mpz_set_ui(theta_i[i], 1); //後で消去
        //gmp_printf("theta[%d] = %Zd\n", i, theta_i[i]);
    }
    mpz_init(eta_0);
    mpz_init(xi);
    gen_random(&eta_0, s, order);
    gen_random(&xi, s, order);
    //mpz_set_ui(xi, 1);
    //gmp_printf("xi = %Zd\n", xi);
    //randomize variables
    
    //generate s_0 := f_1+...+f_r;
    mpz_init(s_0);
    mpz_init(temp1);
    mpz_init(temp2);
    for (i = 0; i < r; i++) {
        mpz_add(temp2, temp1, fv[i]);
        mpz_mod(temp1, temp2, order);
    }
    mpz_set(s_0, temp1);
    //gmp_printf("aa s_0 = %Zd\n", temp1);//debag用
    //generate s_0
    
    //generate sv := M・fv
    for (i = 0; i < l; i++) {
        mpz_init(sv[i]);
        mpz_init(temp1);
        mpz_init(temp2);
        mpz_init(temp3);
        for (j = 0; j < r; j++) {
            mpz_mul(temp1, AS->S->M[i][j], fv[j]);
            mpz_add(temp3, temp1, temp2);
            mpz_set(temp2, temp3);
        }
        mpz_mod(temp3, temp2, order);
        mpz_set(sv[i], temp3);
        //mpz_set_ui(sv[0], 1);
        //gmp_printf("sv[%d] = %Zd\n", i, sv[i]);
    }
    //generate sv := M・fv
    
    //int i, j, k;
    //int l = c_i->dim+1;
    EC_POINT tmp_p1;
    //EC_GROUP ec;
    //curve_init(ec, "ec_bn254_tw");
    //↓これはさすがに……
    
    //printf("param_G.curve = %s\n", curve_get_name(param_G.g1->ec));
    //printf("param_G.curve = %s\n", curve_get_name(param_G.g2->ec));
    //curve_init(ec, pubkey.Bhat->M[0][0]->ec->curve_name); //ec_bn254_pになってる
    point_init(tmp_p1, param_G.p->g1);
    //point_set_infinity(temp1);
    EC_POINT tmp_p2;
    point_init(tmp_p2, param_G.p->g1);
    
    rho_i *rho_ptr = NULL;
    rho_ptr = AS->rho;
    
    //KeyGen時と同様の操作、研究ノートP81参照
    for (i = 0; i < l+1; i++) {
        mpz_init(temp1);
        mpz_init(temp2);
        point_set_infinity(tmp_p1);
        point_set_infinity(tmp_p2); //初期化
        if (i == 0) {//c_0
            //gmp_printf("s_0 = %Zd\n", s_0);//debag用
            mpz_neg(temp1, s_0);
            mpz_mod(temp2, temp1, order);
            mpz_set(temp1, temp2);
            //mpz_invert(temp1, s_0, order); // -s_0
            //gmp_printf("-s_0 = %Zd\n", temp1);//debag用
            for (j = 0; j < 5; j++) {
                for (k = 0; k < 3; k++) {
                    switch(k) {
                        case 0:
                            point_mul(tmp_p1, temp1, pubkey.Bhat[i].M[k][j]);
                            break;
                        case 1:
                            /*point_mulのxi*/
                            point_mul(tmp_p2, xi, pubkey.Bhat[i].M[k][j]);
                            point_add(c_i->M[i][j], tmp_p1, tmp_p2);
                            break;
                        case 2:
                            point_mul(tmp_p1, eta_0, pubkey.Bhat[i].M[k][j]);
                            point_add(tmp_p2, tmp_p1, c_i->M[i][j]);
                            point_set(c_i->M[i][j], tmp_p2);
                            break;
                    }
                }
            }
        }
        else {
            //rho(0)~rho(l-1)
            //iは1~l
            if (rho_ptr == NULL) {
                printf("rho_ptr error\n");
                exit(-1);
            }
            /*if文でrho_i->is_negated分岐*/
            if (rho_ptr->is_negated == TRUE) { //rho(i) = ¬(t, v_i)
                mpz_mul_ui(temp1, sv[i-1], rho_ptr->v_t[0]); //s_i*v_i
                mpz_mod(temp2, temp1, order);
                mpz_set(temp1, temp2);
                mpz_neg(temp2, sv[i-1]);
                mpz_mod(sv[i-1], temp2, order);
                mpz_set(temp2, sv[i-1]);//-s_i
                //gmp_printf("-s_%d = %Zd\n", temp2);
            }
            else { //rho(i) = (t, v_i)
                //gmp_printf("-theta_i = %Zd\n", theta_i[i-1]);
                mpz_mul_ui(temp2, theta_i[i-1], rho_ptr->v_t[0]); //theta_i * v_i
                mpz_add(temp1, sv[i-1], temp2); //s_i+theta_i*v_i
                mpz_mod(temp2, temp1, order);
                mpz_set(temp1, temp2);
                mpz_neg(temp2, theta_i[i-1]);
                mpz_mod(theta_i[i-1], temp2, order);
                mpz_set(temp2, theta_i[i-1]);
            }
            /*if文でrho_i->is_negated分岐*/
            for (j = 0; j < 7; j++) {
                for (k = 0; k < 3; k++) {
                    switch(k) {
                        case 0://エラーになったら一旦rho_ptr->t+1からiへ戻す
                            //point_mul(tmp_p1, temp1, pubkey.Bhat[i].M[k][j]);
                            point_mul(tmp_p1, temp1, pubkey.Bhat[rho_ptr->t+1].M[k][j]);
                            break;
                        case 1:
                            //point_mul(c_i->M[i][j], temp2, pubkey.Bhat[i].M[k][j]);
                            point_mul(c_i->M[i][j], temp2, pubkey.Bhat[rho_ptr->t+1].M[k][j]);
                            point_add(tmp_p2, c_i->M[i][j], tmp_p1);
                            break;
                        case 2:
                            //point_mul(tmp_p1, eta_i[i-1], pubkey.Bhat[i].M[k][j]);
                            point_mul(tmp_p1, eta_i[i-1], pubkey.Bhat[rho_ptr->t+1].M[k][j]);
                            point_add(c_i->M[i][j], tmp_p1, tmp_p2);
                            break;
                    }
                }
            }
            rho_ptr = rho_ptr->next;
        }
    }
    
    
    //sk_Gammaとc_iのチェック
    //#define debag2
#ifdef debag2
    printf("debag");
    tfel_masterkey *masterkey;
    masterkey = (tfel_masterkey*)malloc(sizeof(tfel_masterkey));
    importsecret(masterkey, param_G);
    //pk,sk check
    Element egg, tempegg1, tempegg2, eggxi;
    element_init(egg, param_G.p->g3);
    element_init(tempegg1, param_G.p->g3);
    element_init(tempegg2, param_G.p->g3);
    element_init(eggxi, param_G.p->g3);
    element_set_one(egg);
    element_set_zero(tempegg2);
    mpz_t s_0neg, tempz;
    mpz_init(s_0neg);
    mpz_init(tempz);
    //mpz_invert(s_0neg, theta_i[0], order);
    //mpz_add(s_0neg, sv[0], theta_i[0]);
    //element_pow(eggxi, pubkey.param_n.gT, sv[0]);
    //element_pow(eggxi, pubkey.param_n.gT, s_0neg);
    //element_set(eggxi, pubkey.param_n.gT);
    gmp_printf("theta_i[0] = %Zd\n", theta_i[0]);
    for(int i = 1;i < 6; i++) {
        //i = 1;
        element_set_one(egg);
        mpz_mul_ui(tempz, theta_i[i-1], 2);
        mpz_add(s_0neg, sv[i-1], tempz);
        mpz_mod(tempz, s_0neg, order);
        mpz_set(s_0neg, tempz);
        //mpz_invert(s_0neg, theta_i[i-1], order);
        element_pow(eggxi, pubkey.param_n.gT, s_0neg);
        for(int j = 0; j < 7; j++) {
            pairing_map(tempegg1, c_i->M[i][j], masterkey->BStarhat[i].M[0][j], param_G.p);
            element_mul(tempegg2, tempegg1, egg);
            element_set(egg, tempegg2);
        }
        //element_pow(tempegg2, egg, s_0neg);
        //element_pow(tempegg2, egg, xi);
        //element_set(egg, tempegg2);
        printf("element_cmp(gT, egg) = %d\n", element_cmp(eggxi, egg));
        //printf("element_is_zero = %d\n", element_is_zero(egg));
    }
    
    //gT = e(b_ti, b_ti*)をチェック
    element_clear(egg);
    element_clear(tempegg1);
    element_clear(tempegg2);
    free(masterkey);
    mpz_clear(s_0neg);
    mpz_clear(tempz);
    printf("debag2 fin\n");
    //pk,sk check
#endif
    
    
    
    
    
    
    //generate c_(d+1) := gT^xi
    element_pow(*c_d1, pubkey.param_n.gT, xi);
    //generate c_(d+1) := gT^xi
    
    //メモリ解放
    for (i = 0; i < r; i++) {
        mpz_clear(fv[i]);
        mpz_clear(sv[i]);
    }
    for (i = 0; i < l; i++) {
        mpz_clear(eta_i[i]);
        mpz_clear(theta_i[i]);
    }
    mpz_clear(eta_0);
    mpz_clear(xi);
    mpz_clear(order);
    mpz_clear(s_0);
    mpz_clear(temp1);
    mpz_clear(temp2);
    mpz_clear(temp3);
    point_clear(tmp_p1);
    point_clear(tmp_p2);
    
    free(fv);
    free(sv);
    free(eta_i);
    free(theta_i);
    
    return 0;
}


//c(i)を作る関数
//KP-FE
int c_i_set_kp(tfel_pubkey pubkey, tfel_param_G param_G, basis *c_i, Element *c_d1, attribute_set Delta) {
    /*
     * f←F_q^r, s^T := M・f, s_0 := 1・f, eta_0,eta_i,theta_i,xi←F_q(i = 1,...,l)
     */
    
    int i, j, k;
    int d = c_i->dim;
    mpz_t temp_mpz;
    mpz_init(temp_mpz);
    EC_POINT temp1, temp2;
    mpz_t omega;
    mpz_init(omega);
    mpz_t xi;
    mpz_init(xi);
    mpz_t *phi_t = NULL;
    phi_t = (mpz_t*)malloc(sizeof(mpz_t)*d);
    if (phi_t == NULL) {
        mpz_clear(xi);
        mpz_clear(omega);
        mpz_clear(temp_mpz);
        return -1;
    }
    
    gmp_randstate_t s;
    gmp_randinit_default(s);
    gmp_randseed_ui(s, (unsigned long)time(NULL));
    mpz_t order;
    mpz_init(order);
    mpz_set(order, *pairing_get_order(param_G.p));
    gen_random(&omega, s, order);
    gen_random(&xi, s, order);
    for (i = 0; i < d; i++) {
        gen_random(&phi_t[i], s, order);
    }
    
    v_vector *v_ptr = NULL;
    v_ptr = Delta.value;
    
    //KeyGen時と同様の操作、研究ノートP81参照
    //init c_i
    point_init(temp1, param_G.p->g1);
    point_init(temp2, param_G.p->g1);
    point_set_infinity(temp1);
    point_set_infinity(temp2);
    for (j = 0; j < 5; j++) {//c_0 gen
        for (k = 0; k < 3; k++) {
            switch(k) {
                case 0:
                    point_mul(temp1, omega, pubkey.Bhat[0].M[k][j]);
                    break;
                case 1:
                    point_mul(temp2, xi, pubkey.Bhat[0].M[k][j]);
                    point_add(c_i->M[0][j], temp1, temp2);
                    break;
                case 2:
                    point_mul(temp1, phi_t[0], pubkey.Bhat[0].M[k][j]);
                    point_add(temp2, temp1, c_i->M[0][j]);
                    point_set(c_i->M[0][j], temp2);
                    break;
            }
        }
    }
    
    while (v_ptr != NULL) {//c_t gen
        point_set_infinity(temp1);
        point_set_infinity(temp2);
        i = v_ptr->t + 1;
        
        if (v_ptr->x_t[1] == 0) {
            for (j = 0; j < 7; j++) {
                for (k = 0; k < 4; k++) {
                    point_set_infinity(c_i->M[i][j]);
                }
            }
        }
        else {
            for (j = 0; j < 7; j++) {
                for (k = 0; k < 4; k++) {
                    switch(k) {
                        case 0:
                            point_mul(temp1, omega, pubkey.Bhat[i].M[k][j]);
                            break;
                        case 1:
                            mpz_mul_ui(temp_mpz, omega, v_ptr->x_t[1]);
                            point_mul(c_i->M[i][j], temp_mpz, pubkey.Bhat[i].M[k][j]);
                            point_add(temp2, c_i->M[i][j], temp1);
                            break;
                        case 2:
                            point_mul(temp1, phi_t[i], pubkey.Bhat[i].M[k][j]);
                            point_add(c_i->M[i][j], temp1, temp2);
                            break;
                    }
                }
            }
        }
        
        v_ptr = v_ptr->next;
    }
    
    
    /*
     for (j = 0; j < 5; j++) {
     for (k = 0; k < 3; k++) {
     switch(k) {
     case 0:
     point_mul(temp1, omega, pubkey.Bhat[i].M[k][j]);
     break;
     case 1:
     point_mul(temp2, xi, pubkey.Bhat[i].M[k][j]);
     point_add(c_i->M[i][j], temp1, temp2);
     break;
     case 2:
     point_mul(temp1, phi_t[i], pubkey.Bhat[i].M[k][j]);
     point_add(temp2, temp1, c_i->M[i][j]);
     point_set(c_i->M[i][j], temp2);
     break;
     }
     }
     }
     while (v_ptr != NULL) {
     i = v_ptr->t;
     for (j = 0; j < 7; j++) {
     for (k = 0; k < 4; k++) {
     switch(k) {
     case 0:
     point_mul(temp1, omega, pubkey.Bhat[i].M[k][j]);
     break;
     case 1:
     mpz_mul_ui(temp_mpz, omega, v_ptr->x_t[1]);
     point_mul(c_i->M[i][j], temp_mpz, pubkey.Bhat[i].M[k][j]);
     point_add(temp2, c_i->M[i][j], temp1);
     break;
     case 2:
     point_mul(temp1, phi_t[i], pubkey.Bhat[i].M[k][j]);
     point_add(c_i->M[i][j], temp1, temp2);
     break;
     }
     }
     }
     if (v_ptr->next != NULL) v_ptr = v_ptr->next;
     }
     
     for (i = 0; i < d-1; i++) {//なぜd-1なのか……
     point_init(temp1, param_G.p->g1);
     point_init(temp2, param_G.p->g1);
     point_set_infinity(temp1);
     point_set_infinity(temp2);
     if (i == 0) {//t = 0
     for (j = 0; j < 5; j++) {
     for (k = 0; k < 3; k++) {
     switch(k) {
     case 0:
     point_mul(temp1, omega, pubkey.Bhat[i].M[k][j]);
     break;
     case 1:
     point_mul(temp2, xi, pubkey.Bhat[i].M[k][j]);
     point_add(c_i->M[i][j], temp1, temp2);
     break;
     case 2:
     point_mul(temp1, phi_t[i], pubkey.Bhat[i].M[k][j]);
     point_add(temp2, temp1, c_i->M[i][j]);
     point_set(c_i->M[i][j], temp2);
     break;
     }
     }
     }
     }
     else {
     if (v_ptr == NULL) { //Deltaが上手く行ってない場合
     printf("v_ptr error\n");
     exit(-1);
     }
     else if (v_ptr->t == i) {//t \in Deltta
     for (j = 0; j < 7; j++) {
     for (k = 0; k < 4; k++) {
     switch(k) {
     case 0:
     point_mul(temp1, omega, pubkey.Bhat[i].M[k][j]);
     break;
     case 1:
     mpz_mul_ui(temp_mpz, omega, v_ptr->x_t[1]);
     point_mul(c_i->M[i][j], temp_mpz, pubkey.Bhat[i].M[k][j]);
     point_add(temp2, c_i->M[i][j], temp1);
     break;
     case 2:
     point_mul(temp1, phi_t[i], pubkey.Bhat[i].M[k][j]);
     point_add(c_i->M[i][j], temp1, temp2);
     break;
     }
     }
     }
     if (v_ptr->next != NULL) v_ptr = v_ptr->next;
     }
     else {//t not in Delta
     for (j = 0; j < 7; j++) {
     for (k = 0; k < 4; k++) {
     point_set_infinity(c_i->M[i][j]);
     }
     }
     }
     
     }
     point_clear(temp1);
     point_clear(temp2);
     }
     */
    mpz_clear(temp_mpz);
    //curve_clear(ec);
    
    
    //sk_Gammaとc_iのチェック
    //#define debag2
#ifdef debag2
    printf("debag");
    tfel_masterkey *masterkey;
    masterkey = (tfel_masterkey*)malloc(sizeof(tfel_masterkey));
    importsecret(masterkey, param_G);
    //pk,sk check
    Element egg, tempegg1, tempegg2, eggxi;
    element_init(egg, param_G.p->g3);
    element_init(tempegg1, param_G.p->g3);
    element_init(tempegg2, param_G.p->g3);
    element_init(eggxi, param_G.p->g3);
    element_set_one(egg);
    element_set_zero(tempegg2);
    mpz_t s_0neg, tempz;
    mpz_init(s_0neg);
    mpz_init(tempz);
    //mpz_invert(s_0neg, theta_i[0], order);
    //mpz_add(s_0neg, sv[0], theta_i[0]);
    //element_pow(eggxi, pubkey.param_n.gT, sv[0]);
    //element_pow(eggxi, pubkey.param_n.gT, s_0neg);
    //element_set(eggxi, pubkey.param_n.gT);
    gmp_printf("theta_i[0] = %Zd\n", theta_i[0]);
    for(i = 1;i < 6; i++) {
        //i = 1;
        element_set_one(egg);
        mpz_mul_ui(tempz, theta_i[i-1], 2);
        mpz_add(s_0neg, sv[i-1], tempz);
        mpz_mod(tempz, s_0neg, order);
        mpz_set(s_0neg, tempz);
        //mpz_invert(s_0neg, theta_i[i-1], order);
        element_pow(eggxi, pubkey.param_n.gT, s_0neg);
        for(j = 0; j < 7; j++) {
            pairing_map(tempegg1, c_i->M[i][j], masterkey->BStarhat[i].M[0][j], param_G.p);
            element_mul(tempegg2, tempegg1, egg);
            element_set(egg, tempegg2);
        }
        //element_pow(tempegg2, egg, s_0neg);
        //element_pow(tempegg2, egg, xi);
        //element_set(egg, tempegg2);
        printf("element_cmp(gT, egg) = %d\n", element_cmp(eggxi, egg));
        //printf("element_is_zero = %d\n", element_is_zero(egg));
    }
    
    //gT = e(b_ti, b_ti*)をチェック
    element_clear(egg);
    element_clear(tempegg1);
    element_clear(tempegg2);
    free(masterkey);
    mpz_clear(s_0neg);
    mpz_clear(tempz);
    printf("debag2 fin\n");
    //pk,sk check
#endif
    
    
    
    
    //generate c_(d+1) := gT^xi
    element_pow(*c_d1, pubkey.param_n.gT, xi);
    //generate c_(d+1) := gT^xi
    
    
    mpz_clear(order);
    gmp_randclear(s);
    for (i = 0; i < d; i++) {
        mpz_clear(phi_t[i]);
    }
    free(phi_t);
    mpz_clear(xi);
    mpz_clear(omega);
    
    
    return 0;
}
