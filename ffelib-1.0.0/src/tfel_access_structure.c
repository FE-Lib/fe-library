//
//  tfel_access_structure.c
//  
//
//  Created by h_ksk on 2015/12/16.
//
//

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "policy.h"
#include "csv_converter.h"
#include "tfel_spanprogram.h"

#include "tfel_access_structure.h"
#include "tfel_dpvs.h"
//#include "tfelib.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "sha1.h"
#include "util.h"







//from Enc.c
void init_rho_i(rho_i* rho);
void init_AccessStructure(AccessStructure* AS);
void AccessStructure_clear(AccessStructure* AS);
void print_policy(policy_attribute_list *policy);
int attribute_check(attribute_list *att_list, policy_attribute *policy_att, rho_i *rho);
void rho_clear(rho_i *rho);
int create_AccessStructurefromPolicy(AccessStructure *structure, policy_attribute_list *policy_list, attribute_list* att_list);
void adjustment_SpanProgram(SpanProgram* SP);
int tfel_create_ciphertext_from_policy(tfel_pubkey *pubkey, tfel_param_G param_G, AccessStructure *AS, char *encfile);

void tfel_serialize_ciphertext(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...);
void tfel_AccessStructure_to_buffer(AccessStructure *AS_ptr, unsigned char *buffer, size_t max_len, size_t *result_len);
int tfel_create_ciphertext_from_attribute(tfel_pubkey *pubkey, tfel_param_G param_G, attribute_set Delta, char *encfile);

//from Dec.c
AccessStructure* check_attribute_to_matrix(attribute_set *sk_Delta, AccessStructure *AS);
mpz_t *calc_alpha_i(AccessStructure *AS, mpz_t order);

#define BYTES 4

















//from Enc.c



void init_rho_i(rho_i* rho) {
    rho->t = 0;
    rho->v_t[0] = 0;
    rho->v_t[1] = -1;
    rho->is_negated = FALSE;
    rho->next = NULL;
    return;
}

//エラー処理を書く
void init_AccessStructure(AccessStructure* AS) {
    AS->S = (SpanProgram*)malloc(sizeof(SpanProgram));
    AS->num_policy = 0;
    AS->rho = (rho_i*)malloc(sizeof(rho_i));
    init_rho_i(AS->rho);
    return;
}

void AccessStructure_clear(AccessStructure* AS) {
    Spanprogram_clear(AS->S);
    rho_clear(AS->rho);
    return;
}

void print_policy(policy_attribute_list *policy) {
    int i, j;
    if (policy->node_type == 0) {
        printf("policy_node_type error\n");
        return;
    }
    else if (policy->node_type == 1) {
        for (i = 0; i < policy->num_policy_att; i++) {
            printf("%s=%s ", policy->attribute[i].category_str, policy->attribute[i].value_str);
        }
    }
    else {
        printf("%d ", policy->node_type);
        for (i = 0; i < policy->num_policy_att; i++) {
            for (j = 0; j < i+2; j++) printf(" ");
            if (i != 0) printf("  ");
            print_policy(&(policy->policy[i]));
            printf("\n");
        }
    }
    printf("\n");
    return;
}

//csvファイルと条件式の属性を比較、存在したらベクトルを返す。なかったらエラー。
//att_listは属性の定義←csvファイルから持ってきたやつ
//こっちを先に実行
//void attribute_search(attribute_list* att_list, attribute_set *att_set, char* category, char* value) {
int attribute_check(attribute_list *att_list, policy_attribute *policy_att, rho_i *rho) {
    Attribute *att_ptr;
    Value *value_ptr;
    att_ptr = att_list->attribute;
    
    while (att_ptr != NULL) {
        if (strcmp(att_ptr->data, policy_att->category_str) != 0) { //カテゴリが一致するまでループ、合ってたら0を返す
            att_ptr = att_ptr->next;
            rho->t++;
            continue;
        }
        //一致したのなら以下のループ
        value_ptr = att_ptr->value;
        rho->v_t[0]++;
        while (value_ptr != NULL) {
            //rho->v_t[0]++; //なんでここでインクリメントしてたのか要チェック
            if (strcmp(value_ptr->data, policy_att->value_str) != 0) { //バリュが一致するまでループ
                rho->v_t[0]++;
                value_ptr = value_ptr->next;
                continue;
            }
            else { //一致したら終わり
                rho->is_negated = policy_att->is_negated;
                //printf("neg = %d, rho(%d)=(%d,%d)\n", rho->is_negated, rho->t, rho->v_t[0], rho->v_t[1]);
                return 0;
            }
        }
        att_ptr = att_ptr->next;
    }
    printf("attribute check error\n");
    
    return -1;
}

void rho_clear(rho_i *rho) {
    if (rho->next != NULL) {
        rho_clear(rho->next);
        free(rho);
    }
    else {
        memset(rho, sizeof(rho_i), 0);
        free(rho);
        return;
    }
}


//この関数使ってる？
int create_AccessStructurefromPolicy(AccessStructure *structure, policy_attribute_list *policy_list, attribute_list* att_list) {
    int i, j;
    //最初にpolicyの行列を生成し、num_policy_attの分だけfor文回してreturnされる行列をinsertしていく
    
    AccessStructure *structure_ptr;
    
    rho_i *rho_ptr;
    rho_i *rho_end;
    rho_ptr = NULL;
    rho_end = NULL;
    
    switch (policy_list->node_type) {
        case 0: //node NULL
            printf("plicy node null error\n");
            return -1;
        case 1: //node leaf
            //policyの属性が適当なものかcsvから判断
            //正しかったらstructure->num_policy++してrho_iを
            //最初にrho_iのメモリ確保、初期化をここで
            init_AccessStructure(structure);
            t_nSpanprogram_gen(structure->S, 1, 1);
            /*structure->rho = (rho_i*)malloc(sizeof(rho_i));
             init_rho_i(structure->rho);*/
            rho_ptr = structure->rho;
            if (attribute_check(att_list, policy_list->attribute, rho_ptr) == -1) {
                AccessStructure_clear(structure);
                return -1; //ここの異常終了の返り値とかもちゃんとしたやつにする
            }
            //t_nSpanprogram_gen(structure->S, 1, 1);//この関数を↑に持っていく
            structure->num_policy = 1;
            
            /*		for (i = 0; i < policy->num_policy_att; i++) {
             if (policy->attribute[i] == NULL) {
             printf("policy->attribute[%d] null error\n", i);
             rho_clear(structure->rho);
             return -1;
             }
             if (i != 0) {
             rho_ptr->next = (rho_i*)malloc(sizeof(rho_i));
             init_rho_i(rho_ptr->next);
             rho_ptr = rho_ptr->next;
             }
             if (attribute_check(att_list, &policy->attribute[i], rho_ptr) == -1) {
             rho_clear(structure->rho);
             return -1; //ここの異常終了の返り値とかもちゃんとしたやつにする
             }
             }*/
            break;
        default:
            //k_of_n_threshold実行
            init_AccessStructure(structure);
            t_nSpanprogram_gen(structure->S, policy_list->threshold, policy_list->num_policy_att);
            //structure->rhoの初期化
            /*structure->rho = (rho_i*)malloc(sizeof(rho_i));
             init_rho_i(structure->rho);
             rho_ptr = structure->rho;
             rho_temp = rho_ptr;*/
            
            /*if (attribute_check(att_list, policy_list->attribute, rho_ptr) == -1) {
             rho_clear(structure->rho);
             return -1; //ここの異常終了の返り値とかもちゃんとしたやつにする
             }*/  //いらないかも
            
            structure_ptr = (AccessStructure*)malloc(sizeof(AccessStructure)*policy_list->num_policy_att);
            
            int count = 0;//insertする行をカウントするために必要
            for (i = 0; i < policy_list->num_policy_att; i++) {
                //printf("%d ,i = %d\n", policy_list->num_policy_att, i);
                //k_of_n_threshold実行してSpanProgramを生成、num_policy+1行目にinsert
                if (create_AccessStructurefromPolicy(&structure_ptr[i], &policy_list->policy[i], att_list) == -1) {
                    for (j = 0; j < i; j++) {
                        AccessStructure_clear(&structure_ptr[j]);
                    }
                    free(structure_ptr);
                    return -1;
                }
                //↓でinsertしていく
                //insert_Spanprogram(SpanProgram *S1, SpanProgram *S2, SpanProgram *S3, int n);←たぶんnはn+1で
                insert_Spanprogram(structure->S, structure_ptr[i].S, i+1+count);
                count += structure_ptr[i].S->row-1;
                
                
                //rho_iをつなげる
                if (i == 0) {
                    structure->rho = structure_ptr[0].rho;
                    rho_ptr = structure->rho; //rhoの開始
                    rho_end = structure->rho; //rhoの終わり
                    //printf("(%d, %d)\n", rho_ptr->v_t[0], rho_ptr->v_t[1]);
                }
                else {
                    //printf("aa(%d, %d)\n", rho_end->v_t[0], rho_end->v_t[1]);
                    while (rho_end->next != NULL) rho_end = rho_end->next; //たぶん必要
                    rho_end->next = structure_ptr[i].rho;
                }
                
                /*for (j = 1; j < policy_list->policy[i].num_policy_att; j++) {
                 while (rho_end->next != NULL) rho_end = rho_end->next;
                 rho_end->next = structure_ptr[j].rho;
                 }*/
                
                //num_policyを増やす
                structure->num_policy += structure_ptr[i].num_policy;
                
            }
            //printf("insert end\n");
            
            //structure_ptrを解放する（その中身も？）
            for (i = 0; i < policy_list->num_policy_att; i++) {
                Spanprogram_clear(structure_ptr[i].S);
            }
            memset(structure_ptr, 0, sizeof(AccessStructure)*policy_list->num_policy_att);
            free(structure_ptr);
            break;
    }
    
    //free(rho_ptr);
    
    return 0;
}

//スパンプログラムの行列の2列目以降に＋1する関数
void adjustment_SpanProgram(SpanProgram* SP) {
    int i, j;
    for (i = 0; i < SP->row; i++) {
        for (j = 1; j < SP->column; j++) {
            mpz_add_ui(SP->M[i][j], SP->M[i][j], 1);
        }
    }
    return;
}

//公開鍵pk, アクセス構造S:=(M, rho(i))を引数としてct_Sを出力する
//ペアリングしないんだったらparam_Gいらない→やっぱりいる
//int tfel_create_ciphertext_from_policy(tfel_pubkey *pubkey, tfel_param_G param_G, AccessStructure *AS, char *inputfile, char *encfile) {
int tfel_create_ciphertext_from_policy(tfel_pubkey *pubkey, tfel_param_G param_G, AccessStructure *AS, char *encfile) {
    /*
     * f←F_q^r, s^T := M・f, s_0 := 1・f, eta_0,eta_i,theta_i,xi←F_q(i = 1,...,l)
     */
    //init c_i
    int i, j;
    int l, r;
    l = AS->S->row; //row of matrix
    r = AS->S->column; //column of matrix
    Element c_d1;
    element_init(c_d1, param_G.p->g3);
    basis *c_i = NULL;
    /*c_i = (basis*)malloc(sizeof(basis)*AS->num_policy+1);
     for (k = 0; k < AS->num_policy+1; k++) {
     c_i[k].dim = l+1;
     c_i[k].M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i[k].dim);//mallocのエラー処理
     for (i = 0; i < c_i[k].dim; i++) {
     if (i == 0) {
     c_i[k].M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);//mallocのエラー処理
     for (j = 0; j < 5; j++) {
					point_init(c_i[k].M[i][j], param_G.p->g1);
     }
     }
     else {
     c_i[k].M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);//mallocのエラー処理
     for (j = 0; j < 7; j++) {
					point_init(c_i[k].M[i][j], param_G.p->g1);
     }
     }
     }
     }*/
    c_i = (basis*)malloc(sizeof(basis));
    c_i->dim = l+1;
    c_i->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i->dim);//mallocのエラー処理
    for (i = 0; i < c_i->dim; i++) {
        if (i == 0) {
            c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);//mallocのエラー処理
            for (j = 0; j < 5; j++) {
                point_init(c_i->M[i][j], param_G.p->g1);
            }
        }
        else {
            c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);//mallocのエラー処理
            for (j = 0; j < 7; j++) {
                point_init(c_i->M[i][j], param_G.p->g1);
            }
        }
    }
    //init c_i
    
    //generate c_i,c_(d+1)
    if (c_i_set_cp(*pubkey, param_G, c_i, &c_d1, AS) != 0) {
        printf("c_i_set error\n");
        return -1;
    }

    
    //generate ciphertext　生成できたデータをシリアライズしてciphertextの構造体に入れる
    //後で上に持ってく
    tfel_ciphertext ciphertext;
    memset(&ciphertext, 0, sizeof(tfel_ciphertext));
    //後で上に持ってく
    
    //serialize cihpertext
    unsigned char *ciphertext_buf = NULL; //定義は上に移動させる
    
    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;
    //c_iとASだけシリアライズすればいい？(c_d1いらない？)
    //result_lenが意味分からない。ciphertext.data_lenいらない？
    tfel_serialize_ciphertext(NULL, 0, result_len, "%S%c", AS, c_i);
    //int dd = 10;
    //tfel_serialize_ciphertext(NULL, 0, result_len, "%d", dd);
    //printf("result_len = %zd\n", *result_len);
    if((ciphertext.data = (unsigned char*)malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    ciphertext.max_len = buf_len;
    //ciphertext.data = ciphertext_buf;
    ciphertext.data_len = buf_len; //いらない
    tfel_serialize_ciphertext(ciphertext.data, ciphertext.max_len, result_len, "%S%c", AS, c_i);
    //tfel_serialize_ciphertext(ciphertext.data, ciphertext.max_len, result_len, "%d", dd);
    
    //base64エンコード
    size_t ctLength;
    char *ctBuffer;
    ctBuffer = NewBase64Encode(ciphertext.data, buf_len, FALSE, &ctLength);
    printf("ciphertext_buf =  '%s'\n", ctBuffer); //debag
    
    /*fp = fopen("kStar.cpfe", "w"); //名前も可変にする
     if (fp != NULL) {
     fprintf(fp, "%s", skBuffer);
     }
     fclose(fp);*/
    //base64エンコード
    
    //serialize cihpertext
    
    //generate ciphertext
    
    //hash c_d1 to get AES session key
    //c_d1のバイト列を16ビットのハッシュに?

    
    size_t key_len = element_get_oct_length(c_d1); // size of c_d1
    unsigned char *c_d1_oct;
    c_d1_oct = (unsigned char*)malloc(sizeof(unsigned char)*key_len);
    element_to_oct(c_d1_oct, &key_len, c_d1); // bytes of c_d1
    
    unsigned char *session_key;
    session_key = (unsigned char *)malloc(sizeof(unsigned char)*16);
    //int d_len;
    
    hash_to_bytes(c_d1_oct, key_len, SESSION_KEY_LEN, session_key, 2);
    //printf("%s\n", session_key);
    
    //printf("session_key = \n%s\n", session_key); //debag
    //hash c_d1 to get AES session key
    
    //session_keyを鍵としたAESでファイルを暗号化
    

    char *data;// = NULL;
    ssize_t data_len_f;
    //data = "encdata.txtaaaaaa";
    /*char *enc_file;
     enc_file = "output";*/
    char *ext;
    ext = CPFE_EXTENSION;
    FILE *fp;
    
    //encdataを開く
    //if ((fp = fopen("encdata.rtf", "r")) == NULL) {
    if ((fp = fopen(encfile, "r")) == NULL) {
        printf("encdata open error\n");
        exit(-1);
    }
    data_len_f = read_file(fp, &data);
    fclose(fp);
    
    //encdataを開く
    AES_KEY key;
    size_t iv_length;
    uint8 iv[AES_BLOCK_SIZE+1];
    int data_len = (int) ceil((strlen(data) + strlen(MAGIC))/(double)(AES_BLOCK_SIZE)) * AES_BLOCK_SIZE; // round to nearest multiple of 16-bytes
    //char aes_ciphertext[data_len], data_magic[data_len];
    char *aes_ciphertext, *data_magic;
    aes_ciphertext = (char*)malloc(sizeof(char)*data_len);
    data_magic = (char*)malloc(sizeof(char)*data_len);
    printf("data_len = %d\n", data_len);
    
    /* generate a random IV */
    memset(iv, 0, AES_BLOCK_SIZE);
    RAND_bytes((uint8 *) iv, AES_BLOCK_SIZE);
    //debug("IV: ");
    //print_buffer_as_hex((uint8 *) iv, AES_BLOCK_SIZE);
    char *iv_base64 = NewBase64Encode(iv, AES_BLOCK_SIZE, FALSE, &iv_length);
    
    memset(aes_ciphertext, 0, data_len);
    AES_set_encrypt_key(session_key, 8*SESSION_KEY_LEN, &key); //SESSION_KEY_LENがおかしい？
    //printf("\n\n\n\ndata = %s\n\n\n\n", data);  ////////test
    printf("\nEncrypting data...\n");
    //printf("\tPlaintext is => '%s'.\n", data);
    
    sprintf(data_magic, MAGIC"%s", data);
    //printf("\n\ndata_magic = %s\n\n", data_magic);  ///////test
    //AES暗号化
    AES_cbc_encrypt((uint8 *)data_magic, (uint8 *) aes_ciphertext, data_len, &key, (uint8 *) iv, AES_ENCRYPT);
    
    char filename[strlen(encfile)+1];
    memset(filename, 0, strlen(encfile));
    //uint8 *rand_id[BYTES+1];
    sprintf(filename, "%s.%s", encfile, ext);
    fp = fopen(filename, "w");
    
    printf("\tCiphertext stored in '%s'.\n", filename);
    printf("\tABE Ciphertext size is: '%zd'.\n", ciphertext.data_len);
    printf("\tAES Ciphertext size is: '%d'.\n", data_len);
    
    /* base-64 both ciphertexts and write to the stdout -- in XML? */
    size_t abe_length, aes_length;
    //printf("\n\n\n\nciphertext.data = %d\nciphertext.data_len = %zd\n\n\n\n", *ciphertext.data, ciphertext.data_len); ////test
    char *ABE_cipher_base64 = NewBase64Encode(ciphertext.data, ciphertext.data_len, FALSE, &abe_length);
    char *AES_cipher_base64 = NewBase64Encode(aes_ciphertext, data_len, FALSE, &aes_length);
    
    fprintf(fp, ABE_TOKEN":%s:"ABE_TOKEN_END":", ABE_cipher_base64);
    fprintf(fp, IV_TOKEN":%s:"IV_TOKEN_END":", iv_base64);
    fprintf(fp, AES_TOKEN":%s:"AES_TOKEN_END, AES_cipher_base64);
    
    //色々と初期化(何かあったら)
    free(aes_ciphertext);
    free(data_magic);
    //色々と初期化
    
    fclose(fp);
    
    
    return 0;
}




//余裕を見てtfel_export_secret_paramsと統合したい
void tfel_serialize_ciphertext(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...) {
    va_list comp_list;
    unsigned char *buf_ptr = buffer;
    char *fmt_ptr = NULL;
    int *max_num = NULL;
    v_vector *vector_ptr = NULL;
    AccessStructure *AS_ptr;
    
    basis *basis_list = NULL;
    size_t *result = NULL;
    result = result_len;
    
    *result_len = 0;
    
    va_start(comp_list, fmt);
    
    
    for(fmt_ptr = fmt; *fmt_ptr != '\0'; fmt_ptr++) {
        if(*fmt_ptr != '%') continue;
        
        if(buffer != NULL) buf_ptr = (unsigned char*)(buffer + *result_len);
        
        switch(*++fmt_ptr) {
            case 'd': //number of
                *result_len += sizeof(int);
                max_num = va_arg(comp_list, int*);
                if(buffer != NULL && *result_len <= max_len) {
                    *(int*)buf_ptr = *max_num;
                }
                break;
            case 'S': //access structure
                //*result_len += sizeof(int)*(*max_num);
                AS_ptr = va_arg(comp_list, AccessStructure*);
                max_num = &AS_ptr->num_policy; //後で変更
                //tfel_AccessStructure_to_buffer実行
                tfel_AccessStructure_to_buffer(AS_ptr, buffer, max_len, result_len);
                break;
            case 'v':
                *result_len += sizeof(int)*(*max_num);
                vector_ptr = va_arg(comp_list, v_vector*);
                if(buffer != NULL && *result_len <= max_len) {
                    while (vector_ptr != NULL) {
                        *(int*)buf_ptr = vector_ptr->x_t[1];
                        printf("x_t = %d\n", vector_ptr->x_t[1]);
                        buf_ptr += sizeof(int);
                        vector_ptr = vector_ptr->next;
                    }
                }
                break;
            case 'c': //c_i
                basis_list = va_arg(comp_list, basis*);
                buf_ptr = buffer;
                tfel_kStar_to_buffer(basis_list, buf_ptr, max_len, result_len, basis_list->dim); //KeyGen.hから流用
                break;
                //case 'd'
        }
    }
}

void tfel_AccessStructure_to_buffer(AccessStructure *AS_ptr, unsigned char *buffer, size_t max_len, size_t *result_len) {
    //int t, i, j;
    int i, j;
    unsigned char *buf_ptr = buffer;
    //int size = 0;
    //size_t length;
    //size_t *length_temp = &length;
    char *mpz_str;
    rho_i *rho_ptr;
    
    
    if(AS_ptr == NULL) {
        printf("invalid AS input\n");
        return;
    }
    /*
     * 実装方針
     * 1.num_policy
     * 2.SpanProgram　Sのシリアライズ
     * →row, column, 行列M
     * 3.rho_i
     * →int t, v_t[2], is_negated
     */
    *result_len += sizeof(int)*3;
    if(buffer != NULL && *result_len <= max_len) { //1.+2.のrow,column
        *(int*)buf_ptr = AS_ptr->num_policy;
        buf_ptr += sizeof(int);
        *(int*)buf_ptr = AS_ptr->S->row;
        buf_ptr += sizeof(int);
        *(int*)buf_ptr = AS_ptr->S->column;
    }
    
    for (i = 0; i < AS_ptr->S->row; i++) { //2.S->Mのシリアライズ
        for (j = 0; j < AS_ptr->S->column; j++) {
            if (buffer != NULL && *result_len <= max_len) {
                buf_ptr = (unsigned char*)(buffer + *result_len);
            }
            //↓mpz_get_strは使えるのか要確認
            
            /* 不具合あったら下の0428を消してここのコメント解除
             *result_len += sizeof(char);
             if (buffer != NULL && *result_len <= max_len) {
             mpz_str = (char*)malloc(sizeof(char));
             mpz_get_str(mpz_str, 16, AS_ptr->S->M[i][j]);
             
             *(char*)buf_ptr = *mpz_str;
             //buf_ptr = (unsigned char*)(buffer + *result_len);
             free(mpz_str);
             }*/
            /*0428*/
            *result_len += sizeof(char)*MAX_STRING;
            int k;
            if (buffer != NULL && *result_len <= max_len) {
                mpz_str = (char*)malloc(sizeof(char)*MAX_STRING);
                memset(mpz_str, '\0', sizeof(char)*MAX_STRING);
                //mpz_str = NULL;
                mpz_get_str(mpz_str, 16, AS_ptr->S->M[i][j]);
                for (k = 0; k < MAX_STRING; k++) {
                    *(char*)(buf_ptr+k) = *(mpz_str+k);
                }
                *(char*)buf_ptr = *mpz_str;
                //printf("buf_ptr[%d][%d] = %s\n%s\n", i, j, mpz_str, buf_ptr);
                free(mpz_str);
            }
            /*0428*/
        }
    }
    rho_ptr = AS_ptr->rho;
    while (rho_ptr != NULL) { //3.rho_i→int t, v_t[2], is_negated
        if (buffer != NULL && *result_len <= max_len) {
            buf_ptr = (unsigned char*)(buffer + *result_len);
            *(int*)buf_ptr = rho_ptr->t;
            buf_ptr += sizeof(int);
            *(int*)buf_ptr = rho_ptr->v_t[0];
            buf_ptr += sizeof(int);
            *(int*)buf_ptr = rho_ptr->v_t[1];
            buf_ptr += sizeof(int);
            *(Bool*)buf_ptr = rho_ptr->is_negated;
            buf_ptr += sizeof(Bool);
        }
        *result_len += sizeof(int)*3 + sizeof(Bool);
        rho_ptr = rho_ptr->next;
    }
    /*	for(i = 0; i < AS_ptr->num_policy+1; i++) {
     if (i == 0) t = 5;
     else t = 7;
     for(j = 0; j < t; j++) {
     if (buffer != NULL && *result_len <= max_len) {
     buf_ptr = (unsigned char*)(buffer + *result_len);
     }
     size = point_get_oct_length(basis_list->M[i][j]);
     *result_len += sizeof(int);
     
     if (buffer != NULL && *result_len <= max_len) {
     *((int*)buf_ptr) = size;
     buf_ptr = (unsigned char*)(buffer + *result_len);
     point_to_oct(buf_ptr, length_temp, basis_list->M[i][j]); //sizeとlengthの値が一緒か後で確認→ok
     }
     *result_len += (size_t)size;//point_octの配列の長さ(size)
     }
     }*/
}

//公開鍵pk, ユーザの属性Γを引数としてct_Γを出力する
//下のやつが失敗したらこっちにもどす
//c_iがdeltaの数のみの場合の関数→d個つくる関数の作り変える
//KP-FE
int tfel_create_ciphertext_from_attribute_temp(tfel_pubkey *pubkey, tfel_param_G param_G, attribute_set Delta, char *encfile) {
    /*
     * f←F_q^r, s^T := M・f, s_0 := 1・f, eta_0,eta_i,theta_i,xi←F_q(i = 1,...,l)
     */
    /*	int i, j;
     int l, r;
     l = structure->S->row; //row of matrix
     r = structure->S->column; //column of matrix
     
     mpz_t *fv; //f←F_q^r
     mpz_t *sv; //:= (s_1,..., s_l) := M・f
     mpz_t s_0, eta_0, xi; //s_0, eta_0, xi
     mpz_t *eta_i, *theta_i; //eta_i, theta_i (i = 1,...,l)
     
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
     gen_random(&fv[i], s, order);
     }
     for (i = 0; i < l; i++) {
     gen_random(&eta_i[i], s, order);
     gen_random(&theta_i[i], s, order);
     }
     gen_random(&eta_0, s, order);
     gen_random(&xi, s, order);
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
     //generate s_0
     
     //generate sv := M・fv
     for (i = 0; i < r; i++) {
     mpz_init(temp1);
     mpz_init(temp2);
     mpz_init(temp3);
     for (j = 0; j < l; j++) {
     mpz_mul(temp1, structure->S->M[i][j], fv[i]);
     mpz_mod(temp2, temp1, order);
     mpz_add_ui(temp3, temp2, 0);
     mpz_mod(temp3, temp2, order);
     mpz_set(temp2, temp3);
     }
     mpz_set(sv[i], temp2);
     }
     //generate sv := M・fv
     */
    //init c_i
    int i, j;
    //int l, r;
    v_vector *v_ptr = NULL;
    v_ptr = Delta.value;
    //l = AS->S->row; //row of matrix
    //r = AS->S->column; //column of matrix
    Element c_d1;
    element_init(c_d1, param_G.p->g3);
    basis *c_i = NULL;
    /*c_i = (basis*)malloc(sizeof(basis)*AS->num_policy+1);
     for (k = 0; k < AS->num_policy+1; k++) {
     c_i[k].dim = l+1;
     c_i[k].M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i[k].dim);//mallocのエラー処理
     for (i = 0; i < c_i[k].dim; i++) {
     if (i == 0) {
     c_i[k].M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);//mallocのエラー処理
     for (j = 0; j < 5; j++) {
					point_init(c_i[k].M[i][j], param_G.p->g1);
     }
     }
     else {
     c_i[k].M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);//mallocのエラー処理
     for (j = 0; j < 7; j++) {
					point_init(c_i[k].M[i][j], param_G.p->g1);
     }
     }
     }
     }*/
    c_i = (basis*)malloc(sizeof(basis));
    //c_i->dim = l+1;
    c_i->dim = Delta.num+1;
    c_i->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i->dim);//mallocのエラー処理
    for (i = 0; i < c_i->dim; i++) {
        if (i == 0) {
            c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);//mallocのエラー処理
            for (j = 0; j < 5; j++) {
                point_init(c_i->M[i][j], param_G.p->g1);
            }
        }
        else {
            c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);//mallocのエラー処理
            for (j = 0; j < 7; j++) {
                point_init(c_i->M[i][j], param_G.p->g1);
            }
        }
    }
    
    //init c_i
    
    //generate c_i,c_(d+1)
    if (c_i_set_kp(*pubkey, param_G, c_i, &c_d1, Delta) != 0) {
        printf("c_i_set_kp error\n");
        return -1;
    }
    /*if (c_i_set(*pubkey, param_G, c_i, &c_d1, AS) != 0) {//変える
     printf("c_i_set error\n");
     return -1;
     }*/
    /*for (i = 0; i < AS->num_policy+1; i++) {
     if (c_i_set(*pubkey, param_G, c_i, &c_d1, AS) != 0) {//ここ絶対やばい
     printf("c_i_set error\n");
     return -1;
     }
     }*/
    
    //generate c_i,c_(d+1)
    /*int length = element_get_str_length(c_d1);
     char *os;
     os = (char*)malloc(sizeof(char)*length);
     printf("testetstetstests\n");
     element_get_str(os, c_d1);
     printf("c_d1 = \n%s\n", os);
     free(os);*/
    
    //generate ciphertext　生成できたデータをシリアライズしてciphertextの構造体に入れる
    //後で上に持ってく
    tfel_ciphertext ciphertext;
    memset(&ciphertext, 0, sizeof(tfel_ciphertext));
    //後で上に持ってく
    
    //serialize cihpertext
    unsigned char *ciphertext_buf = NULL; //定義は上に移動させる
    
    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;
    
    tfel_serialize_ciphertext(NULL, 0, result_len, "%d%v%c", &(Delta.num), Delta.value, c_i);
    
    if((ciphertext.data = (unsigned char*)malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    ciphertext.max_len = buf_len;
    //ciphertext.data = ciphertext_buf;
    ciphertext.data_len = buf_len; //いらない
    
    tfel_serialize_ciphertext(ciphertext.data, ciphertext.max_len, result_len, "%d%v%c", &(Delta.num), Delta.value, c_i);
    
    
    //base64エンコード
    size_t ctLength;
    char *ctBuffer;
    
    ctBuffer = NewBase64Encode(ciphertext.data, buf_len, FALSE, &ctLength);
    printf("ciphertext_buf =  '%s'\n", ctBuffer); //debag
    
    /*fp = fopen("kStar.cpfe", "w"); //名前も可変にする
     if (fp != NULL) {
     fprintf(fp, "%s", skBuffer);
     }
     fclose(fp);*/
    //base64エンコード
    
    //serialize cihpertext
    
    //generate ciphertext
    
    //hash c_d1 to get AES session key
    //c_d1のバイト列を16ビットのハッシュに?128ビット？
#define SESSION_KEY_LEN 16
    
    size_t key_len = element_get_oct_length(c_d1); // size of c_d1
    unsigned char *c_d1_oct;
    c_d1_oct = (unsigned char*)malloc(sizeof(unsigned char)*key_len);
    element_to_oct(c_d1_oct, &key_len, c_d1); // bytes of c_d1
    
    unsigned char *session_key;
    session_key = (unsigned char *)malloc(sizeof(unsigned char)*16);
    //int d_len;
    
    hash_to_bytes(c_d1_oct, key_len, SESSION_KEY_LEN, session_key, 2);
    //printf("%s\n", session_key);
    
    //printf("session_key = \n%s\n", session_key); //debag
    //hash c_d1 to get AES session key
    
    //session_keyを鍵としたAESでファイルを暗号化
    
    //後で適切な変更
#define MAGIC "ABE|"
#define ABE_TOKEN "ABE"
#define ABE_TOKEN_END "ABE_END"
#define	IV_TOKEN "IV"
#define IV_TOKEN_END "IV_END"
#define AES_TOKEN "AES"
#define AES_TOKEN_END "AES_END"
    char *data;// = NULL;
    ssize_t data_len_f;
    //data = "encdata.txtaaaaaa";
    /*char *enc_file;
     enc_file = "output";*/
    char *ext;
    ext = "tfel";
    FILE *fp;
    
    //encdataを開く
    //if ((fp = fopen("encdata.rtf", "r")) == NULL) {
    if ((fp = fopen(encfile, "r")) == NULL) {
        printf("encdata open error\n");
        exit(-1);
    }
    data_len_f = read_file(fp, &data);
    fclose(fp);
    
    //encdataを開く
    AES_KEY key;
    size_t iv_length;
    uint8 iv[AES_BLOCK_SIZE+1];
    int data_len = (int) ceil((strlen(data) + strlen(MAGIC))/(double)(AES_BLOCK_SIZE)) * AES_BLOCK_SIZE; // round to nearest multiple of 16-bytes
    //char aes_ciphertext[data_len], data_magic[data_len];
    char *aes_ciphertext, *data_magic;
    aes_ciphertext = (char*)malloc(sizeof(char)*data_len);
    data_magic = (char*)malloc(sizeof(char)*data_len);
    printf("data_len = %d\n", data_len);
    
    /* generate a random IV */
    memset(iv, 0, AES_BLOCK_SIZE);
    RAND_bytes((uint8 *) iv, AES_BLOCK_SIZE);
    //debug("IV: ");
    //print_buffer_as_hex((uint8 *) iv, AES_BLOCK_SIZE);
    char *iv_base64 = NewBase64Encode(iv, AES_BLOCK_SIZE, FALSE, &iv_length);
    
    memset(aes_ciphertext, 0, data_len);
    AES_set_encrypt_key(session_key, 8*SESSION_KEY_LEN, &key); //SESSION_KEY_LENがおかしい？
    //printf("\n\n\n\ndata = %s\n\n\n\n", data);  ////////test
    printf("\nEncrypting data...\n");
    //printf("\tPlaintext is => '%s'.\n", data);
    
    sprintf(data_magic, MAGIC"%s", data);
    //printf("\n\ndata_magic = %s\n\n", data_magic);  ///////test
    //AES暗号化
    AES_cbc_encrypt((uint8 *)data_magic, (uint8 *) aes_ciphertext, data_len, &key, (uint8 *) iv, AES_ENCRYPT);
    
    char filename[strlen(encfile)+1];
    memset(filename, 0, strlen(encfile));
    //uint8 *rand_id[BYTES+1];
    sprintf(filename, "%s.%s", encfile, ext);
    fp = fopen(filename, "w");
    
    printf("\tCiphertext stored in '%s'.\n", filename);
    printf("\tABE Ciphertex size is: '%zd'.\n", ciphertext.data_len);
    printf("\tAES Ciphertext size is: '%d'.\n", data_len);
    
    /* base-64 both ciphertexts and write to the stdout -- in XML? */
    size_t abe_length, aes_length;
    //printf("\n\n\n\nciphertext.data = %d\nciphertext.data_len = %zd\n\n\n\n", *ciphertext.data, ciphertext.data_len); ////test
    char *ABE_cipher_base64 = NewBase64Encode(ciphertext.data, ciphertext.data_len, FALSE, &abe_length);
    char *AES_cipher_base64 = NewBase64Encode(aes_ciphertext, data_len, FALSE, &aes_length);
    
    fprintf(fp, ABE_TOKEN":%s:"ABE_TOKEN_END":", ABE_cipher_base64);
    fprintf(fp, IV_TOKEN":%s:"IV_TOKEN_END":", iv_base64);
    fprintf(fp, AES_TOKEN":%s:"AES_TOKEN_END, AES_cipher_base64);
    
    //色々と初期化(何かあったら)
    free(aes_ciphertext);
    free(data_magic);
    //色々と初期化
    
    fclose(fp);
    
    
    return 0;
}


//公開鍵pk, ユーザの属性Γを引数としてct_Γを出力する
//c_iがd個の関数
//KP-FE
int tfel_create_ciphertext_from_attribute(tfel_pubkey *pubkey, tfel_param_G param_G, attribute_set Delta, char *encfile) {
    /*
     * f←F_q^r, s^T := M・f, s_0 := 1・f, eta_0,eta_i,theta_i,xi←F_q(i = 1,...,l)
     */
    /*	int i, j;
     int l, r;
     l = structure->S->row; //row of matrix
     r = structure->S->column; //column of matrix
     
     mpz_t *fv; //f←F_q^r
     mpz_t *sv; //:= (s_1,..., s_l) := M・f
     mpz_t s_0, eta_0, xi; //s_0, eta_0, xi
     mpz_t *eta_i, *theta_i; //eta_i, theta_i (i = 1,...,l)
     
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
     gen_random(&fv[i], s, order);
     }
     for (i = 0; i < l; i++) {
     gen_random(&eta_i[i], s, order);
     gen_random(&theta_i[i], s, order);
     }
     gen_random(&eta_0, s, order);
     gen_random(&xi, s, order);
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
     //generate s_0
     
     //generate sv := M・fv
     for (i = 0; i < r; i++) {
     mpz_init(temp1);
     mpz_init(temp2);
     mpz_init(temp3);
     for (j = 0; j < l; j++) {
     mpz_mul(temp1, structure->S->M[i][j], fv[i]);
     mpz_mod(temp2, temp1, order);
     mpz_add_ui(temp3, temp2, 0);
     mpz_mod(temp3, temp2, order);
     mpz_set(temp2, temp3);
     }
     mpz_set(sv[i], temp2);
     }
     //generate sv := M・fv
     */
    //init c_i
    int i, j;
    v_vector *v_ptr = NULL;
    v_ptr = Delta.value;
    Element c_d1;
    element_init(c_d1, param_G.p->g3);
    basis *c_i = NULL;
    
    c_i = (basis*)malloc(sizeof(basis));
    c_i->dim = Delta.num+1;//
    //c_i->dim = pubkey->num_att+1;
    c_i->M = (EC_POINT**)malloc(sizeof(EC_POINT*)*c_i->dim);//mallocのエラー処理
    for (i = 0; i < c_i->dim; i++) {
        if (i == 0) {
            c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*5);//mallocのエラー処理
            for (j = 0; j < 5; j++) {
                point_init(c_i->M[i][j], param_G.p->g1);
            }
        }
        else {
            c_i->M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*7);//mallocのエラー処理
            for (j = 0; j < 7; j++) {
                point_init(c_i->M[i][j], param_G.p->g1);
            }
        }
    }
    
    //init c_i
    
    /*
     下の引数変えるべき？
     後で考える
     */
    //generate c_i,c_(d+1)
    if (c_i_set_kp(*pubkey, param_G, c_i, &c_d1, Delta) != 0) {
        printf("c_i_set_kp error\n");
        return -1;
    }
    
    /*
     下の引数変えるべき？
     後で考える
     */
    
    //generate ciphertext　生成できたデータをシリアライズしてciphertextの構造体に入れる
    //後で上に持ってく
    tfel_ciphertext ciphertext;
    memset(&ciphertext, 0, sizeof(tfel_ciphertext));
    //後で上に持ってく
    
    //serialize cihpertext
    unsigned char *ciphertext_buf = NULL; //定義は上に移動させる
    
    size_t buf_len;
    size_t *result_len;
    result_len = &buf_len;
    *result_len = 0;
    
    /*
     下のtfel_serialize_ciphertextの引数変えるべき？
     後で考える
     */
    
    tfel_serialize_ciphertext(NULL, 0, result_len, "%d%v%c", &(Delta.num), Delta.value, c_i);
    
    if((ciphertext.data = (unsigned char*)malloc(buf_len)) == NULL) {
        printf("malloc failed.\n");
        exit(1);
    }
    ciphertext.max_len = buf_len;
    //ciphertext.data = ciphertext_buf;
    ciphertext.data_len = buf_len; //いらない
    
    tfel_serialize_ciphertext(ciphertext.data, ciphertext.max_len, result_len, "%d%v%c", &(Delta.num), Delta.value, c_i);
    
    
    //base64エンコード
    size_t ctLength;
    char *ctBuffer;
    
    ctBuffer = NewBase64Encode(ciphertext.data, buf_len, FALSE, &ctLength);
    printf("ciphertext_buf =  '%s'\n", ctBuffer); //debag
    
    /*fp = fopen("kStar.cpfe", "w"); //名前も可変にする
     if (fp != NULL) {
     fprintf(fp, "%s", skBuffer);
     }
     fclose(fp);*/
    //base64エンコード
    
    //serialize cihpertext
    
    //generate ciphertext
    
    //hash c_d1 to get AES session key
    //c_d1のバイト列を16ビットのハッシュに?
#define SESSION_KEY_LEN 16
    
    size_t key_len = element_get_oct_length(c_d1); // size of c_d1
    unsigned char *c_d1_oct;
    c_d1_oct = (unsigned char*)malloc(sizeof(unsigned char)*key_len);
    element_to_oct(c_d1_oct, &key_len, c_d1); // bytes of c_d1
    
    unsigned char *session_key;
    session_key = (unsigned char *)malloc(sizeof(unsigned char)*16);
    //int d_len;
    
    hash_to_bytes(c_d1_oct, key_len, SESSION_KEY_LEN, session_key, 2);
    //printf("%s\n", session_key);
    
    //printf("session_key = \n%s\n", session_key); //debag
    //hash c_d1 to get AES session key
    
    //session_keyを鍵としたAESでファイルを暗号化
    
    //後で適切な変更
#define MAGIC "ABE|"
#define ABE_TOKEN "ABE"
#define ABE_TOKEN_END "ABE_END"
#define	IV_TOKEN "IV"
#define IV_TOKEN_END "IV_END"
#define AES_TOKEN "AES"
#define AES_TOKEN_END "AES_END"
    char *data;// = NULL;
    ssize_t data_len_f;
    //data = "encdata.txtaaaaaa";
    /*char *enc_file;
     enc_file = "output";*/
    char *ext;
    ext = KPFE_EXTENSION;
    FILE *fp;
    
    //encdataを開く
    //if ((fp = fopen("encdata.rtf", "r")) == NULL) {
    if ((fp = fopen(encfile, "r")) == NULL) {
        printf("encdata open error\n");
        exit(-1);
    }
    data_len_f = read_file(fp, &data);
    fclose(fp);
    
    //encdataを開く
    AES_KEY key;
    size_t iv_length;
    uint8 iv[AES_BLOCK_SIZE+1];
    int data_len = (int) ceil((strlen(data) + strlen(MAGIC))/(double)(AES_BLOCK_SIZE)) * AES_BLOCK_SIZE; // round to nearest multiple of 16-bytes
    //char aes_ciphertext[data_len], data_magic[data_len];
    char *aes_ciphertext, *data_magic;
    aes_ciphertext = (char*)malloc(sizeof(char)*data_len);
    data_magic = (char*)malloc(sizeof(char)*data_len);
    printf("data_len = %d\n", data_len);
    
    /* generate a random IV */
    memset(iv, 0, AES_BLOCK_SIZE);
    RAND_bytes((uint8 *) iv, AES_BLOCK_SIZE);
    //debug("IV: ");
    //print_buffer_as_hex((uint8 *) iv, AES_BLOCK_SIZE);
    char *iv_base64 = NewBase64Encode(iv, AES_BLOCK_SIZE, FALSE, &iv_length);
    
    memset(aes_ciphertext, 0, data_len);
    AES_set_encrypt_key(session_key, 8*SESSION_KEY_LEN, &key); //SESSION_KEY_LENがおかしい？
    //printf("\n\n\n\ndata = %s\n\n\n\n", data);  ////////test
    printf("\nEncrypting data...\n");
    //printf("\tPlaintext is => '%s'.\n", data);
    
    sprintf(data_magic, MAGIC"%s", data);
    //printf("\n\ndata_magic = %s\n\n", data_magic);  ///////test
    //AES暗号化
    AES_cbc_encrypt((uint8 *)data_magic, (uint8 *) aes_ciphertext, data_len, &key, (uint8 *) iv, AES_ENCRYPT);
    
    char filename[strlen(encfile)+1];
    memset(filename, 0, strlen(encfile));
    //uint8 *rand_id[BYTES+1];
    sprintf(filename, "%s.%s", encfile, ext);
    fp = fopen(filename, "w");
    
    printf("\tCiphertext stored in '%s'.\n", filename);
    printf("\tABE Ciphertext size is: '%zd'.\n", ciphertext.data_len);
    printf("\tAES Ciphertext size is: '%d'.\n", data_len);
    
    /* base-64 both ciphertexts and write to the stdout -- in XML? */
    size_t abe_length, aes_length;
    //printf("\n\n\n\nciphertext.data = %d\nciphertext.data_len = %zd\n\n\n\n", *ciphertext.data, ciphertext.data_len); ////test
    char *ABE_cipher_base64 = NewBase64Encode(ciphertext.data, ciphertext.data_len, FALSE, &abe_length);
    char *AES_cipher_base64 = NewBase64Encode(aes_ciphertext, data_len, FALSE, &aes_length);
    
    fprintf(fp, ABE_TOKEN":%s:"ABE_TOKEN_END":", ABE_cipher_base64);
    fprintf(fp, IV_TOKEN":%s:"IV_TOKEN_END":", iv_base64);
    fprintf(fp, AES_TOKEN":%s:"AES_TOKEN_END, AES_cipher_base64);
    
    //色々と初期化(何かあったら)
    free(aes_ciphertext);
    free(data_magic);
    //色々と初期化
    
    fclose(fp);
    
    
    return 0;
}


//sk_Gammaの属性集合とアクセス構造の属性rho_iを比較し、一致している行を集めた行列を作る
//アクセス構造を返す関数
AccessStructure* check_attribute_to_matrix(attribute_set *sk_Delta, AccessStructure *AS) {
    printf("calling check_attribute_to_matrix\n");
    int i = 0;
    int j, k;
    int *matched = (int*)malloc(sizeof(int)*(AS->S->row));
    if (matched == NULL) {
        printf("matched malloc error\n");
        exit(-1);
    }
    for (i = 0; i < AS->S->row; i++) {
        matched[i] = -1;
    }
    //int matched[MAX_ATTRIBUTE] = {-1};
    v_vector *v_ptr = NULL;
    v_ptr = sk_Delta->value;
    rho_i *r_ptr;
    /*rho_i *r_temp = NULL;
     rho_i *r_i;*/
    AccessStructure *aAS;
    aAS = (AccessStructure*)malloc(sizeof(AccessStructure));
    if (aAS == NULL) {
        printf("aAS malloc error\n");
        free(matched);
        exit(-1);
    }
    SpanProgram *aM; //augmented matrix
    aM = (SpanProgram*)malloc(sizeof(SpanProgram)); //mallocのエラー処理
    if (aAS == NULL) {
        printf("aAM malloc error\n");
        exit(-1);
    }
    aAS->S = aM;
    rho_i *r_temp = NULL;
    
    r_ptr = AS->rho;
    j = 0;
    while (r_ptr != NULL) {
        v_ptr = sk_Delta->value;//初期化
        
        while (v_ptr != NULL) {
            if (v_ptr == NULL || r_ptr == NULL) {
                printf("v_ptr or r_ptr null error\n");
            }
            if (v_ptr->t == r_ptr->t) {
                if (r_ptr->is_negated == TRUE) {
                    if (v_ptr->x_t[1] != r_ptr->v_t[0]) {
                        //matched[i] = j;
                        matched[j] = 1;
                        r_ptr->v_t[0] = r_ptr->v_t[0] - v_ptr->x_t[1];
                        r_ptr = r_ptr->next;
                        j++;
                        break;
                    }
                }
                else { //is_negated == FALSE
                    if (v_ptr->x_t[1] == r_ptr->v_t[0]) {
                        //matched[i] = j;
                        matched[j] = 1;
                        r_ptr = r_ptr->next;
                        j++;
                        break;
                    }
                }
            }
            
            
            v_ptr = v_ptr->next;
        }
        if (v_ptr == NULL) {
            j++;
            r_ptr = r_ptr->next;
        }
        
    }
    
    
    aAS->num_policy = AS->num_policy;
    aAS->rho = AS->rho;
    
    /*aAS->num_policy = i;*/
    
    aM->row = AS->S->row;
    aM->column = AS->S->column;
    aM->M = (mpz_t**)malloc(sizeof(mpz_t*)*aM->row); //エラー処理
    for (j = 0; j < aM->row; j++) {
        //matchedの有無を確認
        aM->M[j] = (mpz_t*)malloc(sizeof(mpz_t)*aM->column);
        if (matched[j] < 0) {
            for (k = 0; k < aM->column; k++) {
                mpz_init(aM->M[j][k]);
            }
        }
        else {
            for (k = 0; k < aM->column; k++) {
                mpz_init_set(aM->M[j][k], AS->S->M[j][k]);
            }
        }
        
    }
    //debag
    printf("\nprintf spanprogram\n");
    print_spanprogram(aM);
    
    return aAS;
}



//スパンプログラムを変形してalpha_iを求めていく
mpz_t *calc_alpha_i(AccessStructure *AS, mpz_t order) {
    int i, j, k, l;
    int row = AS->S->row;
    int column = AS->S->column;
    int all_zero = 0;
    mpz_t tmp, tmp2, tmp3;
    mpz_init(tmp);
    mpz_init(tmp2);
    mpz_init(tmp3);
    mpz_t *row_tmp = NULL;
    
    mpz_t *a_tmp = (mpz_t*)malloc(sizeof(mpz_t)*row);
    mpz_t *b_tmp = (mpz_t*)malloc(sizeof(mpz_t)*row);
    mpz_t *c_tmp = (mpz_t*)malloc(sizeof(mpz_t)*row);
    mpz_t *d_tmp = (mpz_t*)malloc(sizeof(mpz_t)*row);
    mpz_t *alpha_i = (mpz_t*)malloc(sizeof(mpz_t)*row);
    if (alpha_i == NULL) return NULL;
    for (i = 0; i < row; i++) {
        mpz_init(a_tmp[i]);
        mpz_init(b_tmp[i]);
        mpz_init(c_tmp[i]);
        mpz_init(d_tmp[i]);
        mpz_init(alpha_i[i]);
    }
    
    //alpha_iの係数になる行列をつくる
    mpz_t **matrix = (mpz_t**)malloc(sizeof(mpz_t*)*row);
    if (matrix == NULL) {
        free(alpha_i);
        return NULL;
    }
    for (i = 0; i < row; i++) {
        matrix[i] = (mpz_t*)malloc(sizeof(mpz_t)*row);
        if (matrix[i] == NULL) {
            for (j = 0; j < i; j++) {
                free(matrix[j]);
                free(matrix);
                free(alpha_i);
                return NULL;
            }
        }
        for (k = 0; k < row; k++) {
            if (i == k) mpz_init_set_ui(matrix[i][k], 1);
            else mpz_init_set_ui(matrix[i][k], 0);
        }
    }
    
    
    //どこかでall_one判定
    
    for (i = 0; i < column; i++) {
        for (j = 0; j < row; j++) {
            all_zero = 0;
            //非0の要素を見つけてそこを残すように消していく
            //消したら次の列へ→i++
            if (mpz_cmp_ui(AS->S->M[j][i], 0) == 0) continue;//これはいいはず
            for (k = 0; k < i; k++) {//他の列ですでに利用していないか
                if (mpz_cmp_ui(AS->S->M[j][k], 0) != 0) all_zero = 1;
            }
            if (all_zero) {
                continue;
            }
            
            for (k = 0; k < row; k++) {
                if (j == k) continue;
                mpz_set(tmp2, AS->S->M[j][i]);
                mpz_set(tmp3, AS->S->M[k][i]);
                
                
                for (l = 0; l < column; l++) {
                    mpz_mul(a_tmp[l], AS->S->M[k][l], tmp2);
                    mpz_mul(b_tmp[l], AS->S->M[j][l], tmp3);
                    mpz_sub(AS->S->M[k][l], a_tmp[l], b_tmp[l]);
                }
                for (l = 0; l < row; l++) {
                    mpz_mul(c_tmp[l], matrix[k][l], tmp2);
                    mpz_mul(d_tmp[l], matrix[j][l], tmp3);
                    mpz_sub(matrix[k][l], c_tmp[l], d_tmp[l]);
                }
            }
        }
    }
    
    
    
    int a, b;
    printf("matrix = \n");
    for (a = 0; a < row; a ++) {
        for (b = 0; b < row; b++) {
            gmp_printf("%Zd ", matrix[a][b]);
        }
        printf("\n");
    }
    
    printf("AS = \n");
    print_spanprogram(AS->S);
    
    //mpz_t column_count;
    //mpz_init(column_count);
    int column_count = 0;
    int *column_check = (int*)malloc(sizeof(int)*column);
    for (i = 0; i < column; i++) {
        column_check[i] = 0;
    }
    
    while (column - column_count != 0) {
        for (i = 0; i < row; i++) {
            if (mpz_cmp_ui(AS->S->M[i][column_count], 0)==0) {
                continue;
            }
            else {
                if (column_check[column_count]) continue;
                mpz_invert(tmp, AS->S->M[i][column_count], order);
                for (j = 0; j < row; j++) {
                    mpz_mul(tmp2, tmp, matrix[i][j]);
                    mpz_add(tmp3, alpha_i[j], tmp2);
                    mpz_mod(alpha_i[j], tmp3, order);
                }
                //column_check[i] = 1;
                column_check[column_count] = 1;
            }
        }
        column_count++;
    }
    
    printf("\nalpha_i = ");
    for (i = 0; i < row; i++) {
        gmp_printf("%Zd ", alpha_i[i]);
    }
    printf("\n");
    
    free(column_check);
    free(d_tmp);
    free(c_tmp);
    free(b_tmp);
    free(a_tmp);
    mpz_clear(tmp3);
    mpz_clear(tmp2);
    mpz_clear(tmp);
    
    
    
    return alpha_i;
}




