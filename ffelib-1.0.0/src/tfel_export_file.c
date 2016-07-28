//
//  tfel_exportfile.c
//  
//
//  Created by h_ksk on 2015/12/19.
//
//

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include "tfelib.h"
#include "tfel_matrix.h"
#include <tepla/ec.h>
#include "tfel_attribute.h"
//#include "att_list.h"

void tfel_export_public_params(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...);
void tfel_basis_to_buffer(unsigned char *buffer, basis *Basis, size_t max_len,  size_t *result_len);
void tfel_basis_list_to_buffer(basis *basis_list, unsigned char *buf_ptr, size_t max_len, size_t *result_len, int num_att, int Star);
void tfel_export_secret_params(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...);
void tfel_export_sk_Gamma(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...);
void tfel_kStar_to_buffer(basis *basis_list, unsigned char *buffer, size_t max_len, size_t *result_len, int max_num);
void tfel_clear_pk(uint32 d, tfel_pubkey *pk);
void tfel_clear_sk(uint32 d, tfel_masterkey *sk);


void tfel_export_public_params(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...) {
    va_list comp_list;
    unsigned char *buf_ptr = buffer;
    char *fmt_ptr;
    int *num_att;
    tfel_param_n *param_n;
    //unsigned char *element_temp;
    
    basis *basis_list;
    
    size_t temp = 0;
    size_t *result;
    result = result_len;
    
    *result_len = 0;
    
    va_start(comp_list, fmt);
    
    for(fmt_ptr = fmt; *fmt_ptr != '\0'; fmt_ptr++) {
        if(*fmt_ptr != '%') continue;
        
        if(buffer != NULL) buf_ptr = (unsigned char*)(buffer + *result_len);
        
        switch(*++fmt_ptr) {
            case 'd':
                *result_len += sizeof(int);
                num_att = va_arg(comp_list, int*);
                if(buffer != NULL && *result_len <= max_len) {
                    *((int*)buf_ptr) = *num_att;
                }
                //printf("result_len = %d\n", (int)*result_len);
                break;
            case 'B':
                basis_list = va_arg(comp_list, basis*);
                buf_ptr = buffer;
                tfel_basis_list_to_buffer(basis_list, buf_ptr, max_len, result_len, *num_att, 0); //Bhat
                //tfel_basis_list_to_buffer(basis_list, buf_ptr, result_len, *num_att, 1); //BhatStar
                break;
            case 'n':
                //param_V serialize
                param_n = va_arg(comp_list, tfel_param_n*);
                //basis A, AStar serialize
                //とりあえずいったん実行しないでおく
                //tfel_basis_to_buffer(buf_ptr, &param_n->param_V->A, max_len,  result_len);
                //tfel_basis_to_buffer(buf_ptr, &param_n->param_V->AStar, max_len,  result_len);
                //EC_PARING serialize
                //必要だけどECBN254しかないので今は必要なし
                //EC_PARING serialize
                //gT serialize
                int el_length = element_get_oct_length(param_n->gT);
                *result_len += sizeof(el_length);
                if(buffer != NULL && *result_len <= max_len) {
                    *(int*)buf_ptr = el_length;
                    buf_ptr = (unsigned char*)(buffer + *result_len);
                }
                *result_len += el_length;
                if(buffer != NULL && *result_len <= max_len) {
                    element_to_oct(buf_ptr, &temp, param_n->gT);
                }
                break;
        }
    }
}

void tfel_basis_to_buffer(unsigned char *buffer, basis *Basis, size_t max_len,  size_t *result_len) {
    int i, j;
    unsigned char *buf_ptr = buffer;
    //*result_len = 0;
    int size;
    size_t length;
    size_t *length_temp = &length;
    
    *result_len += sizeof(int);
    if (buffer != NULL) {
        *((int*)buf_ptr) = Basis->dim; //???????
    }
    
    for( i = 0; i < Basis->dim; i++) {
        for( j = 0; j < Basis->dim; j++) {
            if (buffer != NULL && *result_len <= max_len) {
                buf_ptr = (unsigned char*)(buffer + *result_len);
            }
            size = point_get_oct_length(Basis->M[i][j]);
            *result_len += (sizeof((size_t)size));//sizeの値もserialize
            *result_len += (size_t)size;
            
            if (buffer != NULL && *result_len <= max_len) {
                *((size_t*)buf_ptr) = (size_t)size;
                buf_ptr += (sizeof((size_t)size));
                point_to_oct(buf_ptr, length_temp, Basis->M[i][j]); //sizeとlengthの値が一緒か後で確認
            }
        }
    }
}

void tfel_basis_list_to_buffer(basis *basis_list, unsigned char *buffer, size_t max_len, size_t *result_len, int num_att, int Star) {
    int t, i, j, k;
    unsigned char *buf_ptr = buffer;
    int size = 0;
    size_t length;
    size_t *length_temp = &length;
    
    
    if(basis_list == NULL) {
        printf("invalid basis input\n");
        return;
    }
    
    for(i = 0; i < num_att; i++) {
        if (i == 0 || Star == 0) t = 3;
        else t = 4;
        for(j = 0; j < t; j++) {
            for(k = 0; k < basis_list[i].dim; k++) {
                if (buffer != NULL && *result_len <= max_len) {
                    buf_ptr = (unsigned char*)(buffer + *result_len);
                }
                size = point_get_oct_length(basis_list[i].M[j][k]);
                *result_len += sizeof(int);
                
                if (buffer != NULL && *result_len <= max_len) {
                    *((int*)buf_ptr) = size;
                    buf_ptr = (unsigned char*)(buffer + *result_len);
                    point_to_oct(buf_ptr, length_temp, basis_list[i].M[j][k]); //sizeとlengthの値が一緒か後で確認→ok
                }
                *result_len += (size_t)size;//point_octの配列の長さ(size)
            }
        }
    }
}

void tfel_export_secret_params(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...) {
    va_list comp_list;
    unsigned char *buf_ptr = buffer;
    char *fmt_ptr;
    int *num_att;
    
    basis *basis_list;
    size_t *result;
    result = result_len;
    
    *result_len = 0;
    
    va_start(comp_list, fmt);
    
    for(fmt_ptr = fmt; *fmt_ptr != '\0'; fmt_ptr++) {
        if(*fmt_ptr != '%') continue;
        
        if(buffer != NULL) buf_ptr = (unsigned char*)(buffer + *result_len);
        
        switch(*++fmt_ptr) {
            case 'd':
                *result_len += sizeof(int);
                num_att = va_arg(comp_list, int*);
                if(buffer != NULL && *result_len <= max_len) {
                    *(int*)buf_ptr = *num_att;
                }
                break;
            case 'B':
                basis_list = va_arg(comp_list, basis*);
                buf_ptr = buffer;
                //tfel_basis_list_to_buffer(basis_list, buf_ptr, max_len, result_len, *num_att, 0); //Bhat
                tfel_basis_list_to_buffer(basis_list, buf_ptr, max_len, result_len, *num_att, 1); //BhatStar
                break;
        }
    }
}

//余裕を見てtfel_export_secret_paramsと統合したい
void tfel_export_sk_Gamma(unsigned char *buffer, size_t max_len, size_t *result_len, char *fmt, ...) {
    va_list comp_list;
    unsigned char *buf_ptr = buffer;
    char *fmt_ptr;
    int *max_num;
    v_vector *vector_ptr;
    
    basis *basis_list;
    size_t *result;
    result = result_len;
    
    *result_len = 0;
    
    va_start(comp_list, fmt);
    
    for(fmt_ptr = fmt; *fmt_ptr != '\0'; fmt_ptr++) {
        if(*fmt_ptr != '%') continue;
        
        if(buffer != NULL) buf_ptr = (unsigned char*)(buffer + *result_len);
        
        switch(*++fmt_ptr) {
            case 'd':
                *result_len += sizeof(int);
                max_num = va_arg(comp_list, int*);
                if(buffer != NULL && *result_len <= max_len) {
                    *(int*)buf_ptr = *max_num;
                }
                break;
            case 'v':
                *result_len += sizeof(int)*(*max_num);
                vector_ptr = va_arg(comp_list, v_vector*);
                if(buffer != NULL && *result_len <= max_len) {
                    while (vector_ptr != NULL) {
                        *(int*)buf_ptr = vector_ptr->x_t[1];
                        buf_ptr += sizeof(int);
                        vector_ptr = vector_ptr->next;
                    }
                }
                break;
            case 'B':
                basis_list = va_arg(comp_list, basis*);
                buf_ptr = buffer;
                tfel_kStar_to_buffer(basis_list, buf_ptr, max_len, result_len, *max_num); //bStar
                break;
        }
    }
}

//余裕を見てtfel_basis_list_to_bufferと統合したい
void tfel_kStar_to_buffer(basis *basis_list, unsigned char *buffer, size_t max_len, size_t *result_len, int max_num) {
    int t, i, j;
    unsigned char *buf_ptr = buffer;
    int size = 0;
    size_t length;
    size_t *length_temp = &length;
    
    if(basis_list == NULL) {
        printf("invalid basis input\n");
        return;
    }
    for(i = 0; i < max_num; i++) {
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
    }
}


void tfel_clear_pk(uint32 d, tfel_pubkey *pk) {
    int i,j,k;
    for (i = 0; i < d; i++) {
        for (j = 0; j < 3; j++) {
            if (i == 0) {
                for (k = 0; k < 5; k++) {
                    point_clear(pk->Bhat[i].M[j][k]);
                }
            }
            else {
                for (k = 0; k < 7; k++) {
                    point_clear(pk->Bhat[i].M[j][k]);
                }
            }
            free(pk->Bhat[i].M[j]);
        }
    }
    free(pk->Bhat);
}

void tfel_clear_sk(uint32 d, tfel_masterkey *sk) {
    int i, j, k;
    for (i = 0; i < d; i++) {
        for (j = 0; j < 3; j++) {
            if (i == 0) {
                for (k = 0; k < 5; k++) {
                    point_clear(sk->BStarhat[i].M[j][k]);
                }
            }
            else {
                for (k = 0; k < 7; k++) {
                    point_clear(sk->BStarhat[i].M[j][k]);
                }
            }
            free(sk->BStarhat[i].M[j]);
        }
    }
    free(sk->BStarhat);
}