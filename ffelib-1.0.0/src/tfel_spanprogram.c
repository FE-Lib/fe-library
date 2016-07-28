/*
 * SpanProgram.c
 *
 *  Created on: 2014/11/21
 *      Author: h_ksk
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tfel_spanprogram.h"
#include "attribute_policy.h"
#include <glib.h>

policy_attribute_list *tfel_policy_create_leaf(char *category, char *value, Bool is_negated);
policy_attribute_list *tfel_policy_create_node(ATTRIBUTE_NODE_TYPE node_type, int num_subnodes, int threshold, policy_attribute_list** subnodes);
void tfel_policy_clear(policy_attribute_list *policy);
int t_nSpanprogram_gen(SpanProgram *S, int t, int n);
int insert_Spanprogram(SpanProgram *S1, SpanProgram *S2, int n);
void Spanprogram_clear(SpanProgram *S); //for debag

void print_spanprogram(SpanProgram *S);

int rank(SpanProgram *SP);
int check_rank_of_matrix(SpanProgram *SP);
int modify_matrix(attribute_set *sk_Delta, SpanProgram *SP);

//復号条件の最小単位。カテゴリとバリュとneg情報の構造体を生成
policy_attribute_list *tfel_policy_create_leaf(char *category, char *value, Bool is_negated) {
	policy_attribute_list *leaf;
	policy_attribute *att;

	if (strlen(category+1) > MAX_ATTRIBUTE_STR || strlen(value+1) > MAX_ATTRIBUTE_STR) {
		return NULL;
	}

	leaf = (policy_attribute_list*)malloc(sizeof(policy_attribute_list));
	if (leaf == NULL) return NULL;
	memset(leaf, 0, sizeof(policy_attribute_list));
	att = (policy_attribute*)malloc(sizeof(policy_attribute));
	if (att == NULL) {
		free(leaf);
		return NULL;
	}

	leaf->node_type = ATTRIBUTE_POLICY_LEAF;
	leaf->policy = NULL;
	leaf->attribute = att;
	leaf->num_policy_att = 1;
	leaf->threshold = 1;

	strcpy(leaf->attribute->category_str, category);
	strcpy(leaf->attribute->value_str, value);
	leaf->attribute->is_negated = is_negated;

	return leaf;
}

//subnodesを子ノードとして新しいノードを作成する
policy_attribute_list *tfel_policy_create_node(ATTRIBUTE_NODE_TYPE node_type, int num_subnodes, int threshold, policy_attribute_list** subnodes) {
	int i;
	policy_attribute_list *node;
	node = (policy_attribute_list*)malloc(sizeof(policy_attribute_list));
	if (node == NULL) return NULL;
	node->node_type = node_type;
	node->attribute = NULL;
	node->policy = (policy_attribute_list*)malloc(sizeof(policy_attribute_list)*num_subnodes);
	node->threshold = threshold;
	//node->policy = *subnodes;
	if (node->policy == NULL) return NULL;
	for (i = 0; i < num_subnodes; i++) {
		node->policy[i] = subnodes[i][0]; //こういうことだよね？
	}
	node->num_policy_att = num_subnodes;
	//挿入したsubnodesは開放する？→しない

	return node;
}

void tfel_policy_clear(policy_attribute_list *policy) {
	int i, num;
	if (policy == NULL) return;
	num = policy->num_policy_att;
	//printf("policy->node_type = %d, num_subnode = %d\n", policy->node_type, policy->num_policy_att);
	switch (policy->node_type) {
	case 0:
		break;
	case 1:
		for(i = 0; i < num; i++) {
			memset(policy->attribute[i].category_str, 0, MAX_ATTRIBUTE_STR);
			memset(policy->attribute[i].value_str, 0, MAX_ATTRIBUTE_STR);
			policy->attribute[i].is_negated = 0;
			free(&policy->attribute[i]);
		}
		break;
	default:
		for(i = 0; i < num; i++) {
			tfel_policy_clear(&policy->policy[i]);
			policy->policy[i].node_type = 0;
			policy->num_policy_att = 0;
		}
		free(policy->policy);
		break;
	}

	return;
}

//t-out-of-nのしきい値のアクセス構造を構成する
//mallocエラーの時の処理も書く
int t_nSpanprogram_gen(SpanProgram *S, int t, int n) {
//int t_nSpanprogram_gen(mpz_t ***M, int t, int n) {
	int i, j;
	mpz_t temp;
	mpz_init(temp);
	S->row = n;
	S->column = t;

	if (NULL == (S->M = (mpz_t**)malloc(sizeof(mpz_t*)*n))) {
		exit(-1);
	}
	for (i = 0; i < n; i++) {
		if (NULL == (S->M[i] = (mpz_t*)malloc(sizeof(mpz_t)*t))) {
			exit(-1);
		}
		for (j = 0; j < t; j++) {
			mpz_init(S->M[i][j]);
			mpz_set_ui(temp, i+1);
			mpz_pow_ui(S->M[i][j], temp, j);
		}
	}

	mpz_clear(temp);
	return 0;
}

//n行目に挿入する。0行目がある場合はn+1で指定
int insert_Spanprogram(SpanProgram *S1, SpanProgram *S2, int n) {
	int i, j;
	int r, c;
	if (S1->row < n) {
		printf("insert argument n error\n");
		exit(-1);
	}
	r = S1->row + S2->row - 1; //row of inserted matrix
	c = S1->column + S2->column -1; //column of inserted matrix
	//printf("r = %d, c = %d\n", r, c);

	mpz_t **M;
	//initialize inserted matrix
	if (NULL == (M = (mpz_t**)malloc(sizeof(mpz_t*)*r))) {
		exit(-1);
	}

	for (i = 0; i < r; i++) {
		if (NULL == (M[i] = (mpz_t*)malloc(sizeof(mpz_t)*c))) {
			exit(-1);
		}
		for (j = 0; j < c; j++) {
			mpz_init(M[i][j]);
			if (j == 0) mpz_set_ui(M[i][j], 1);
		}
	}
	//initialize inserted matrix

	//insert
	for (i = 0; i < r; i++) {
		if (i < n-1) {
			for (j = 1; j < S1->column; j++) {
				mpz_set(M[i][j], S1->M[i][j]);
			}
		}
		else if (i >= n-1 && i < n-1 + S2->row) {
			for (j = 1; j < c; j++) {
				if (j < S1->column) mpz_set(M[i][j], S1->M[n-1][j]);
				else mpz_set(M[i][j], S2->M[i-(n-1)][(j+1)-S1->column]);
			}
		}
		else {
			for (j = 1; j < S1->column; j++) {
				mpz_set(M[i][j], S1->M[i-(S2->row-1)][j]);
			}
		}
	}
	//insert

	Spanprogram_clear(S1);
	S1->M = M;
	S1->row = r;
	S1->column = c;

//debag
	printf("\ninserted\n");
	print_spanprogram(S1);
	printf("\n");
//debag

	//消去は後でまとめて
	//Spanprogram_clear(S1);
	//Spanprogram_clear(S2);


	return 0;
}

//こっちの関数は消去して上のを利用
//行列の挿入
//A1のMのr行目にA2のMを挿入する、挿入後M1,M2は開放
//M2はここで開放するか外で開放するか考える
/*int insert_Spanprogram(AccessStructure *A1, AccessStructure *A2, int r) {
	int i, j;
	int r1 = A1->S.row + A2->S.row - 1;
	int c1 = A1->S.column + A2->S.column - 1;
	mpz_t **M;

	if (NULL == (M = (mpz_t**)malloc(sizeof(mpz_t*)*r1))) {
		exit(-1);
	}
	for (i = 0; i < r1; i++) {
		if (NULL == (M[i] = (mpz_t*)malloc(sizeof(mpz_t)*c1))) {
			exit(-1);
		}
		for (j = 0; j < c1; j++) {
			mpz_init(M[i][j]);
		}
	}

	for (i = 0; i < r1; i++) {
		for (j = 0; j < c1; j++) {
			if (i >= r && i <= (r + A2->S.row)) {
				if (j < A1->S.column) mpz_set(M[i][j], A1->S.M[r][j]);
				else mpz_set(M[i][j], A2->S.M[i-r][j-A1->S.column+1]);
			}
			else if (i < r || i > (r + A2->S.row)){
				if (j < A1->S.column) mpz_set(M[i][j], A1->S.M[i][j]);
			}
		}
	} //ここまで行列の挿入

	//ここから挿入された行列をA1につける

	Spanprogram_clear(A1->S.M, A1->S.row, A1->S.column);
	A1->S.M = M;
	A1->S.row = r1;
	A1->S.column = c1;
	Spanprogram_clear(A2->S.M, A2->S.row, A2->S.column);
	A2->S.M = NULL;
	//A2はここでSとかも全部消していこう


	return 0;
}*/

//行列の開放
//引数をaccessstructure一つだけにするのもありか
//void Spanprogram_clear(mpz_t **M, int m, int n) {
void Spanprogram_clear(SpanProgram *S) {
	int i, j;
	for (i = 0; i < S->row; i++) {
		for (j = 0; j < S->column; j++) {
			mpz_clear(S->M[i][j]);
		}
		free(S->M[i]);
		S->M[i] = NULL;
	}
	free(S->M);
	S->M = NULL;

	return;
}

//for debag
void print_spanprogram(SpanProgram *S) {
	int i, j;
	for (i = 0; i < S->row; i++) {
		for (j = 0; j < S->column; j++) {
			gmp_printf("%Zd ", S->M[i][j]);
		}
		printf("\n");
	}
	return;
}
/*
SpanProgram *init_Spanprogram(int row, int column) {
    int i, j;
    SpanProgram *SP = (SpanProgram*)malloc(sizeof(SpanProgram));
    if (SP == NULL) return NULL;
    
    SP->row = row;
    SP->column = column;
    SP->M = (mpz_t**)malloc(sizeof(mpz_t*)*row);
    if (SP->M == NULL) {
        free(SP);
        return NULL;
    }
    
}
*/

//rank()の引数がポインタのもの
int rank(SpanProgram *SP){
    int i, j, k;
    mpz_t tmp;
    mpz_t *ltmp = NULL, *a_tmp = NULL, *b_tmp = NULL;
    ltmp = (mpz_t*)malloc(sizeof(mpz_t)*SP->column);
    a_tmp = (mpz_t*)malloc(sizeof(mpz_t)*SP->column);
    b_tmp = (mpz_t*)malloc(sizeof(mpz_t)*SP->column);
    mpz_init(tmp);
    for (i = 0; i < SP->column; i++) {
        mpz_init(ltmp[i]);
        mpz_init(a_tmp[i]);
        mpz_init(b_tmp[i]);
    }
    int n = SP->row;
    int m = SP->column;
    int count;
    int all_zero;
    
    for(i = 0; i < n; i++){
        all_zero = 0;
        if(SP->M[i][i] == 0){
            for(j = 0; j < m; j++){
                if(SP->M[j][i] != 0){
                    for(k = 0; k < n; k++){
                        mpz_set(tmp, SP->M[i][k]);
                        mpz_set(SP->M[i][k], SP->M[j][k]);
                        mpz_set(SP->M[j][k], tmp);
                    }
                } else if(j == n - 1)
                    all_zero = 1;
            }
        }
        
        
        
        if(!all_zero){
            for(j = i + 1; j < n; j++){
                for(k = 0; k < m; k++){
                    mpz_mul(a_tmp[k], SP->M[i][k], SP->M[j][i]);
                    mpz_mul(b_tmp[k], SP->M[j][k], SP->M[i][i]);
                }
                for(k = 0; k < n; k++)
                    mpz_sub(SP->M[j][k], b_tmp[k], a_tmp[k]);
            }
        }
    }
    
    /*for (i = 0; i < SP->row; i++) {
     mpz_set(tmp, SP->M[i][i]);
     if (mpz_cmp_ui(SP->M[i][i], 0)) {//i行i列目が0の場合、行の入れ替え
     for (j = 0; j < SP->row; j++) {
     if (mpz_cmp_ui(SP->M[j][i], 0)) {
     if (j == SP->row-1) all_zero = 1;
     }
     else {
     for(k = 0; k < SP->column; k++){
     mpz_set(tmp, SP->M[i][k]);
     mpz_set(SP->M[i][k], SP->M[j][k]);
     mpz_set(SP->M[j][k], tmp);
     }
     }
     }
     }
     if (!all_zero) {
     continue;
     }
     for (j = 0; j < SP->row; j++) {
     if (i == j) continue;
     for (k = 0; k < SP->column; k++) {
     mpz_mul(a_tmp[k], SP->M[j][k], SP->M[i][i]);
     mpz_mul(b_tmp[k], SP->M[i][k], SP->M[j][i]);
     }
     for (k = 0; k < SP->column; k++) {
     mpz_sub(SP->M[j][k], b_tmp[k], a_tmp[k]);
     }
     }
     }
     */
    
    count = 0;
    for (i = 0; i < SP->row; i++){
        for (j = 0; j < SP->column; j++) {
            if (mpz_cmp_ui(SP->M[i][j], 0)) {
                count++;
                break;
            }
        }
    }
    
    mpz_clear(tmp);
    for (i = 0; i < SP->column; i++) {
        mpz_clear(ltmp[i]);
        mpz_clear(a_tmp[i]);
        mpz_clear(b_tmp[i]);
    }
    free(ltmp);
    free(a_tmp);
    free(b_tmp);
    
    return (count);
}


int check_rank_of_matrix(SpanProgram *SP) {
    //SPの階数とSPに1ベクトルを最終行に追加した行列SP'の階数が一致するかどうか確かめる
    //SP'を作ってrank(SP)?=rank(SP')でおｋ
    int i, j, k;
    SpanProgram *SP2 = NULL;
    SP2 = (SpanProgram*)malloc(sizeof(SpanProgram));
    if (SP2 == NULL) return -1;
    SP2->column = SP->column;
    SP2->row = SP->row+1;
    SP2->M = (mpz_t**)malloc(sizeof(mpz_t*)*SP2->row);
    if (SP2->M == NULL) {
        free(SP2);
        return -1;
    }
    for (i = 0; i < SP2->row; i++) {
        SP2->M[i] = (mpz_t*)malloc(sizeof(mpz_t)*SP2->column);
        if (SP2->M[i] == NULL) {
            for (j = 0; j < i; j++) {
                free(SP2->M[j]);
            }
            free(SP2->M);
            free(SP2);
        }
        if (i != SP2->row-1) {
            for (k = 0; k < SP2->column; k++) {
                mpz_init_set(SP2->M[i][k], SP->M[i][k]);
            }
        }
        else {
            for (k = 0; k < SP2->column; k++) {
                mpz_init_set_ui(SP2->M[i][k], 1);
            }
        }
        
    }
    
    printf("rank check\n");
    if (rank(SP) != rank(SP2)) {
        printf("can't decrypt\n");
        return -1;
    }
    
    Spanprogram_clear(SP2);
    free(SP2);
    return 0;
}

int modify_matrix(attribute_set *sk_Delta, SpanProgram *SP) {
    v_vector *v_ptr = sk_Delta->value;
    
}

