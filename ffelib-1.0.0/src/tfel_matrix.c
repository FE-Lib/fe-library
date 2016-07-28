/*
 * tfel_matrix.c
 *
 *  Created on: 2014/06/08
 *      Author: h_ksk
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "tfelib.h"
#include "tfel_matrix.h"


//generate Xt
matrix *tfel_gen_general_linear_groups(const uint32 N, const EC_PAIRING p, gmp_randstate_t s)
{
    int i, j;
	mpz_t order;
	mpz_init(order);
	mpz_set(order, *pairing_get_order(p));

	matrix *D;
	D = tfel_matrix_init(N);
	for (i = 0; i < D->dim; i++) {
		for (j = 0; j < D->dim; j++) {
			mpz_urandomm(D->M[i][j], s, order);
		}
	}
	return D;
}

//generate theta


//入力の行列の逆行列を返す
//対角成分が0の場合考える
matrix *tfel_invert(const matrix *D, const EC_PAIRING p) {
    int i, j, k, l;
	mpz_t order;
	mpz_init(order);
	mpz_set(order, *pairing_get_order(p));

	matrix *temp1, *inv;

	//逆行列求める行列のコピー
	temp1 = tfel_matrix_copy(D);
	//ここに逆行列が入る
	inv = tfel_matrix_init(D->dim);
	for(i = 0; i < D->dim; i++) {
		mpz_set_str(inv->M[i][i], "1", 10);
	}

	//一時的なデータを蓄える
	mpz_t buf1, buf2, buf3, buf4, *temp_v1, *temp_v2;
	mpz_init(buf1);
	mpz_init(buf2);
	mpz_init(buf3);
	mpz_init(buf4);
	temp_v1 = (mpz_t*)malloc(sizeof(mpz_t)*temp1->dim);
	temp_v2 = (mpz_t*)malloc(sizeof(mpz_t)*temp1->dim);

	for(i = 0; i < temp1->dim; i++) {
		mpz_init(temp_v1[i]);
		mpz_init(temp_v2[i]);
	}

	//すごく汚い掃き出し法
	for(i=0; i < temp1->dim; i++) {
		mpz_invert(buf1, temp1->M[i][i], order); //j行j列の乗法の逆元求める(1)

		for(j=0; j < temp1->dim; j++) {
			mpz_mul(buf2, buf1, temp1->M[i][j]);
			mpz_set(temp1->M[i][j], buf2); //(1)をi行全体にかける(2)
			//mpz_set(temp_v1[j], buf2); //(2)のコピー
			mpz_mod(temp_v1[j], buf2, order);

			mpz_mul(buf2, buf1, inv->M[i][j]);
			mpz_set(inv->M[i][j], buf2); //単位行列の方にも同様の操作
			//mpz_set(temp_v2[j], buf2);
			mpz_mod(temp_v2[j], buf2, order);
		} //ここまでokだと思う……

		for(k=0; k < temp1->dim; k++) {
			if(i == k) continue;
			//element_neg(buf1, temp1->M[k][i]); //i行以外の行のj列の加法の逆元求める(3)
			mpz_neg(buf1, temp1->M[k][i]);
			for(l=0; l < temp1->dim; l++) {
				mpz_mul(buf3, buf1, temp_v1[l]); //(3)×(2)
				mpz_add(buf4, buf3, temp1->M[k][l]); //(4)
				mpz_set(temp1->M[k][l], buf4);

				mpz_mul(buf3, buf1, temp_v2[l]);
				mpz_add(buf4, buf3, inv->M[k][l]);
				mpz_mod(inv->M[k][l], buf4, order); //単位行列の方にも同様の操作
			}
		}
	}

	//invert check→ok!!
			mpz_t temp_1, temp_2, result;
			mpz_init(temp_1);
			mpz_init(temp_2);

			for(k = 0; k < D->dim; k++) {
				for(i = 0; i < D->dim; i++) {
					mpz_init_set_ui(result, 0);
					for(j = 0; j < D->dim; j++) {
						mpz_mul(temp_1, D->M[k][j], inv->M[j][i]);
						mpz_add(temp_2, temp_1, result);
						mpz_mod(result, temp_2, order);
					}
					if(k == i) {
						if(mpz_get_ui(result) != 1) {
							printf("error\n");
							goto clear;
						}
					}
					else {
						if(mpz_get_ui(result) != 0) {
							printf("error\n");
							goto clear;
						}
					}
				}
			}
clear:
			mpz_clear(temp_1);
			mpz_clear(temp_2);
			mpz_clear(result);
			//invert check

	mpz_clear(order);
	mpz_clear(buf1);
	mpz_clear(buf2);
	mpz_clear(buf3);
	mpz_clear(buf4);
	for(i=0; i < temp1->dim; i++) {
		mpz_clear(temp_v1[i]);
		mpz_clear(temp_v2[i]);
	}
	free(temp_v1);
	free(temp_v2);
	tfel_matrix_clear(temp1);
	return inv;
}

matrix *tfel_transpose(const matrix *D) {
    int i, j;
    matrix *inv;

	inv = tfel_matrix_init(D->dim);
	for(i = 0; i < D->dim; i++) {
		for(j = 0; j < D->dim; j++) {
			mpz_set(inv->M[i][j], D->M[j][i]);
		}
	}
	return inv;
}

//行列の初期化
matrix *tfel_matrix_init(const uint32 N) {
    int i, j;
	matrix *D;
	D = (matrix*)malloc(sizeof(matrix));
	D->dim = N;
	D->M = (mpz_t**)malloc(sizeof(mpz_t*)*N);
	if(D->M == NULL) {
		printf("malloc failed\n");
		exit(1);
	}

	for(i = 0; i < N; i++) {
		D->M[i] = (mpz_t*)malloc(sizeof(mpz_t)*N);
		if(D->M[i] == NULL) {
			printf("malloc failed\n");
			exit(1);
		}
	}


	for(i = 0; i < N; i++) {
		for(j = 0; j < N; j++) {
			mpz_init(D->M[i][j]);
		}
	}

	return D;
}

//行列の配列を作る
matrices *tfel_matrices_init(const uint32 N, matrices *array_D, const Field f) {
    int i;
	//定義されてるところでmalloc
	//array_D = (matrices*)malloc(sizeof(matrix)*N);

	for(i = 0; i < N; i++) {
		//array_D[i] = (matrix*)malloc(sizeof(matrix)*N);
		array_D[i] = tfel_matrix_init(N);
	}
	return array_D;
}

void tfel_matrix_clear(matrix *D) {
    int i, j;
    
	for(i = 0; i < D->dim; i++) {
		for(j = 0; j < D->dim; j++) {
			mpz_clear(D->M[i][j]);
		}
	}
	free(D->M);
	free(D);
}

//入力の行列のコピーを返す
matrix *tfel_matrix_copy(const matrix *D) {
    int i, j;
	matrix *cp;
	cp = tfel_matrix_init(D->dim);
	for(i = 0; i < D->dim; i++) {
		for(j = 0; j < D->dim; j++) {
			mpz_set(cp->M[i][j], D->M[i][j]);
		}
	}
	return cp;
}

//B_t, B_t*を生成
basis tfel_linear_transformation(const matrix *D, const basis A, const EC_GROUP g) {
    int i, j;
	EC_POINT temp1, temp2, temp3;
	EC_POINT *temp;
	temp = (EC_POINT*)malloc(sizeof(EC_POINT)*D->dim);

	for(i = 0; i < D->dim; i++) {
		point_init(temp[i], g);
	}
	point_init(temp1, g);
	point_init(temp2, g);
	point_init(temp3, g);
	point_set_infinity(temp2);
	//matrix *B;

	basis B;
	B.dim = D->dim;
	B.M = (EC_POINT**)malloc(sizeof(EC_POINT*)*D->dim);
	for(i = 0; i < D->dim; i++) {
		B.M[i] = (EC_POINT*)malloc(sizeof(EC_POINT)*D->dim);
		for(j = 0; j < D->dim; j++) {
			point_init(B.M[i][j], g);
		}
	}

	for(i = 0; i < D->dim; i++) {
		for(j = 0; j < D->dim; j++) {
			point_mul(B.M[i][j], D->M[i][j], A.M[i][i]);
		}
	}

	return B;
}
