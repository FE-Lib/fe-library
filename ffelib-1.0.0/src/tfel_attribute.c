/*
 * attribute.c
 *
 *  Created on: 2014/09/10
 *      Author: h_ksk
 */

#include "csv_converter.h"
#include "tfel_attribute.h"

//#define debag 1

void import_att_list(int d, attribute_list* att_list, char *csvfile);
void export_att_list(attribute_list* att_list);
void clear_att_list(attribute_list* att_list);
void clear_value(Value* value, int all);
void clear_attribute(Attribute* attribute, int all);
void clear_att_set_value(v_vector *value);
int att_set(attribute_set *att_set, int att_num, char *inputcsv, char *useratt);

void category_add(attribute_list* att_list, char* input);
void value_add(attribute_list* att_list, char* input);
void category_del(attribute_list* att_list, char* input);
void value_del(attribute_list* att_list, char* input);
void init_vector(v_vector* vec, int t);
void attribute_search(attribute_list* att_list, attribute_set *att_set, char* category, char* value);

//今のところtest1.csvから属性リストを入力しているが、属性リストのファイル名を引数に取ろう
void import_att_list(int d, attribute_list* att_list, char *csvfile) {
	FILE *fp;
	char s[256];
	char *att;
	int i = 0;
	Attribute* att_ptr = NULL;


	if ((fp = fopen(csvfile, "r")) == NULL) {
		printf("attribute list file open error\n");
		printf("%s cannot open\n", csvfile);
		exit(-1);
	}

	att_list->cnum = d;
	Value* tail;
	att_list->attribute = malloc(sizeof(Attribute));
	att_ptr = att_list->attribute;
	att_ptr->next = NULL;
	while (fgets(s, 256, fp) != NULL) {
		if (i > d) {
			printf("number of category error\n");
			fclose(fp);
			free(att_list->attribute);
			exit(-1);
		}
		if (i > 0) {
			att_ptr->next = malloc(sizeof(Attribute));
			att_ptr = att_ptr->next;
			att_ptr->next = NULL;
		}
		att = strtok(s, ",\n");
		strcpy(att_ptr->data, att); //categoryに入れる
		att_ptr->value = malloc(sizeof(Value)); //valueのメモリ確保
		att_ptr->value->next = NULL;
		tail = att_ptr->value; //valueノードの最後のアドレスをtailに
		att_ptr->vnum = 0;
		while ((att = strtok(NULL, ",\r\n")) != NULL) { //valueをリスト構造で追加していく
			if (att_ptr->vnum > 0) {
				tail->next = malloc(sizeof(Value));
				tail = tail->next;
			}
			att_ptr->vnum++;
			strcpy(tail->data, att);
		}
		tail->next = NULL;
		/*if (strcmp(att_ptr->value->data, "\0") == 0) {
			free(att_ptr->value);
			att_ptr->value = NULL;
		}*/
		i++;
	}

	fclose(fp);

	return;
}

void export_att_list(attribute_list* att_list) {
	FILE *fp;
	if ((fp = fopen("testwrite.csv", "w")) == NULL) {
		printf("attribute list file write error\n");
		exit(-1);
	}

	Attribute* att_ptr;
	Value* value_ptr;
	att_ptr = att_list->attribute;

	while (att_ptr != NULL) {
		value_ptr = att_ptr->value;
		fprintf(fp, "%s", att_ptr->data);

		while (value_ptr != NULL) {
			fprintf(fp, ",%s", value_ptr->data);
			value_ptr = value_ptr->next;
			//if (value_ptr != NULL) fprintf(fp, "%c", ',');
		}
		fprintf(fp, "\n");
		att_ptr = att_ptr->next;
	}
	fclose(fp);
	return;
}

void clear_att_list(attribute_list* att_list) {
	if(att_list->attribute != NULL) clear_attribute(att_list->attribute, 1);
	free(att_list);
	return;
}

void clear_value(Value* value, int all) {
	if (all == 1) {
		if (value->next != NULL) clear_value(value->next, 1);
	}
	memset(value, 0, sizeof(Value));
	free(value);
	return;
}

void clear_attribute(Attribute* attribute, int all) {
	if (all == 1) {
		if (attribute->next != NULL) clear_attribute(attribute->next, 1);
	}
	if (attribute->value != NULL) clear_value(attribute->value, 1);
	memset(attribute, 0, sizeof(Attribute));
	free(attribute);
	return;
}

//att_setのvalueを消す関数、他に似たのあったら消す
void clear_att_set_value(v_vector *value) {
    if (value != NULL) clear_att_set_value(value->next);
    else free(value);
    return;
}

//属性を指定する、今のところatt_set1.txtから指定している
//voidじゃない方がいい、エラー返したりとか
//入力の属性リストはtest1.csv指定しているが、ファイル名を可変にしたらここも変える
int att_set(attribute_set *att_set, int att_num, char *inputcsv, char *useratt) {
    int i, j;
    int d = att_num;
    att_set->value = NULL;
    att_set->num = 0;
    
    char *path;
    path = inputcsv;
    
    attribute_list *list = malloc(sizeof(attribute_list));
    if (list == NULL) return -1;
    import_att_list(d, list, path);
    
    
    
    char delimit = ',';//パースの区切り文字
    
    Parsed_CSV_t parsed;
    Parsed_CSV_t *p;
    p = &parsed;
    path = useratt;
    
    if (parse_csv_file(path, delimit, p) != 0){
        printf("parse_csv_file error %d\n", parse_csv_file(path, delimit, p));
        clear_att_list(list);
        return -1;
    }
    
    v_vector *ptr = NULL, *temp = NULL;
    
    //att_list内のカテゴリ分のatt_setを生成する
    for (i = 0; i < list->cnum; i++) { //mallocで全部のカテゴリのメモリ確保
        if (i == 0) {
            att_set->value = (v_vector*)malloc(sizeof(v_vector));
            if (att_set->value == NULL) {
                clear_att_list(list);
                return -1;
            }
            init_vector(att_set->value, 0);
            ptr = att_set->value;
            att_set->num++;
        }
        else {
            ptr->next = (v_vector*)malloc(sizeof(v_vector));
            if (ptr->next == NULL) {
                clear_att_list(list);
                clear_att_set_value(att_set->value);
                return -1;
            }
            init_vector(ptr->next, i);
            ptr = ptr->next;
            att_set->num++;
        }
    }
    for (i = 0; i < parsed.line_cnt; i++) {//listは属性リスト？
        attribute_search(list, att_set, parsed.lines[i]->cols[0], parsed.lines[i]->cols[1]);
    }
    
    
    clear_att_list(list);
    
    return 0;
}


//カテゴリをリストの最後に追加
//input は"category"の形式で受け取る
//"category=value1,value2,"のような感じでもできる
void category_add(attribute_list* att_list, char* input) {
    Attribute *att_ptr;
    Value *value_ptr;
    char *category;
    char *tp;
    int i = 0;
    
    tp = strtok(input, " \"=,");
    category = malloc(sizeof(tp));
    strcpy(category, tp);
    
    att_ptr = att_list->attribute;
    while (att_ptr->next != NULL) {
        if (strcmp(att_ptr->data, category) == 0) {
            printf("category exist error\n");
            free(category);
            return;
        }
        att_ptr = att_ptr->next;
        i++;
    }
    if (att_list->cnum - 1 <= i) {
        printf("max category error\n");
        free(category);
        return;
    }
    
    att_ptr->next = malloc(sizeof(Attribute));
    att_list->cnum++;
    att_ptr = att_ptr->next;
    att_ptr->value = malloc(sizeof(Value));
    value_ptr = att_ptr->value;
    value_ptr->next = NULL;
    strcpy(att_ptr->data, category);
    tp = strtok(NULL, " ,\"");
    while (tp != NULL) {
        //if (value_ptr == NULL) value_ptr = malloc(sizeof(Value));
        strcpy(value_ptr->data, tp);
        att_ptr->vnum++;
        if ((tp = strtok(NULL, " ,\"")) != NULL) {
            value_ptr->next = malloc(sizeof(Value));
            value_ptr = value_ptr->next;
        }
    }
    /*if (strcmp(value_ptr->data, "\0") == 0) {
     free(value_ptr);
     att_ptr->value = NULL;
     }*/
    free(category);
    return;
}

//バリュをリストの最後に追加
//input は"category=value"の形式で受け取る
void value_add(attribute_list* att_list, char* input) {
    Attribute *att_ptr;
    Value *value_ptr;
    Value *temp;
    char *category;
    char *value;
    char *tp;
    
    tp = strtok(input, " \"=");
    category = malloc(sizeof(tp));
    strcpy(category, tp);
    tp = strtok(NULL, " \"=");
    value = malloc(sizeof(tp));
    strcpy(value, tp);
    
    att_ptr = att_list->attribute;
    while (att_ptr != NULL) {
        if (strcmp(att_ptr->data, category)) {
            att_ptr = att_ptr->next;
            continue;
        }
        value_ptr = att_ptr->value;
        temp = value_ptr->next;
        while (value_ptr != NULL) {
            if (temp != NULL) {
                value_ptr = value_ptr->next;
                temp = value_ptr->next;
                continue;
            }
            value_ptr->next = malloc(sizeof(Value));
            value_ptr = value_ptr->next;
            strcpy(value_ptr->data, value);
            value_ptr->next = NULL;
            att_ptr->vnum++;
            free(category);
            free(value);
            return;
        }
        att_ptr = att_ptr->next;
    }
    
    printf("input category not exit error\n");
    free(category);
    free(value);
    return;
}

//カテゴリの消去、バリュも全て消去
//input は"category"の形式で受け取る
void category_del(attribute_list* att_list, char* input) {
    Attribute *att_ptr;
    Attribute *temp;
    char *category;
    char *tp;
    
    tp = strtok(input, " \"");
    category = malloc(sizeof(tp));
    strcpy(category, tp);
    
    att_ptr = att_list->attribute;
    temp = NULL;
    while (att_ptr != NULL) {
        if (strcmp(att_ptr->data, category)) {
            temp = att_ptr;
            att_ptr = att_ptr->next;
            continue;
        }
        if (temp == NULL) att_list->attribute = att_ptr->next;
        else temp->next = att_ptr->next;
        att_ptr->next = NULL;
        clear_attribute(att_ptr, 1);
        att_list->cnum--;
        free(category);
        return;
    }
    
    printf("input category not exit error\n");
    free(category);
    return;
}

//バリュを一つ消去
//input は"category=value"の形式で受け取る
void value_del(attribute_list* att_list, char* input) {
    Attribute *att_ptr;
    Value *value_ptr;
    Value *temp;
    char *category;
    char *value;
    char *tp;
    
    tp = strtok(input, " \"=");
    category = malloc(sizeof(tp));
    strcpy(category, tp);
    tp = strtok(NULL, " \"=");
    value = malloc(sizeof(tp));
    strcpy(value, tp);
    
    att_ptr = att_list->attribute;
    while (att_ptr != NULL) {
        if (strcmp(att_ptr->data, category)) {
            att_ptr = att_ptr->next;
            continue;
        }
        value_ptr = att_ptr->value;
        temp = NULL;
        while (value_ptr != NULL) {
            if (strcmp(value_ptr->data, value)) {
                temp = value_ptr;
                value_ptr = value_ptr->next;
                continue;
            }
            if (temp == NULL) att_ptr->value = value_ptr->next;
            else temp->next = value_ptr->next;
            clear_value(value_ptr, 0);
            att_ptr->vnum--;
            free(category);
            free(value);
            return;
        }
        att_ptr = att_ptr->next;
    }
    
    printf("input category or value not exit error\n");
    free(category);
    free(value);
    return;
}

void init_vector(v_vector* vec, int t) {
    vec->t = t;
    vec->x_t[0] = 1;
    vec->x_t[1] = 0;
    vec->next = NULL;
    return;
}
//inputは"category=value	"という形式
void attribute_search(attribute_list* att_list, attribute_set *att_set, char* category, char* value) {
    Attribute *att_ptr;
    Value *value_ptr;
    v_vector *vector_ptr;
    
    att_ptr = att_list->attribute;
    vector_ptr = att_set->value;
    while (att_ptr != NULL) {
        if (vector_ptr == NULL) {
            printf("vector_ptr error\n");
            exit(-1);
        }
        if (strcmp(att_ptr->data, category) != 0) { //カテゴリが一致するまでループ、合ってたら0を返す
            att_ptr = att_ptr->next;
            vector_ptr = vector_ptr->next; //att_setの位置もずらしていく
            continue;
        }
        //一致したのなら以下のループ
        value_ptr = att_ptr->value;
        while (value_ptr != NULL) {
            vector_ptr->x_t[1]++;
            if (strcmp(value_ptr->data, value) != 0) { //バリュが一致するまでループ
                value_ptr = value_ptr->next;
                continue;
            }
            else { //一致したら終わり
                return;
            }
        }
        att_ptr = att_ptr->next;
    }
    printf("attribute not found error\n");
    
    return;
}
