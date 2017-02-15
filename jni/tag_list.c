/*
 *
 *  Copyright (C) 2015-2016  Du Hui
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "tag_list.h"
#include "log.h"

/*
void free_tag(tag_list * tl, int i) {
    if (i < 0 || i > tl->size) {
        return;
    }
    free(tl->tags[i].tag);
    free(tl->tags[i].value);
    if (i != tl->size - 1) {
        tl->tags[i].tag = tl->tags[tl->size - 1].tag;
        tl->tags[i].value = tl->tags[tl->size - 1].value;
    }
    tl->size--;
}*/

tag_list * create_tag_list() {
    tag_list* tl = malloc(sizeof(tag_list));
    tl->size = 0;
    tl->capacity = 16;
    tl->tags = malloc(sizeof(tag_value) * tl->capacity);
    memset(tl->tags, 0, sizeof(tag_value) * tl->capacity);
    return tl;
}

void tag_list_put(tag_list *tl, const char * tag, int tag_len, const char * value, int value_len) {
    if (tl->capacity == tl->size) {
        tl->capacity *= 2;
        tag_value *p = realloc(tl->tags, sizeof(tag_value) * tl->capacity);
        if (p == NULL) {
            return;
        }
    }

    tl->tags[tl->size].tag = strndup(tag, tag_len);
    tl->tags[tl->size].value = strndup(value, value_len);
    tl->size++;
}

char* tag_list_find(tag_list *tl, const char * tag) {
    for (int i = 0; i < tl->size; i++) {
        if (strcmp(tag, tl->tags[i].tag) == 0) {
            return tl->tags[i].value;
        }
    }
    return NULL;
}

void tag_list_destroy(tag_list *tl) {
    if (tl == NULL) {
        return;
    }
    for (int i = 0; i < tl->size; i++) {
        free(tl->tags[i].tag);
        free(tl->tags[i].value);
    }
    free(tl->tags);
    free(tl);
}
