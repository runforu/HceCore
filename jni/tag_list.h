/*
 *
 *  Copyright (C) 2015-2016  Du Hui
 *
 */

#ifndef TAG_LIST_H
#define TAG_LIST_H

typedef struct _tag_value_ {
    char * tag;
    char * value;
} tag_value;

typedef struct _tag_list_ {
    int size;
    int capacity;
    tag_value * tags;
} tag_list;

tag_list * create_tag_list();

void tag_list_put(tag_list *tl, const char * tag, int tag_len, const char * value, int value_len);

char* tag_list_find(tag_list *tl, const char * tag);

void tag_list_destroy(tag_list *tl);

#endif /* TAG_LIST_H */
