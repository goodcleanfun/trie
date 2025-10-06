/******************************************************************************
* Double-array trie implementation for compactly storing large dictionaries.
* This trie differs from most implmentations in that it stores all of the tails
* (compressed) in a single contiguous character array, separated by NUL-bytes,
* so given an index into that array, we can treat the array as a C string
* starting at that index. It also makes serialization dead simple.
* This trie implementation also has several *_from_index methods which allow 
* for effective namespacing e.g. adding the keys "en|blvd" and "fr|blvd"
* and searching by language. For more information on double-array tries
* generally, see: http://linux.thai.net/~thep/datrie/datrie.html
******************************************************************************/

#ifndef TRIE_H
#define TRIE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "char_array/char_array.h"

// Using 256 characters can fit all UTF-8 encoded strings
#define TRIE_NUM_CHARS 256
#define TRIE_NULL_NODE_ID 0
#define TRIE_FREE_LIST_ID 1
#define TRIE_ROOT_NODE_ID 2
#define TRIE_POOL_BEGIN 3

typedef struct trie_node {
    int32_t base;
    int32_t check;
} trie_node_t;

#define TRIE_NULL_NODE (trie_node_t){0, 0}

typedef struct trie_data_node {
    uint32_t tail;
    uint32_t data;
} trie_data_node_t;

#define TRIE_NULL_DATA_NODE (trie_data_node_t){0, 0};

#define ARRAY_NAME trie_node_array
#define ARRAY_TYPE trie_node_t
#include "array/array.h"
#undef ARRAY_NAME
#undef ARRAY_TYPE

#define ARRAY_NAME trie_data_array
#define ARRAY_TYPE trie_data_node_t
#include "array/array.h"
#undef ARRAY_NAME
#undef ARRAY_TYPE

typedef struct trie {
    trie_node_t null_node;
    trie_node_array *nodes;
    trie_data_array *data;
    char_array *tail;
    uint8_t *alphabet;
    uint8_t alpha_map[TRIE_NUM_CHARS];
    uint32_t alphabet_size;
    uint32_t num_keys;
} trie_t;

trie_t *trie_new_alphabet(uint8_t *alphabet, size_t alphabet_size);
trie_t *trie_new(void);

uint32_t trie_get_char_index(trie_t *self, uint8_t c);
uint32_t trie_get_transition_index(trie_t *self, trie_node_t node, uint8_t c);
trie_node_t trie_get_transition(trie_t *self, trie_node_t node, uint8_t c);
bool trie_node_is_free(trie_node_t node);


trie_node_t trie_get_node(trie_t *self, uint32_t index);
void trie_set_base(trie_t *self, size_t index, int32_t base);
void trie_set_check(trie_t *self, size_t index, int32_t check);
trie_node_t trie_get_root(trie_t *self);
trie_node_t trie_get_free_list(trie_t *self);

trie_data_node_t trie_get_data_node(trie_t *self, trie_node_t node);
bool trie_set_data_node(trie_t *self, uint32_t index, trie_data_node_t data_node);

bool trie_get_at_index(trie_t *self, uint32_t index,  uint32_t *data);
bool trie_get(trie_t *self, char *key, uint32_t *data);
bool trie_set_at_index(trie_t *self, uint32_t index, uint32_t data);
bool trie_set(trie_t *self, char *key, uint32_t data);

bool trie_add_at_index(trie_t *self, uint32_t node_id, char *key, size_t len, uint32_t data);
bool trie_add(trie_t *self, char *key, uint32_t data);
bool trie_add_len(trie_t *self, char *key, size_t len, uint32_t data);

uint32_t trie_get_node_id_for_key_from_node_id(trie_t *self, char *key, size_t len, uint32_t i);
uint32_t trie_get_node_id_for_key_len(trie_t *self, char *key, size_t len);
uint32_t trie_get_node_id_for_key(trie_t *self, char *key);

uint32_t trie_num_keys(trie_t *self);

typedef struct trie_prefix_result {
    uint32_t node_id;
    size_t tail_pos;
} trie_prefix_result_t;

#define TRIE_ROOT_PREFIX_RESULT (trie_prefix_result_t) {TRIE_ROOT_NODE_ID, 0}
#define TRIE_NULL_PREFIX_RESULT (trie_prefix_result_t) {TRIE_NULL_NODE_ID, 0}

trie_prefix_result_t trie_get_prefix(trie_t *self, char *key);
trie_prefix_result_t trie_get_prefix_len(trie_t *self, char *key, size_t len);
trie_prefix_result_t trie_get_prefix_from_index(trie_t *self, char *key, size_t len, uint32_t start_index, size_t tail_pos);

void trie_destroy(trie_t *self);

 
#endif
