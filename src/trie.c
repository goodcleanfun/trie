#include "trie.h"

#include "logging/logging.h"

#define TRIE_SIGNATURE 0xABABABAB
#define DEFAULT_NODE_ARRAY_SIZE 32

#define TRIE_INDEX_ERROR  0
#define TRIE_MAX_INDEX 0x7fffffff

#define TRIE_PREFIX_CHAR "\x02"
#define TRIE_SUFFIX_CHAR "\x03"

/* 
* Maps the 256 characters (suitable for UTF-8 strings) to array indices
* ordered by frequency of usage in Wikipedia titles.
* In practice the order of the chars shouldn't matter for larger key sets
* but may save space for a small number of keys
*/
uint8_t DEFAULT_ALPHABET[] = {
32, 97, 101, 105, 111, 110, 114, 0, 116, 108, 115, 117, 104, 99, 100, 109,
103, 121, 83, 112, 67, 98, 107, 77, 65, 102, 118, 66, 80, 84, 41, 40,
119, 82, 72, 68, 76, 71, 70, 87, 49, 44, 78, 75, 69, 74, 73, 48,
195, 122, 45, 50, 57, 79, 86, 46, 120, 85, 106, 39, 56, 51, 52, 89,
128, 226, 147, 55, 53, 54, 197, 113, 196, 90, 169, 161, 81, 179, 58, 88,
173, 188, 141, 182, 153, 177, 38, 130, 135, 164, 159, 47, 168, 33, 186, 167,
129, 200, 131, 162, 155, 184, 163, 171, 160, 137, 132, 190, 133, 34, 225, 187,
165, 189, 176, 63, 201, 140, 154, 180, 151, 170, 145, 175, 43, 152, 150, 166,
158, 194, 198, 178, 144, 181, 148, 134, 136, 42, 185, 174, 156, 143, 172, 191,
142, 96, 59, 202, 139, 183, 64, 206, 157, 61, 146, 36, 37, 199, 149, 126,
229, 230, 204, 233, 231, 207, 138, 208, 232, 92, 227, 228, 209, 94, 224, 239,
217, 205, 221, 218, 211, 4, 8, 12, 16, 20, 24, 28, 60, 203, 215, 219,
223, 235, 243, 247, 251, 124, 254, 3, 7, 11, 15, 19, 23, 27, 31, 35,
192, 212, 216, 91, 220, 95, 236, 240, 244, 248, 123, 252, 127, 2, 6, 10,
14, 18, 22, 26, 30, 62, 193, 213, 237, 241, 245, 249, 253, 1, 5, 9,
13, 17, 21, 25, 29, 210, 214, 93, 222, 234, 238, 242, 246, 250, 125, 255
};


/*
Constructors
*/

static trie_t *trie_new_empty(uint8_t *alphabet, size_t alphabet_size) {
    trie_t *trie = calloc(1, sizeof(trie_t));
    if (!trie)
        goto exit_no_malloc;

    trie->nodes = trie_node_array_new_size(DEFAULT_NODE_ARRAY_SIZE);
    if (!trie->nodes)
        goto exit_trie_created;

    trie->null_node = TRIE_NULL_NODE;

    trie->tail = char_array_new();
    if (!trie->tail)
        goto exit_node_array_created;

    trie->alphabet = malloc(alphabet_size);
    if (!trie->alphabet)
        goto exit_tail_created;
    memcpy(trie->alphabet, alphabet, alphabet_size);

    trie->alphabet_size = alphabet_size;

    trie->num_keys = 0;

    for (size_t i = 0; i < trie->alphabet_size; i++) {
        trie->alpha_map[alphabet[i]] = i;
        log_debug("setting alpha_map[%c] = %zu\n", alphabet[i], i);
    }

    trie->data = trie_data_array_new_size(1);
    if (!trie->data)
        goto exit_alphabet_created;

    return trie;

exit_alphabet_created:
    free(trie->alphabet);
exit_tail_created:
    char_array_destroy(trie->tail);
exit_node_array_created:
    trie_node_array_destroy(trie->nodes);
exit_trie_created:
    free(trie);
exit_no_malloc:
    return NULL;
}

trie_t *trie_new_alphabet(uint8_t *alphabet, size_t alphabet_size) {
    trie_t *trie = trie_new_empty(alphabet, alphabet_size);
    if (!trie)
        return NULL;

    trie_node_array_push(trie->nodes, (trie_node_t){0, 0});
    // Circular reference  point for first and last free nodes in the linked list
    trie_node_array_push(trie->nodes, (trie_node_t){-1, -1});
    // Root node
    trie_node_array_push(trie->nodes, (trie_node_t){TRIE_POOL_BEGIN, 0});

    char_array_push(trie->tail, '\0');
    // Since data indexes are negative integers, index 0 is not valid, so pad it
    trie_data_array_push(trie->data, (trie_data_node_t){0, 0});

    return trie;
}

trie_t *trie_new(void) {
    return trie_new_alphabet(DEFAULT_ALPHABET, sizeof(DEFAULT_ALPHABET));
}

inline bool trie_node_is_free(trie_node_t node) {
    return node.check < 0;
}

inline trie_node_t trie_get_node(trie_t *trie, uint32_t index) {
    if ((index >= trie_node_array_size(trie->nodes)) || index < TRIE_ROOT_NODE_ID) return trie->null_node;
    return trie_node_array_get_unchecked(trie->nodes, index);
}

inline void trie_set_base(trie_t *trie, size_t index, int32_t base) {
    log_debug("Setting base at %zu to %d\n", index, base);
    trie_node_t node = trie_node_array_get_unchecked(trie->nodes, index);
    node.base = base;
    trie_node_array_set_unchecked(trie->nodes, index, node);
}

inline void trie_set_check(trie_t *trie, size_t index, int32_t check) {
    log_debug("Setting check at %zu to %d\n", index, check);
    trie_node_t node = trie_node_array_get_unchecked(trie->nodes, index);
    node.check = check;
    trie_node_array_set_unchecked(trie->nodes, index, node);
}


inline trie_node_t trie_get_root(trie_t *trie) {
    return trie_node_array_get_unchecked(trie->nodes, TRIE_ROOT_NODE_ID);
}

inline trie_node_t trie_get_free_list(trie_t *trie) {
    return trie_node_array_get_unchecked(trie->nodes, TRIE_FREE_LIST_ID);
}


/* 
* Private implementation
*/


static bool trie_extend(trie_t *trie, size_t to_index) {
    uint32_t new_begin, i, free_tail;

    if (to_index <= 0 || TRIE_MAX_INDEX <= to_index)
        return false;

    size_t num_nodes = trie_node_array_size(trie->nodes);

    if (to_index < num_nodes)
        return true;

    new_begin = (uint32_t)num_nodes;

    for (i = new_begin; i < (uint32_t)to_index + 1; i++) {
        trie_node_array_push(trie->nodes, (trie_node_t){-(i-1), -(i+1)});
    }

    trie_node_t free_list_node = trie_get_free_list(trie);
    free_tail = -free_list_node.base;
    trie_set_check(trie, free_tail, -new_begin);
    trie_set_base(trie, new_begin, -free_tail);
    trie_set_check(trie, to_index, -TRIE_FREE_LIST_ID);
    trie_set_base(trie, TRIE_FREE_LIST_ID, -to_index);

    return true;
}

void trie_make_room_for(trie_t *trie, uint32_t next_id) {
    size_t num_nodes = trie_node_array_size(trie->nodes);
    if ((size_t)next_id + trie->alphabet_size >= num_nodes) {
        trie_extend(trie, (size_t)next_id + trie->alphabet_size);
        log_debug("extended to %zu\n", num_nodes);
    }
}

static inline void trie_set_node(trie_t *trie, uint32_t index, trie_node_t node) {
    log_debug("setting node, index=%d, node=(%d,%d)\n", index, node.base, node.check);
    trie_node_array_set_unchecked(trie->nodes, (size_t)index, node);
}

static void trie_init_node(trie_t *trie, uint32_t index) {
    int32_t prev, next;

    trie_node_t node = trie_get_node(trie, index);
    prev = -node.base;
    next = -node.check;

    trie_set_check(trie, prev, -next);
    trie_set_base(trie, next, -prev);

}

static void trie_free_node(trie_t *trie, uint32_t index) {
    int32_t i, prev;

    trie_node_t free_list_node = trie_get_free_list(trie);
    trie_node_t node;
    i = -free_list_node.check;
    while (i != TRIE_FREE_LIST_ID && i < index) {
        node = trie_get_node(trie, i);
        i = -node.check;
    }

    node = trie_get_node(trie, i);
    prev = -node.base;

    trie_set_node(trie, index, (trie_node_t){-prev, -i});

    trie_set_check(trie, prev, -index);
    trie_set_base(trie, i, -index);
}


static bool trie_node_has_children(trie_t *trie, uint32_t node_id) {
    uint32_t index;
    uint32_t num_nodes = (uint32_t)trie_node_array_size(trie->nodes);
    if (node_id > num_nodes || node_id < TRIE_POOL_BEGIN)
        return false;
    trie_node_t node = trie_get_node(trie, node_id);
    if (node.base < 0)
        return false;
    for (size_t i = 0; i < trie->alphabet_size; i++) {
        uint8_t c = trie->alphabet[i];
        index = trie_get_transition_index(trie, node, c);
        if (index < num_nodes && (uint32_t)(trie_get_node(trie, index).check) == node_id)
            return true;
    }
    return false;
}

static void trie_prune_up_to(trie_t *trie, uint32_t p, uint32_t s) {
    log_debug("Pruning from %d to %d\n", s, p);
    log_debug("%d has_children=%d\n", s, trie_node_has_children(trie, s));
    while (p != s && !trie_node_has_children(trie, s)) {
        uint32_t parent = trie_get_node(trie, s).check;
        trie_free_node(trie, s);
        s = parent;
    }
}

static void trie_prune(trie_t *trie, uint32_t s) {
    trie_prune_up_to(trie, TRIE_ROOT_NODE_ID, s);
}

static void trie_get_transition_chars(trie_t *trie, uint32_t node_id, uint8_t *transitions, uint32_t *num_transitions) {
    uint32_t index;
    uint32_t j = 0;
    uint32_t num_nodes = (uint32_t)trie_node_array_size(trie->nodes);
    trie_node_t node = trie_get_node(trie, node_id);
    for (size_t i = 0; i < trie->alphabet_size; i++) {
        uint8_t c = trie->alphabet[i];
        index = trie_get_transition_index(trie, node, c);
        if (index < num_nodes && trie_get_node(trie, index).check == node_id) {
            log_debug("adding transition char %c to index %d\n", c, j);
            transitions[j++] = c;
        }
    }

    *num_transitions = j;
}


static bool trie_can_fit_transitions(trie_t *trie, uint32_t node_id, uint8_t *transitions, uint32_t num_transitions) {
    uint32_t i;
    uint32_t char_index, index;

    for (i = 0; i < num_transitions; i++) {
        unsigned char c = transitions[i];
        char_index = trie_get_char_index(trie, c);
        index = node_id + char_index;
        trie_node_t node = trie_get_node(trie, index);
        if (node_id > TRIE_MAX_INDEX - char_index || !trie_node_is_free(node)) {
            return false;
        }

    }
    return true;

}

static uint32_t trie_find_new_base(trie_t *trie, uint8_t *transitions, uint32_t num_transitions) {
    uint32_t first_char_index = trie_get_char_index(trie, transitions[0]);

    trie_node_t node = trie_get_free_list(trie);
    uint32_t index = -node.check;

    while (index != TRIE_FREE_LIST_ID && index < first_char_index + TRIE_POOL_BEGIN) {
        node = trie_get_node(trie, index);
        index = -node.check;
    }  


    if (index == TRIE_FREE_LIST_ID) {
        for (index = first_char_index + TRIE_POOL_BEGIN; ; index++) {
            if (!trie_extend(trie, (size_t)index)) {
                log_error("Trie index error extending to %d\n", index);
                return TRIE_INDEX_ERROR;
            }
            node = trie_get_node(trie, index);
            if (node.check < 0) 
                break;
        }
    }

    // search for next free cell that fits the transitions
    while (!trie_can_fit_transitions(trie, index - first_char_index, transitions, num_transitions)) {
        trie_node_t node = trie_get_node(trie, index);
        if (-node.check == TRIE_FREE_LIST_ID) {
            if (!trie_extend(trie, trie_node_array_size(trie->nodes) + trie->alphabet_size)) {
                log_error("Trie index error extending to %d\n", index);
                return TRIE_INDEX_ERROR;
            }
            node = trie_get_node(trie, index);
        }

        index = -node.check;

    }

    return index - first_char_index;

}

static void trie_relocate_base(trie_t *trie, uint32_t current_index, int32_t new_base) {
    log_debug("Relocating base at %d\n", current_index);
    uint32_t i;

    trie_make_room_for(trie, new_base);

    trie_node_t old_node = trie_get_node(trie, current_index);

    uint32_t num_transitions = 0;
    unsigned char transitions[trie->alphabet_size];
    trie_get_transition_chars(trie, current_index, transitions, &num_transitions);

    for (i = 0; i < num_transitions; i++) {
        unsigned char c = transitions[i];

        uint32_t char_index = trie_get_char_index(trie, c);

        uint32_t old_index = old_node.base + char_index;
        uint32_t new_index = new_base + char_index;

        log_debug("old_index=%d\n", old_index);
        trie_node_t old_transition = trie_get_node(trie, old_index);

        trie_init_node(trie, new_index);
        trie_set_node(trie, new_index, (trie_node_t){old_transition.base, current_index});

        /*
        *  All transitions out of old_index are now owned by new_index
        *  set check values appropriately
        */
        if (old_transition.base > 0) {  // do nothing in the case of a tail pointer
            uint32_t num_nodes = trie_node_array_size(trie->nodes);
            for (uint32_t j = 0; j < trie->alphabet_size; j++) {
                unsigned char c = trie->alphabet[j];
                uint32_t index = trie_get_transition_index(trie, old_transition, c);
                if (index < num_nodes && trie_get_node(trie, index).check == old_index) {
                    trie_set_check(trie, index, new_index);
                }
            }
        }

        // Free the node at old_index
        log_debug("freeing node at %d\n", old_index);
        trie_free_node(trie, old_index);

    }

    trie_set_base(trie, current_index, new_base);
}



/*
* Public methods
*/

inline uint32_t trie_get_char_index(trie_t *trie, uint8_t c) {
    return trie->alpha_map[c] + 1;
}

inline uint32_t trie_get_transition_index(trie_t *trie, trie_node_t node, uint8_t c) {
    uint32_t char_index = trie_get_char_index(trie, c);
    return node.base + char_index;
}

inline trie_node_t trie_get_transition(trie_t *trie, trie_node_t node, uint8_t c) {
   uint32_t index = trie_get_transition_index(trie, node, c);

    if (index >= trie_node_array_size(trie->nodes)) {
        return trie->null_node;
    } else {
        return trie->nodes->a[index];
    }

}

void trie_add_tail(trie_t *trie, char *tail, size_t len) {
    size_t current_pos = char_array_size(trie->tail);
    char_array_append_len(trie->tail, tail, len);
    char_array_push(trie->tail, '\0');
    log_debug("Added tail: %s at pos %zu\n", char_array_get_string(trie->tail) + current_pos, current_pos);
}

void trie_set_tail(trie_t *trie, char *tail, size_t len, uint32_t tail_pos) {
    log_debug("Setting tail: %s at pos %d\n", tail, tail_pos);
    size_t i = 0;

    size_t tail_len = char_array_size(trie->tail);

    for (i = 0; i < len && ((size_t)tail_pos + i) < tail_len; i++) {
        char_array_set_unchecked(trie->tail, (size_t)tail_pos + i, tail[i]);
    }
    char_array_set_unchecked(trie->tail, tail_pos + i, '\0');

    // Pad with 0s if we're short
    for (i = tail_len; i < ((size_t)tail_pos + len); i++) {
        char_array_push(trie->tail, '\0');
    }
}


uint32_t trie_add_transition(trie_t *trie, uint32_t node_id, char c) {
    uint32_t next_id;
    trie_node_t node, next;
    uint32_t new_base;

    node = trie_get_node(trie, node_id);
    uint32_t char_index = trie_get_char_index(trie, c);

    log_debug("adding transition %c to node_id %d + char_index %d, base=%d, check=%d\n", c, node_id, char_index, node.base, node.check);


    if (node.base > 0) {
        log_debug("node.base > 0\n");
        next_id = node.base + char_index;
        log_debug("next_id=%d\n", next_id);
        trie_make_room_for(trie, next_id);

        next = trie_get_node(trie, next_id);

        if (next.check == node_id) {
            return next_id;
        }

        log_debug("next.base=%d, next.check=%d\n", next.base, next.check);

        if (node.base > TRIE_MAX_INDEX - char_index || !trie_node_is_free(next)) {
            log_debug("node.base > TRIE_MAX_INDEX\n");
            uint32_t num_transitions;
            uint8_t transitions[trie->alphabet_size];
            trie_get_transition_chars(trie, node_id, transitions, &num_transitions);

            transitions[num_transitions++] = c;
            new_base = trie_find_new_base(trie, transitions, num_transitions);

            trie_relocate_base(trie, node_id, new_base);
            next_id = new_base + char_index;
        }

    } else {
        uint8_t transitions[1] = {c};
        new_base = trie_find_new_base(trie, transitions, 1);
        log_debug("Found base for transition char %c, base=%d\n", c, new_base);

        trie_set_base(trie, node_id, new_base);
        next_id = new_base + char_index;
    }
    log_debug("init_node\n");
    trie_init_node(trie, next_id);
    log_debug("setting check\n");
    trie_set_check(trie, next_id, node_id);

    return next_id;
}

int32_t trie_separate_tail(trie_t *trie, uint32_t from_index, char *tail, size_t len, uint32_t data) {
    uint8_t c = (uint8_t)*tail;
    int32_t index = trie_add_transition(trie, from_index, c);

    if (*tail != '\0') {
        tail++;
        len--;
    }

    log_debug("Separating node at index %d into char %c with tail %s, len=%zu\n", from_index, c, tail, len);
    trie_set_base(trie, index, -1 * (int32_t)trie_data_array_size(trie->data));

    log_debug("Pushing data to tail, tail ptr=%zu, data=%d\n", char_array_size(trie->tail), data);
    trie_data_array_push(trie->data, (trie_data_node_t){(uint32_t)char_array_size(trie->tail), data});
    trie_add_tail(trie, tail, len);

    return index;
}

void trie_tail_merge(trie_t *trie, uint32_t old_node_id, char *suffix, size_t suffix_len, uint32_t data) {
    uint8_t c;
    uint32_t next_id;

    trie_node_t old_node = trie_get_node(trie, old_node_id);
    int32_t old_data_index = -1 * old_node.base;
    trie_data_node_t old_data_node;
    if (!trie_data_array_get(trie->data, (size_t)old_data_index, &old_data_node)) {
        log_error("No data node found for old_node_id=%d, old_data_index=%d\n", old_node_id, old_data_index);
        return;
    }
    uint32_t old_tail_pos = old_data_node.tail;

    uint8_t *original_tail = (uint8_t *)char_array_get_string(trie->tail) + old_tail_pos;
    char *old_tail = (char *)original_tail;
    log_debug("Merging existing tail %s with new tail %s, (len=%zu) node_id=%d\n", original_tail, suffix, suffix_len, old_node_id);

    size_t common_prefix = 0;
    for (char *s1 = old_tail, *s2 = suffix; *s1 && *s1 == *s2; s1++, s2++, common_prefix++);

    size_t old_tail_len = strlen((char *)old_tail);
    if (common_prefix == old_tail_len && old_tail_len == suffix_len) {
        log_debug("Key already exists, setting value to %d\n", data);
        trie_data_array_set(trie->data, (size_t)old_data_index, (trie_data_node_t) {old_tail_pos, data});
        return;
    }

    uint32_t node_id = old_node_id;
    log_debug("common_prefix=%zu\n", common_prefix);

    for (size_t i = 0; i < common_prefix; i++) {
        c = original_tail[i];
        log_debug("merge tail, c=%c, node_id=%d\n", c, node_id);
        next_id = trie_add_transition(trie, node_id, c);
        if (next_id == TRIE_INDEX_ERROR) {
            goto exit_prune;
        }
        node_id = next_id;
    }

    uint32_t old_tail_index = trie_add_transition(trie, node_id, *(old_tail+common_prefix));
    log_debug("old_tail_index=%d\n", old_tail_index);
    if (old_tail_index == TRIE_INDEX_ERROR) {
        goto exit_prune;
    }

    old_tail += common_prefix;
    old_tail_len -= common_prefix;
    if (*old_tail != '\0') {
        old_tail++;
        old_tail_len--;
    }

    trie_set_base(trie, old_tail_index, -1 * old_data_index);
    trie_set_tail(trie, (char *)old_tail, old_tail_len, old_tail_pos);

    trie_separate_tail(trie, node_id, suffix + common_prefix, suffix_len - common_prefix, data);
    return;

exit_prune:
    trie_prune_up_to(trie, old_node_id, node_id);
    trie_set_tail(trie, (char *)original_tail, old_tail_len, old_tail_pos);
    return;
}

bool trie_add_at_index(trie_t *trie, uint32_t node_id, char *key, size_t len, uint32_t data) {
    char *ptr = key; 
    uint32_t last_node_id = node_id;
    trie_node_t last_node = trie_get_node(trie, node_id);
    if (last_node.base == TRIE_NULL_NODE_ID) {
        log_debug("last_node.base == TRIE_NULL_NODE_ID, node_id = %d\n", node_id);
        return false;
    }
    
    trie_node_t node;

    // Walks node until prefix reached, including the trailing \0

    for (size_t i = 0; i < len; ptr++, i++, last_node_id = node_id, last_node = node) {

        uint8_t c = (uint8_t)*ptr;
        log_debug("--- char=%c\n", c);
        node_id = trie_get_transition_index(trie, last_node, c);
        log_debug("node_id=%d, last_node.base=%d, last_node.check=%d, char_index=%d\n", node_id, last_node.base, last_node.check, trie_get_char_index(trie, c));

        if (node_id != TRIE_NULL_NODE_ID) {
            trie_make_room_for(trie, node_id);
        }

        node = trie_get_node(trie, node_id);
        log_debug("node.check=%d, last_node_id=%d, node.base=%d\n", node.check, last_node_id, node.base);

        if (node.check < 0 || (node.check != last_node_id)) {
            log_debug("last_node_id=%d, ptr=%s, tail_pos=%zu, len=%zu\n", last_node_id,  ptr, char_array_size(trie->tail), len - i - 1);
            trie_separate_tail(trie, last_node_id, ptr, len - i  - 1, data);
            break;
        } else if (node.base < 0 && node.check == last_node_id) {
            log_debug("tail merge\n");
            trie_tail_merge(trie, node_id, ptr + 1, len - i > 1 ? len - i - 2 : 0, data);
            break;
        }
    }

    trie->num_keys++;
    return true;
}


inline bool trie_add(trie_t *trie, char *key, uint32_t data) {
    size_t len = strlen(key);
    if (len == 0) return false;
    return trie_add_at_index(trie, TRIE_ROOT_NODE_ID, key, len + 1, data);
}

inline bool trie_add_len(trie_t *trie, char *key, size_t len, uint32_t data) {
    return trie_add_at_index(trie, TRIE_ROOT_NODE_ID, key, len, data);
}

bool trie_compare_tail(trie_t *trie, char *str, size_t len, size_t tail_index) {
    if (tail_index >= char_array_size(trie->tail)) return false;

    char *current_tail = char_array_get_string(trie->tail) + tail_index;
    return strncmp((char *)current_tail, str, len) == 0;
}

inline trie_data_node_t trie_get_data_node(trie_t *trie, trie_node_t node) {
    if (node.base >= 0) {
        return TRIE_NULL_DATA_NODE;
    }
    int32_t data_index = -1*node.base;
    trie_data_node_t data_node = trie->data->a[data_index];
    return data_node;
}

inline bool trie_set_data_node(trie_t *trie, uint32_t index, trie_data_node_t data_node) {
    if (trie == NULL || trie->data == NULL || index >= trie->data->n) return false;
    trie->data->a[index] = data_node;
    return true;
}

inline bool trie_get_data_at_index(trie_t *trie, uint32_t index,  uint32_t *data) {
     if (index == TRIE_NULL_NODE_ID) return false;

     trie_node_t node = trie_get_node(trie, index);
     trie_data_node_t data_node = trie_get_data_node(trie, node);
     if (data_node.tail == 0) return false;
     *data = data_node.data;

     return true;    
}

inline bool trie_get_data(trie_t *trie, char *key, uint32_t *data) {
     uint32_t node_id = trie_get(trie, key);
     return trie_get_data_at_index(trie, node_id, data);
}

inline bool trie_set_data_at_index(trie_t *trie, uint32_t index, uint32_t data) {
    if (index == TRIE_NULL_NODE_ID) return false;
     trie_node_t node = trie_get_node(trie, index);
     trie_data_node_t data_node = trie_get_data_node(trie, node);
     data_node.data = data;
     return trie_set_data_node(trie, -1*node.base, data_node);

}

inline bool trie_set_data(trie_t *trie, char *key, uint32_t data) {
     uint32_t node_id = trie_get(trie, key);
     if (node_id == TRIE_NULL_NODE_ID) {
        return trie_add(trie, key, data);
     }

     return trie_set_data_at_index(trie, node_id, data);
}

trie_prefix_result_t trie_get_prefix_from_index(trie_t *trie, char *key, size_t len, uint32_t start_index, size_t tail_pos) {
    if (key == NULL) {
        return TRIE_NULL_PREFIX_RESULT;
    }

    char *ptr = key;

    uint32_t node_id = start_index;
    trie_node_t node = trie_get_node(trie, node_id);
    if (node.base == TRIE_NULL_NODE_ID) {
        return TRIE_NULL_PREFIX_RESULT;
    }

    uint32_t next_id = TRIE_NULL_NODE_ID;

    bool original_node_no_tail = node.base >= 0;

    size_t i = 0;

    if (node.base >= 0) {
        // Include NUL-byte. It may be stored if this phrase is a prefix of a longer one
        for (i = 0; i < len; i++, ptr++, node_id = next_id) {
            next_id = trie_get_transition_index(trie, node, *ptr);
            node = trie_get_node(trie, next_id);

            if (node.check != node_id) {
                return TRIE_NULL_PREFIX_RESULT;
            }

            if (node.base < 0) break;
        }
    } else {
        next_id = node_id;
        node = trie_get_node(trie, node_id);
    }

    if (node.base < 0) {
        trie_data_node_t data_node = trie_get_data_node(trie, node);

        char *query_tail = (*ptr && original_node_no_tail) ? (char *)ptr + 1 : (char *)ptr;
        size_t query_len = (*ptr && original_node_no_tail) ? len - i - 1 : len - i;

        if (data_node.tail != 0 && trie_compare_tail(trie, query_tail, query_len, data_node.tail + tail_pos)) {
            return (trie_prefix_result_t){next_id, tail_pos + query_len};
        } else {
            return TRIE_NULL_PREFIX_RESULT;

        }
    } else {
        return (trie_prefix_result_t){next_id, 0};
    }

    return TRIE_NULL_PREFIX_RESULT;

}

trie_prefix_result_t trie_get_prefix_len(trie_t *trie, char *key, size_t len) {
    return trie_get_prefix_from_index(trie, key, len, TRIE_ROOT_NODE_ID, 0);
}

trie_prefix_result_t trie_get_prefix(trie_t *trie, char *key) {
    return trie_get_prefix_from_index(trie, key, strlen(key), TRIE_ROOT_NODE_ID, 0);
}

uint32_t trie_get_from_index(trie_t *trie, char *key, size_t len, uint32_t i) {
    if (key == NULL) return TRIE_NULL_NODE_ID;

    uint8_t *ptr = (uint8_t *)key;

    uint32_t node_id = i;
    trie_node_t node = trie_get_node(trie, i);
    if (node.base == TRIE_NULL_NODE_ID) return TRIE_NULL_NODE_ID;

    uint32_t next_id;

    // Include NUL-byte. It may be stored if this phrase is a prefix of a longer one

    for (size_t i = 0; i < len + 1; i++, ptr++, node_id = next_id) {
        next_id = trie_get_transition_index(trie, node, *ptr);
        node = trie_get_node(trie, next_id);
        log_debug("trie_get_from_index: node_id=%d, node.base=%d, node.check=%d, next_id=%d, char=%c\n", node_id, node.base, node.check, next_id, *ptr);

        if (node.check != node_id) {
            log_debug("trie_get_from_index: node.check != node_id, returning TRIE_NULL_NODE_ID\n");
            return TRIE_NULL_NODE_ID;
        }

        if (node.check == node_id && node.base < 0) {
            trie_data_node_t data_node = trie_get_data_node(trie, node);

            char *query_tail = *ptr ? (char *) ptr + 1 : (char *) ptr;

            if (data_node.tail != 0 && trie_compare_tail(trie, query_tail, strlen(query_tail) + 1, data_node.tail)) {
                return next_id;
            } else {
                return TRIE_NULL_NODE_ID;
            }

        }

    }

    return next_id;

}

uint32_t trie_get_len(trie_t *trie, char *word, size_t len) {
    return trie_get_from_index(trie, word, len, TRIE_ROOT_NODE_ID);
}

uint32_t trie_get(trie_t *trie, char *word) {
    size_t word_len = strlen(word);
    return trie_get_from_index(trie, word, word_len, TRIE_ROOT_NODE_ID);
}


inline uint32_t trie_num_keys(trie_t *trie) {
    if (trie == NULL) return 0;
    return trie->num_keys;
}

/*
Destructor
*/
void trie_destroy(trie_t *trie) {
    if (!trie)
        return;

    if (trie->alphabet)
        free(trie->alphabet);
    if (trie->nodes)
        trie_node_array_destroy(trie->nodes);
    if (trie->tail)
        char_array_destroy(trie->tail);
    if (trie->data)
        trie_data_array_destroy(trie->data);
    
    free(trie);
}

