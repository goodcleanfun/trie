#include <stdint.h>
#include "greatest/greatest.h"

#include "trie.h"

TEST test_trie(void) {
    trie_t *trie = trie_new();
    uint32_t data;

    ASSERT(trie_add(trie, "foo", 1));
    ASSERT(trie_get_data(trie, "foo", &data));
    ASSERT_EQ(data, 1);
    ASSERT(trie_add(trie, "bar", 2));
    ASSERT(trie_get_data(trie, "bar", &data));
    ASSERT_EQ(data, 2);
    ASSERT(trie_add(trie, "baz", 3));
    ASSERT(trie_get_data(trie, "bar", &data));
    ASSERT_EQ(data, 2);
    ASSERT(trie_get_data(trie, "baz", &data));
    ASSERT_EQ(data, 3);
    ASSERT(trie_add(trie, "barbaz", 4));

    ASSERT(trie_get_data(trie, "bar", &data));
    ASSERT_EQ(data, 2);
    ASSERT(trie_get_data(trie, "baz", &data));
    ASSERT_EQ(data, 3);
    ASSERT(trie_get_data(trie, "barbaz", &data));
    ASSERT_EQ(data, 4);
    ASSERT_EQ(trie_num_keys(trie), 4);

    ASSERT(trie_get_data(trie, "foo", &data));
    ASSERT_EQ(data, 1);
    ASSERT(trie_get_data(trie, "bar", &data));
    ASSERT_EQ(data, 2);
    ASSERT(trie_get_data(trie, "baz", &data));
    ASSERT_EQ(data, 3);
    //ASSERT(trie_get_data(trie, "barz", &data));
    //ASSERT_EQ(data, 4);

    trie_destroy(trie);
    PASS();
}

/* Add definitions that need to be in the test runner's main file. */
GREATEST_MAIN_DEFS();

int32_t main(int32_t argc, char **argv) {
    GREATEST_MAIN_BEGIN();      /* command-line options, initialization. */

    RUN_TEST(test_trie);

    GREATEST_MAIN_END();        /* display results */
}
