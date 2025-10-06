
install:
	clib install --dev

test:
	@$(CC) test.c src/trie.c $(CFLAGS) -g -I src -I deps -I deps/greatest $(LDFLAGS) -o $@
	@./$@

.PHONY: install test
