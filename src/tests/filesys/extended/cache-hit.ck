# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-hit) begin
(cache-hit) create test file
(cache-hit) open test file for writing
(cache-hit) write test file data
(cache-hit) Resetting buffer cache
(cache-hit) Initial cache stats: 0 hits, 0 misses
(cache-hit) Reading file with cold cache
(cache-hit) open test file for cold read
(cache-hit) read file data (cold)
(cache-hit) Cold read hit rate: 18%
(cache-hit) Reading file with warm cache
(cache-hit) open test file for warm read
(cache-hit) read file data (warm)
(cache-hit) Warm read hit rate: 100%
(cache-hit) PASS: Warm read hit rate > cold read hit rate
(cache-hit) remove test file
(cache-hit) end
EOF
pass;