#include <syscall.h>
#include <stdio.h>
#include <string.h>
#include "tests/lib.h"
#include "tests/main.h"

#define TEST_FILE_SIZE (8 * 1024)
#define TEST_FILE_NAME "test_file"

static char buffer[TEST_FILE_SIZE];

void test_main(void) {
  int hit_before, miss_before, hit_after, miss_after;
  int fd;

  CHECK(create(TEST_FILE_NAME, TEST_FILE_SIZE), "create test file");

  fd = open(TEST_FILE_NAME);
  CHECK(fd > 1, "open test file for writing");

  memset(buffer, 'A', TEST_FILE_SIZE);
  CHECK(write(fd, buffer, TEST_FILE_SIZE) == TEST_FILE_SIZE, "write test file data");

  close(fd);

  msg("Resetting buffer cache");
  buffer_cache_reset();

  buffer_cache_stats(&hit_before, &miss_before);
  msg("Initial cache stats: %d hits, %d misses", hit_before, miss_before);

  msg("Reading file with cold cache");
  fd = open(TEST_FILE_NAME);
  CHECK(fd > 1, "open test file for cold read");
  CHECK(read(fd, buffer, TEST_FILE_SIZE) == TEST_FILE_SIZE, "read file data (cold)");
  close(fd);

  buffer_cache_stats(&hit_after, &miss_after);

  int cold_hits = hit_after - hit_before;
  int cold_misses = miss_after - miss_before;
  int cold_total = cold_hits + cold_misses;
  int cold_hit_rate = cold_total > 0 ? (cold_hits * 100) / cold_total : 0;

  msg("Cold read hit rate: %d%%", cold_hit_rate);

  hit_before = hit_after;
  miss_before = miss_after;

  msg("Reading file with warm cache");
  fd = open(TEST_FILE_NAME);
  CHECK(fd > 1, "open test file for warm read");
  CHECK(read(fd, buffer, TEST_FILE_SIZE) == TEST_FILE_SIZE, "read file data (warm)");
  close(fd);

  buffer_cache_stats(&hit_after, &miss_after);

  int warm_hits = hit_after - hit_before;
  int warm_misses = miss_after - miss_before;
  int warm_total = warm_hits + warm_misses;
  int warm_hit_rate = warm_total > 0 ? (warm_hits * 100) / warm_total : 0;

  msg("Warm read hit rate: %d%%", warm_hit_rate);

  if (warm_hit_rate > cold_hit_rate) {
    msg("PASS: Warm read hit rate > cold read hit rate");
  } else {
    msg("FAIL: Warm read hit rate <= cold read hit rate");
    fail("Warm read hit rate (%d%%) should be > cold read hit rate (%d%%)", warm_hit_rate,
         cold_hit_rate);
  }

  CHECK(remove(TEST_FILE_NAME), "remove test file");
}
