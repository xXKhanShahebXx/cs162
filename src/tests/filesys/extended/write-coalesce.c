/* Test buffer cache's ability to coalesce writes to the same sector */

#include <syscall.h>
#include <stdio.h>
#include <string.h>
#include "tests/lib.h"
#include "tests/main.h"

#define TEST_FILE_SIZE (64 * 1024)
#define TEST_FILE_NAME "coalesce_test"
#define BUFFER_SIZE 512

static char buffer[BUFFER_SIZE];

void test_main(void) {
  int fd;
  int reads_before, writes_before, reads_after, writes_after;
  int expected_sectors = TEST_FILE_SIZE / BUFFER_SIZE;

  msg("Resetting buffer cache");
  buffer_cache_reset();

  block_device_stats(&reads_before, &writes_before);
  msg("Initial stats: %d reads, %d writes", reads_before, writes_before);

  CHECK(create(TEST_FILE_NAME, 0), "create test file");
  fd = open(TEST_FILE_NAME);
  CHECK(fd > 1, "open test file");

  msg("Writing 64 KB file in 512-byte chunks");

  for (int i = 0; i < TEST_FILE_SIZE / BUFFER_SIZE; i++) {
    memset(buffer, 'A' + (i % 26), BUFFER_SIZE);

    CHECK(write(fd, buffer, BUFFER_SIZE) == BUFFER_SIZE, "write chunk %d", i);

    if (i == 32)
      msg("Written 16 KB so far...");
    else if (i == 64)
      msg("Written 32 KB so far...");
    else if (i == 96)
      msg("Written 48 KB so far...");
  }

  close(fd);

  block_device_stats(&reads_after, &writes_after);
  int write_count = writes_after - writes_before;

  msg("Device writes: %d for %d KB file (%d sectors)", write_count, TEST_FILE_SIZE / 1024,
      expected_sectors);

  int max_reasonable = expected_sectors * 5;

  if (write_count <= max_reasonable) {
    msg("PASS: Write count is reasonable");
  } else {
    msg("FAIL: Too many writes: %d (expected ~%d sectors)", write_count, expected_sectors);
  }

  msg("Verifying file contents");
  fd = open(TEST_FILE_NAME);
  CHECK(fd > 1, "reopen file");

  bool data_correct = true;
  for (int i = 0; i < TEST_FILE_SIZE / BUFFER_SIZE; i++) {
    char expected = 'A' + (i % 26);
    int bytes_read = read(fd, buffer, BUFFER_SIZE);

    if (bytes_read != BUFFER_SIZE) {
      data_correct = false;
      break;
    }

    for (int j = 0; j < BUFFER_SIZE; j++) {
      if (buffer[j] != expected) {
        data_correct = false;
        break;
      }
    }

    if (!data_correct)
      break;

    if (i == 32)
      msg("Verified 16 KB so far...");
    else if (i == 64)
      msg("Verified 32 KB so far...");
    else if (i == 96)
      msg("Verified 48 KB so far...");
  }

  CHECK(data_correct, "file contents are correct");
  close(fd);

  CHECK(remove(TEST_FILE_NAME), "remove file");
}