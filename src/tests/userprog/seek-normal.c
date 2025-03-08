/* Tests that we can seek in a file to adjust the read/write position. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include <string.h>

void test_main(void) {
  const char* filename = "seek.dat";
  const char* data1 = "ABCDE";
  const char* data2 = "XYZ";
  char buffer[16];
  int fd, bytes;

  CHECK(create(filename, 5), "create seek.dat");

  fd = open(filename);
  CHECK(fd > 1, "open seek.dat");

  bytes = write(fd, data1, 5);
  if (bytes != 5)
    fail("write() returned %d instead of 5", bytes);

  seek(fd, 2);

  bytes = write(fd, data2, 3);
  if (bytes != 3)
    fail("write() returned %d instead of 3", bytes);

  close(fd);

  fd = open(filename);
  CHECK(fd > 1, "open seek.dat again");

  bytes = read(fd, buffer, sizeof buffer);
  close(fd);

  if (bytes != 5)
    fail("read() returned %d instead of 5", bytes);

  buffer[bytes] = '\0';
  if (strcmp(buffer, "ABXYZ") != 0)
    fail("expected 'ABXYZ', got '%s'", buffer);

  msg("seek test passed");
}
