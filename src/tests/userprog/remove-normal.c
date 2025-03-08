/* Test removing a file in the most normal way. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int fd;

  CHECK(create("test.txt", 0), "create \"test.txt\"");

  CHECK((fd = open("test.txt")) > 1, "open \"test.txt\"");

  close(fd);

  CHECK(remove("test.txt"), "remove \"test.txt\"");

  fd = open("test.txt");
  if (fd != -1)
    fail("open(\"test.txt\") after removal returned %d", fd);
}
