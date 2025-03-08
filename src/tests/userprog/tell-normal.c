/* Checks that tell() returns the correct file position for reads and writes. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  const char data[] = "Hello, Pintos!";
  int fd, pos;

  /* 1) Create a file named "tell.dat". */
  CHECK(create("tell.dat", 0), "create tell.dat");

  /* 2) Open the file and write some data. */
  fd = open("tell.dat");
  CHECK(fd > 1, "open tell.dat");
  int written = write(fd, data, sizeof data - 1);
  if (written != (int)(sizeof data - 1))
    fail("write() returned %d instead of %zu", written, sizeof data - 1);

  /* 3) tell() should return the current position (end of the data). */
  pos = tell(fd);
  if (pos != written)
    fail("tell() returned %d instead of %d", pos, written);

  close(fd);

  /* 4) Re-open the file for reading. */
  fd = open("tell.dat");
  CHECK(fd > 1, "open tell.dat again");

  /* 5) Read some bytes. */
  char buffer[10];
  int read_count = read(fd, buffer, 5);
  if (read_count != 5)
    fail("read() returned %d instead of 5", read_count);

  /* 6) tell() should now be 5. */
  pos = tell(fd);
  if (pos != 5)
    fail("tell() returned %d instead of 5 after reading 5 bytes", pos);

  close(fd);
}
