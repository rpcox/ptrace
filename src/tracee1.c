/* tracee1.c

   A simple tracee

 */

#include <stdio.h>
#include <unistd.h>

int main () {
  int i;

  for (i=0; i<10; ++i) {
    printf("-> %d\n", i);
    sleep(2);
  }

  return 0;
}
