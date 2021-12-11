/* tracee2.c

   A simple tracee that reverses a string

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void reverse (char *string) {
  char tmp;
  int n = strlen(string);

  for (int i = 0; i < n/2; i++) {
    tmp = string[i];
    string[i] = string[n - i - 1];
    string[n - i - 1] = tmp;
  }
}

int main(int argc, char* argv[]) {

  if (argc == 1) {
    fprintf(stderr, "usage: tracee2 STRING\n");
    exit(EXIT_FAILURE);
  }

  char **p = argv;
  p++;

  for(; *p != 0; p++) {
    reverse(*p);
    fprintf(stderr, " => %s\n", *p);
    sleep(2);
  }

  return 0;
}
