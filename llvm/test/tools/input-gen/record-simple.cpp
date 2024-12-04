// clang++

// void *alloca(size_t size);
// void *malloc(size_t size);
// int printf(const char *restrict format, ...);

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>

#define N 1000

extern "C" int foo(int *a, int *b, int *c, int n) {
  int sum = 0;
  for (int i = 0; i < n; i++) {
    c[i] = a[i] + b[i] * n;
    sum += c[i];
  }
  return sum;
}

int main() {
  int *a = (int *)malloc(N * sizeof(*a));
  int *b = (int *)malloc(N * sizeof(*b));
  int *c = (int *)alloca(N * sizeof(*c));

  for (int i = 0; i < N; i++) {
    a[i] = b[i] = i % 10;
  }

  int d = foo(a, b, c, N);
  printf("Output: %d\n", d);
  return 0;
}
