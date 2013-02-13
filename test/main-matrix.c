#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int mat_mult(int*, int*, int*);


static void print_matrix3(int* m) {
	int i, j;

	for (i = 0; i < 3; ++i) {
		for (j = 0; j < 3; ++j) {
			printf("%d ", m[i*3 + j]);
		}

		printf("\n");
	}
}

int main(int argc, char** argv) {
	int A[9];
	int B[9];
	int C[9];
	int i;

	if (argc < 2) {
		printf("Usage: matrix-main.c <seed>\n");
		return 1;
	}

	srand(atoi(argv[1]));

	for (i = 0; i < 9; ++i) {
		A[i] = rand() % 100;
		B[i] = rand() % 100;
	}

	memset(C, -1, sizeof(C));
	mat_mult(A, B, C);

	printf("A is\n");
	print_matrix3(A);

	printf("\nB is\n");
	print_matrix3(B);

	printf("\nC is\n");
	print_matrix3(C);

	return 0;
}
