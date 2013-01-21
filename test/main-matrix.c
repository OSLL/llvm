#include <stdio.h>

extern int mat_mult(int*, int*, int*);

int main() {
	int A[] = {	1, 0, 0,
				0, 1, 0,
				0, 0, 1	};

	int B[] = {	2, 0, 0,
				0, 2, 0,
				0, 0, 2	};

	int C[9];
	int i, j;


	mat_mult(A, B, C);


	for (i = 0; i < 3; ++i) {
		for (j = 0; j < 3; ++j) {
			printf("%d ", C[i*3 + j]);
		}

		printf("\n");
	}

	return 0;
}
