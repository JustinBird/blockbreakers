#include "aes.h"

#include <stdio.h>
#include <string.h>

#define STR_PASSED "\033[32mPASSED\033[0m!\n"
#define STR_FAILED "\033[31mFAILED\033[0m!\n"

void rot_word(uint8_t const *word, uint8_t* out) {
	uint8_t tmp = word[0];
	out[0] = word[1];
	out[1] = word[2];
	out[2] = word[3];
	out[3] = tmp;
}

void sbox_word(uint8_t const *word, uint8_t* out) {
	for (int i = 0; i < 4; i++) {
		out[i] = sbox_en[word[i]];
	}
}

void rcon_word(int i, uint8_t* out) {
	out[0] = rcon[i];
}

void xor_bytes(uint8_t const *left, uint8_t const *right, uint8_t* out, int bytes) {
	for(int i = 0; i < bytes; i++) {
		out[i] = left[i] ^ right[i];
	}
}

void print_bytes(char const *message, uint8_t const *bytes, int num) {
	printf("%s: ", message);
	for (int i = 0; i < num; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n");
}

void key_expansion(uint8_t const *round_key, uint8_t* new_round_key, int round) {
	uint8_t tmp[AES_128_BYTES] = {0};
	uint8_t const *last_word = round_key + 12;
	rot_word(last_word, tmp);
	sbox_word(tmp, tmp);
	xor_bytes(round_key, tmp, tmp, 4);
	uint8_t rcon[4] = {0};
	rcon_word(round, rcon);
	xor_bytes(tmp, rcon, tmp, 4);

	for (int i = 0; i < 3; i++) {
		xor_bytes(tmp + (i * 4),
			  round_key + ((i + 1) * 4),
			  tmp + ((i + 1) * 4), 4);
	}
	memcpy(new_round_key, tmp, AES_128_BYTES);
}

void print_state(uint8_t const *state) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x ", state[(j * 4) + i]);
		}
		printf("\n");
	}
}

void copy_state(uint8_t const *state1, uint8_t* state2) {
	memcpy(state2, state1, AES_128_BYTES);
}

void sbox_state_ex(uint8_t const *state, uint8_t* state_out, uint8_t* sbox) {
	for (int i = 0; i < AES_128_BYTES; i++) {
		state_out[i] = sbox[state[i]];
	}
}

void sbox_state(uint8_t const *state, uint8_t* state_out) {
	sbox_state_ex(state, state_out, sbox_en);
}

void inv_sbox_state(uint8_t const *state, uint8_t* state_out) {
	sbox_state_ex(state, state_out, sbox_dec);
}

void shift_state_ex(uint8_t const* state, uint8_t* state_out, uint8_t const* shift) {
	uint8_t tmp_state[AES_128_BYTES] = {0};
	for (int i = 0; i < AES_128_BYTES; i++) {
		tmp_state[i] = state[shift[i]];
	}

	copy_state(tmp_state, state_out);
}

void shift_state(uint8_t const *state, uint8_t* state_out) {
	uint8_t positions[] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
	shift_state_ex(state, state_out, positions);
}

void inv_shift_state(uint8_t const *state, uint8_t* state_out) {
	uint8_t positions[] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
	shift_state_ex(state, state_out, positions);
}

void mix_columns(uint8_t const *state, uint8_t* state_out, uint8_t* matrix) {
	uint8_t tmp_state[AES_128_BYTES] = {0};
	for (int column = 0; column < 4; column++) {
		for (int row = 0; row < 4; row++) {
			int out_pos = (column * 4) + row;
			int answer = 0;
			for (int i = 0; i < 4; i++) {
				int read_pos = (column * 4) + i;
				int matrix_pos = (row * 4) + i;
				//printf("(%02x * %d) + ", state[read_pos], matrix[matrix_pos]);
				switch (matrix[matrix_pos]) {
				case 1:
					answer ^= state[read_pos];
					break;
				case 2:
					answer ^= multiplication_by_2[state[read_pos]];
					break;
				case 3:
					answer ^= multiplication_by_3[state[read_pos]];
					break;
				case 9:
					answer ^= multiplication_by_9[state[read_pos]];
					break;
				case 11:
					answer ^= multiplication_by_11[state[read_pos]];
					break;
				case 13:
					answer ^= multiplication_by_13[state[read_pos]];
					break;
				case 14:
					answer ^= multiplication_by_14[state[read_pos]];
					break;
				}
			}
			tmp_state[out_pos] = answer;
			//printf(" = %02x\n", tmp_state[out_pos]);
		}
	}
	copy_state(tmp_state, state_out);
}

void mix_columns_enc(uint8_t const* state, uint8_t* state_out) {
	uint8_t matrix[] = {2, 3, 1, 1, 1, 2, 3 ,1, 1, 1, 2, 3, 3, 1, 1, 2};
	mix_columns(state, state_out, matrix);
}

void mix_columns_dec(uint8_t const* state, uint8_t* state_out) {
	uint8_t matrix[] = {14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14};
	mix_columns(state, state_out, matrix);
}

void add_round_key(uint8_t const* state, uint8_t const* round_key, uint8_t* state_out) {
	for (int i = 0; i < AES_128_BYTES; i++) {
		state_out[i] = state[i] ^ round_key[i];
	}
}

void encrypt(uint8_t const* plaintext, uint8_t const* key, uint8_t* ciphertext) {
	add_round_key(plaintext, key, ciphertext);
	uint8_t round_key[AES_128_BYTES] = {0};
	memcpy(round_key, key, AES_128_BYTES);
	for (int i = 0; i < AES_128_ROUNDS; i++) {
		sbox_state(ciphertext, ciphertext);
		shift_state(ciphertext, ciphertext);
		if (i + 1 < AES_128_ROUNDS) {
			mix_columns_enc(ciphertext, ciphertext);
		}
		key_expansion(round_key, round_key, i + 1);
		add_round_key(ciphertext, round_key, ciphertext);
	}
}

void decrypt(uint8_t const* ciphertext, uint8_t const* key, uint8_t* plaintext) {
	uint8_t keys[AES_128_ROUNDS + 1][AES_128_BYTES] = {{0}};
	memcpy(keys[0], key, AES_128_BYTES);
	for (int i = 0; i < AES_128_ROUNDS; i++) {
		key_expansion(keys[i], keys[i + 1], i + 1);
	}
	printf("ciphertext:\n");
	print_state(ciphertext);
	printf("\n");

	printf("key:\n");
	print_state(keys[AES_128_ROUNDS]);
	printf("\n");

	add_round_key(ciphertext, keys[AES_128_ROUNDS], plaintext);
	printf("add_round_key:\n");
	print_state(plaintext);
	printf("\n");

	for (int i = AES_128_ROUNDS - 1; i >= 0; i--) {
		inv_shift_state(plaintext, plaintext);
		printf("shift_state:\n");
		print_state(plaintext);
		printf("\n");
		inv_sbox_state(plaintext, plaintext);
		printf("sbox_state:\n");
		print_state(plaintext);
		printf("\n");

		printf("key:\n");
		print_state(keys[i]);
		printf("\n");

		add_round_key(plaintext, keys[i], plaintext);
		printf("add_round_key:\n");
		print_state(plaintext);
		printf("\n");

		if (i != 0) {
			mix_columns_dec(plaintext, plaintext);
			printf("shift_state:\n");
			print_state(plaintext);
			printf("\n");
		}
	}
};


int test_rot_word() {
	printf("Testing rot_word()...");
	uint8_t expected[] = {0x01, 0x02, 0x03, 0x00};
	uint8_t initial[] = {0x00, 0x01, 0x02, 0x03};
	rot_word(initial, initial);
	if (memcmp(expected, initial, sizeof(expected)) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_sbox_word() {
	printf("Testing sbox_word()...");
	uint8_t expected[] = {0x7c, 0x25, 0x0b, 0x77};
	uint8_t initial[] = {0x01, 0xc2, 0x9e, 0x02};
	sbox_word(initial, initial);
	if (memcmp(expected, initial, sizeof(expected)) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_rcon_word() {
	printf("Testing rcon_word()...");
	uint8_t expected[] = {0x08, 0x00, 0x00, 0x00};
	uint8_t initial[] = {0x00, 0x00, 0x00, 0x00};
	rcon_word(4, initial);
	if (memcmp(expected, initial, sizeof(expected)) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_key_expansion() {
	printf("Testing key_expansion()...");
	uint8_t round_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t expected[] = {0xd6, 0xaa, 0x74, 0xfd};
	uint8_t new_key[] = {0x00, 0x00, 0x00, 0x00};
	key_expansion(round_key, new_key, 1);
	if (memcmp(expected, new_key, sizeof(expected)) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_key_expansion_full() {
	printf("Testing key_expansion() full...");
	uint8_t key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	uint8_t expected_expansion[AES_128_ROUNDS][AES_128_BYTES] = {
		{0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1,
		 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05},
		{0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43,
		 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f},
		{0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e,
		 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b},
		{0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f,
		 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00},
		{0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87,
		 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc},
		{0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd,
		 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd},
		{0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3,
		 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f},
		{0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2,
		 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f},
		{0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21,
		 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e},
		{0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89,
		 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6}
	};

	for (int i = 0; i < AES_128_ROUNDS; i++) {
		key_expansion(key, key, i + 1);
		if (memcmp(key, expected_expansion[i], AES_128_BYTES) != 0) {
			printf(STR_FAILED);
			return 1;
		}
	}

	printf(STR_PASSED);
	return 0;
}

int test_sbox_state() {
	printf("Testing sbox_state()...");
	uint8_t state[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	uint8_t expected[] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
		0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
	};
	sbox_state(state, state);
	
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_inv_sbox_state() {
	printf("Testing inv_sbox_state()...");
	uint8_t state[] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
		0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
	};
	uint8_t expected[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	
	inv_sbox_state(state, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_shift_state() {
	printf("Testing shift_state()...");
	uint8_t state[] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
		0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
	};
	uint8_t expected[] = {
		0x63, 0x6b, 0x67, 0x76, 0xf2, 0x01, 0xab, 0x7b,
		0x30, 0xd7, 0x77, 0xc5, 0xfe, 0x7c, 0x6f, 0x2b
	};
	shift_state(state, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_inv_shift_state() {
	printf("Testing inv_shift_state()...");
	uint8_t state[] = {
		0x63, 0x6b, 0x67, 0x76, 0xf2, 0x01, 0xab, 0x7b,
		0x30, 0xd7, 0x77, 0xc5, 0xfe, 0x7c, 0x6f, 0x2b
	};
	uint8_t expected[] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
		0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
	};
	inv_shift_state(state, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_mix_columns_enc() {
	printf("Testing mix_columns_enc()...");
	uint8_t state[] = {
		0x63, 0x6b, 0x67, 0x76, 0xf2, 0x01, 0xab, 0x7b,
		0x30, 0xd7, 0x77, 0xc5, 0xfe, 0x7c, 0x6f, 0x2b
	};
	uint8_t expected[] = {
		0x6a, 0x6a, 0x5c, 0x45, 0x2c, 0x6d, 0x33, 0x51,
		0xb0, 0xd9, 0x5d, 0x61, 0x27, 0x9c, 0x21, 0x5c
	};
	mix_columns_enc(state, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_mix_columns_dec() {
	printf("Testing mix_columns_dec()...");
	uint8_t state[] = {
		0x6a, 0x6a, 0x5c, 0x45, 0x2c, 0x6d, 0x33, 0x51,
		0xb0, 0xd9, 0x5d, 0x61, 0x27, 0x9c, 0x21, 0x5c
	};
	uint8_t expected[] = {
		0x63, 0x6b, 0x67, 0x76, 0xf2, 0x01, 0xab, 0x7b,
		0x30, 0xd7, 0x77, 0xc5, 0xfe, 0x7c, 0x6f, 0x2b
	};
	mix_columns_dec(state, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_add_round_key() {
	printf("Testing add_round_key()...");
	uint8_t state[] = {
		0x6a, 0x6a, 0x5c, 0x45, 0x2c, 0x6d, 0x33, 0x51,
		0xb0, 0xd9, 0x5d, 0x61, 0x27, 0x9c, 0x21, 0x5c
	};
	uint8_t round_key[] = {
		0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa,
		0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe
	};
	uint8_t expected[] = {
		0xbc, 0xc0, 0x28, 0xb8, 0xfe, 0xc2, 0x41, 0xab,
		0x6a, 0x7f, 0x25, 0x90, 0xf1, 0x37, 0x57, 0xa2
	};
	add_round_key(state, round_key, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
};

int test_full_round() {
	printf("Testing full round...");
	uint8_t state[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	uint8_t round_key[] = {
		0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa,
		0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe
	};
	uint8_t expected[] = {
		0xbc, 0xc0, 0x28, 0xb8, 0xfe, 0xc2, 0x41, 0xab,
		0x6a, 0x7f, 0x25, 0x90, 0xf1, 0x37, 0x57, 0xa2
	};
	sbox_state(state, state);
	shift_state(state, state);
	mix_columns_enc(state, state);
	add_round_key(state, round_key, state);
	if (memcmp(state, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_encrypt() {
	printf("Testing encrypt()...");
	uint8_t plaintext[] = {'t','h','e','b','l','o','c','k','b','r','e','a','k','e','r','s'};
	uint8_t key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	uint8_t ciphertext[AES_128_BYTES] = {};
	uint8_t expected[] = {
		0xc6, 0x9f, 0x25, 0xd0, 0x02, 0x5a, 0x9e, 0xf3,
		0x23, 0x93, 0xf6, 0x3e, 0x2f, 0x05, 0xb7, 0x47
	};
	encrypt(plaintext, key, ciphertext);
	if (memcmp(ciphertext, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_encrypt_nist() {
	printf("Testing encrypt() with NIST vector...");
	uint8_t plaintext[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	uint8_t ciphertext[AES_128_BYTES] = {};
	uint8_t expected[] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
	};
	encrypt(plaintext, key, ciphertext);
	if (memcmp(ciphertext, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}

int test_decrypt_nist() {
	printf("Testing decrypt() with NIST vector...");
	uint8_t ciphertext[] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
	};
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	uint8_t plaintext[AES_128_BYTES] = {};
	uint8_t expected[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	};
	decrypt(ciphertext, key, plaintext);
	if (memcmp(plaintext, expected, AES_128_BYTES) != 0) {
		printf(STR_FAILED);
		return 1;
	} else {
		printf(STR_PASSED);
		return 0;
	}
}
int main() {
	test_rot_word();
	test_sbox_word();
	test_rcon_word();
	test_key_expansion();
	test_key_expansion_full();
	test_sbox_state();
	test_inv_sbox_state();
	test_shift_state();
	test_inv_shift_state();
	test_mix_columns_enc();
	test_mix_columns_dec();
	test_add_round_key();
	test_full_round();
	test_encrypt();
	test_encrypt_nist();
	test_decrypt_nist();
	return 0;

	uint8_t state[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
	print_state(state);
	sbox_state(state, state);
	print_state(state);
	uint8_t out[AES_128_BYTES] = {0};
	shift_state(state, out);
	print_state(out);
	uint8_t out2[AES_128_BYTES] = {0};
	//mix_columns(out, out2);
	print_state(out2);
}

