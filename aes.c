#include "aes.h"

#include <stdio.h>
#include <string.h>

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
	uint8_t const *last_word = round_key + 12;
	rot_word(last_word, new_round_key);
	sbox_word(new_round_key, new_round_key);
	xor_bytes(round_key, new_round_key, new_round_key, 4);
	uint8_t rcon[4] = {0};	
	rcon_word(round, rcon);
	xor_bytes(new_round_key, rcon, new_round_key, 4);

	for (int i = 0; i < 3; i++) {
		xor_bytes(new_round_key + (i * 4),
			  round_key + ((i + 1) * 4),
			  new_round_key + ((i + 1) * 4), 4);
	}
}

void print_state(uint8_t const *state) {
	for (int i = 0; i < 16; i++) {
		if (i != 0 && i % 4 == 0) {
			printf("\n");
		}
		printf("%02x ", state[i]);
	}
}

void sbox_state(uint8_t const *state, uint8_t* state_out) {
	for (int i = 0; i < 16; i++) {
		state_out[i] = sbox_en[state[i]];
	}
}

void shift_state(uint8_t const *state, uint8_t* state_out) {
	uint8_t positions[] = {0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14};
	for (int i = 0; i < 16; i++) {
		state_out[i] = state[positions[i]];
	}
}

int test_rot_word() {
	printf("Testing rot_word()...");
	uint8_t expected[] = {0x01, 0x02, 0x03, 0x00};
	uint8_t initial[] = {0x00, 0x01, 0x02, 0x03};
	rot_word(initial, initial);
	if (memcmp(expected, initial, sizeof(expected)) != 0) {
		printf("FAILED!\n");
		return 1;
	} else {
		printf("PASSED!\n");
		return 0;
	}
}

int test_sbox_word() {
	printf("Testing sbox_word()...");
	uint8_t expected[] = {0x7c, 0x25, 0x0b, 0x77};
	uint8_t initial[] = {0x01, 0xc2, 0x9e, 0x02};
	sbox_word(initial, initial);
	if (memcmp(expected, initial, sizeof(expected)) != 0) {
		printf("FAILED!\n");
		return 1;
	} else {
		printf("PASSED!\n");
		return 0;
	}
}

int test_rcon_word() {
	printf("Testing rcon_word()...");
	uint8_t expected[] = {0x08, 0x00, 0x00, 0x00};
	uint8_t initial[] = {0x00, 0x00, 0x00, 0x00};
	rcon_word(4, initial);
	if (memcmp(expected, initial, sizeof(expected)) != 0) {
		printf("FAILED!\n");
		return 1;
	} else {
		printf("PASSED!\n");
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
		printf("FAILED!\n");
		return 1;
	} else {
		printf("PASSED!\n");
		return 0;
	}
}

int test_key_expansion_full() {
	printf("Testing key_expansion() full...");
	uint8_t initial_key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	uint8_t expected_expansion[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
		0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
		0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,
		0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,
		0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,
		0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,
		0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
		0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,
		0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,
		0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,
		0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6
	};

	uint8_t key[16] = {0};
	for (int i = 0; i < AES_128_ROUNDS; i++) {
		if (memcmp(initial_key, &expected_expansion[16 * i], 16) != 0) {
			printf("FAILED!\n");
			return 1;
		}
		key_expansion(initial_key, key, i + 1);
		memcpy(initial_key, key, 16);
	}

	printf("PASSED\n");
	return 0;
}

int test_shift_state() {
	printf("Testing shift_state()...");
	uint8_t input[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	uint8_t output[16] = {0};
	uint8_t expected[] = {0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14};
	shift_state(input, output);

	print_state(output);
	if (memcmp(output, expected, 16) != 0) {
		printf("FAILED!\n");
		return 1;
	} else {
		printf("PASSED!\n");
		return 0;
	}
	print_state(output);
}

int main() {
	test_rot_word();
	test_sbox_word();
	test_rcon_word();
	test_key_expansion();
	test_key_expansion_full();
	test_shift_state();
	uint8_t state[] = {
		0x74, 0x20, 0x6f, 0x74,
		0x68, 0x69, 0x6e, 0x65,
		0x69, 0x73, 0x65, 0x78,
		0x73, 0x20, 0x20, 0x74
	};
	print_state(state);
	return 0;
}

