#include "aes.h"

#include <stdio.h>
#include <string.h>

void bb_rot_word(uint8_t const *word, uint8_t* out) {
	uint8_t tmp = word[0];
	out[0] = word[1];
	out[1] = word[2];
	out[2] = word[3];
	out[3] = tmp;
}

void bb_sbox_word(uint8_t const *word, uint8_t* out) {
	for (int i = 0; i < 4; i++) {
		out[i] = sbox_en[word[i]];
	}
}

void bb_rcon_word(int i, uint8_t* out) {
	out[0] = rcon[i];
}

void bb_xor_bytes(uint8_t const *left, uint8_t const *right, uint8_t* out, int bytes) {
	for(int i = 0; i < bytes; i++) {
		out[i] = left[i] ^ right[i];
	}
}

void bb_print_bytes(char const *message, uint8_t const *bytes, int num) {
	printf("%s: ", message);
	for (int i = 0; i < num; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n");
}

void bb_first_word_key_expansion(uint8_t const *key, uint8_t key_bytes, uint8_t* output, int round)
{
	uint8_t tmp[4] = { 0 };
	uint8_t const *last_word = key + (key_bytes - 4);
	bb_rot_word(last_word, tmp);
	bb_sbox_word(tmp, tmp);
	bb_xor_bytes(key, tmp, tmp, 4);
	uint8_t rcon[4] = {0};
	bb_rcon_word(round, rcon);
	bb_xor_bytes(tmp, rcon, tmp, 4);
	memcpy(output, tmp, 4);
}

void bb_other_word_key_expansion(uint8_t const *key, uint8_t key_bytes, uint8_t* output, uint8_t word_num)
{
	uint8_t last_offset = (word_num - 1) * 4;
	uint8_t curr_offset = word_num * 4;
	if (key_bytes == AES_256_KEY_BYTES && word_num == 4) {
		uint8_t tmp[4] = { 0 };
		bb_sbox_word(output + last_offset, tmp);
		bb_xor_bytes(tmp, key + curr_offset, output + curr_offset, 4);
	} else {
		bb_xor_bytes(output + last_offset, key + curr_offset, output + curr_offset, 4);
	}
}

void bb_key_expansion(uint8_t const *key, uint8_t key_bytes, uint8_t* new_key, int key_num)
{
	bb_first_word_key_expansion(key, key_bytes, new_key, key_num);

	int nk = key_bytes / 4;
	for (int i = 1; i < nk; i++) {
		bb_other_word_key_expansion(key, key_bytes, new_key, i);
	}
}

void bb_print_state(uint8_t const *state) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02x ", state[(j * 4) + i]);
		}
		printf("\n");
	}
}

void bb_copy_state(uint8_t const *state1, uint8_t* state2) {
	memcpy(state2, state1, AES_128_KEY_BYTES);
}

void bb_sbox_state_ex(uint8_t const *state, uint8_t* state_out, const uint8_t* sbox) {
	for (int i = 0; i < AES_128_KEY_BYTES; i++) {
		state_out[i] = sbox[state[i]];
	}
}

void bb_sbox_state(uint8_t const *state, uint8_t* state_out) {
	bb_sbox_state_ex(state, state_out, sbox_en);
}

void bb_inv_sbox_state(uint8_t const *state, uint8_t* state_out) {
	bb_sbox_state_ex(state, state_out, sbox_dec);
}

void bb_shift_state_ex(uint8_t const* state, uint8_t* state_out, uint8_t const* shift) {
	uint8_t tmp_state[AES_128_KEY_BYTES] = {0};
	for (int i = 0; i < AES_128_KEY_BYTES; i++) {
		tmp_state[i] = state[shift[i]];
	}

	bb_copy_state(tmp_state, state_out);
}

void bb_shift_state(uint8_t const *state, uint8_t* state_out) {
	uint8_t positions[] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
	bb_shift_state_ex(state, state_out, positions);
}

void bb_inv_shift_state(uint8_t const *state, uint8_t* state_out) {
	uint8_t positions[] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
	bb_shift_state_ex(state, state_out, positions);
}

void bb_mix_columns_ex(uint8_t const *state, uint8_t* state_out, uint8_t* matrix) {
	uint8_t tmp_state[AES_128_KEY_BYTES] = {0};
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
	bb_copy_state(tmp_state, state_out);
}

void bb_mix_columns(uint8_t const* state, uint8_t* state_out) {
	uint8_t matrix[] = {2, 3, 1, 1, 1, 2, 3 ,1, 1, 1, 2, 3, 3, 1, 1, 2};
	bb_mix_columns_ex(state, state_out, matrix);
}

void bb_inv_mix_columns(uint8_t const* state, uint8_t* state_out) {
	uint8_t matrix[] = {14, 11, 13, 9, 9, 14, 11, 13, 13, 9, 14, 11, 11, 13, 9, 14};
	bb_mix_columns_ex(state, state_out, matrix);
}

void bb_add_round_key(uint8_t const* state, uint8_t const* round_key,  uint8_t* state_out) {
	for (int i = 0; i < AES_BLOCK_SIZE; i++) {
		state_out[i] = state[i] ^ round_key[i];
	}
}

void bb_encrypt_round(uint8_t* data, uint8_t* key)
{
	bb_sbox_state(data, data);
	bb_shift_state(data, data);
	bb_mix_columns(data, data);
	bb_add_round_key(data, key, data);

}

void bb_encrypt_last_round(uint8_t* data, uint8_t* key)
{
	bb_sbox_state(data, data);
	bb_shift_state(data, data);
	bb_add_round_key(data, key, data);
}

void bb_encrypt_128(uint8_t const* plaintext, uint8_t const* key, uint8_t* ciphertext)
{
	bb_add_round_key(plaintext, key, ciphertext);
	uint8_t round_key[AES_128_KEY_BYTES] = {0};
	memcpy(round_key, key, AES_128_KEY_BYTES);
	for (int i = 1; i < AES_128_ROUNDS; i++) {
		bb_key_expansion(round_key, sizeof(round_key), round_key, i);
		bb_encrypt_round(ciphertext, round_key);
	}
	bb_key_expansion(round_key, sizeof(round_key), round_key, AES_128_ROUNDS);
	bb_encrypt_last_round(ciphertext, round_key);
}

void bb_encrypt_192(uint8_t const* plaintext, uint8_t const* key, uint8_t* ciphertext)
{
	int key_size = AES_192_KEY_BYTES;
	int key_rounds = AES_192_ROUNDS;
	bb_add_round_key(plaintext, key, ciphertext);
	uint8_t round_key[AES_192_KEY_BYTES * 2] = {0};
	memcpy(round_key, key, key_size);
	int key_num = 1;

	uint8_t* second_key_start = round_key + AES_192_KEY_BYTES;
	bb_key_expansion(round_key, AES_192_KEY_BYTES, second_key_start, key_num++);
	int key_bytes_used = AES_BLOCK_SIZE;
	int key_bytes_remaining = sizeof(round_key) - key_bytes_used;

	for (int i = 1; i < key_rounds; i++) {
		if (key_bytes_remaining < AES_BLOCK_SIZE) {
			bb_key_expansion(second_key_start, AES_192_KEY_BYTES, round_key, key_num++);
			bb_key_expansion(round_key, AES_192_KEY_BYTES, second_key_start, key_num++);
			key_bytes_used = 0;
			key_bytes_remaining = sizeof(round_key);
		}

		bb_encrypt_round(ciphertext, round_key + key_bytes_used);
		key_bytes_used += AES_BLOCK_SIZE;
		key_bytes_remaining -= AES_BLOCK_SIZE;
	}
	if (key_bytes_remaining < AES_BLOCK_SIZE) {
		bb_key_expansion(second_key_start, AES_192_KEY_BYTES, round_key, key_num++);
		bb_key_expansion(round_key, AES_192_KEY_BYTES, second_key_start, key_num++);
		key_bytes_used = 0;
		key_bytes_remaining = sizeof(round_key);
	}
	bb_encrypt_last_round(ciphertext, round_key + key_bytes_used);
}

void bb_encrypt_256(uint8_t const* plaintext, uint8_t const* key, uint8_t* ciphertext)
{
	bb_add_round_key(plaintext, key, ciphertext);
	uint8_t round_key[AES_256_KEY_BYTES] = {0};
	memcpy(round_key, key, AES_256_KEY_BYTES);
	int round_key_offset = AES_BLOCK_SIZE;
	int round_key_num = 1;
	for (int i = 1; i < AES_256_ROUNDS; i++) {
		bb_encrypt_round(ciphertext, round_key + round_key_offset);
		if (i % 2 == 1) {
			bb_key_expansion(round_key, sizeof(round_key), round_key, round_key_num++);
			round_key_offset = 0;
		} else {
			round_key_offset = AES_BLOCK_SIZE;
		}
	}
	bb_encrypt_last_round(ciphertext, round_key);
}

void bb_decrypt_rounds(uint8_t const* ciphertext, uint8_t* plaintext, uint8_t const* keys, uint32_t rounds)
{
	bb_add_round_key(ciphertext, keys, plaintext);
	keys -= AES_BLOCK_SIZE;

	for (int i = rounds - 1; i >= 0; i--) {
		bb_inv_shift_state(plaintext, plaintext);
		bb_inv_sbox_state(plaintext, plaintext);

		bb_add_round_key(plaintext, keys, plaintext);
		keys -= AES_BLOCK_SIZE;
		if (i != 0) {
			bb_inv_mix_columns(plaintext, plaintext);
		}
	}
}

void bb_decrypt_128(uint8_t const* ciphertext, uint8_t const* key, uint8_t* plaintext) {
	uint8_t keys[AES_128_KEY_BYTES * AES_128_NEEDED_KEYS] = {0};
	uint32_t key_size = AES_128_KEY_BYTES;
	memcpy(keys, key, key_size);
	for (int i = 1; i < AES_128_NEEDED_KEYS; i++) {
		uint8_t* read_offset = keys + ((i - 1) * key_size);
		uint8_t* write_offset = keys + (i * key_size);
		bb_key_expansion(read_offset, key_size, write_offset, i);
	}
	uint8_t* key_offset = keys + (AES_128_EXPANDED_KEY_BYTES - AES_BLOCK_SIZE);
	bb_decrypt_rounds(ciphertext, plaintext, key_offset, AES_128_ROUNDS);

/*	for (int i = AES_128_ROUNDS - 1; i >= 0; i--) {
		bb_inv_shift_state(plaintext, plaintext);
		bb_inv_sbox_state(plaintext, plaintext);

		bb_add_round_key(plaintext, keys[i], plaintext);

		if (i != 0) {
			bb_inv_mix_columns(plaintext, plaintext);
		}
	}*/
};

void bb_decrypt_192(uint8_t const* ciphertext, uint8_t const* key, uint8_t* plaintext) {
	uint8_t keys[AES_192_KEY_BYTES * AES_192_NEEDED_KEYS] = {0};
	uint32_t key_size = AES_192_KEY_BYTES;
	memcpy(keys, key, key_size);
	for (uint32_t i = 1; i < AES_192_NEEDED_KEYS; i++) {
		uint8_t* read_offset = keys + ((i - 1) * key_size);
		uint8_t* write_offset = keys + (i * key_size);
		bb_key_expansion(read_offset, key_size, write_offset, i);
	}
	uint8_t* key_offset = keys + (AES_192_EXPANDED_KEY_BYTES - AES_BLOCK_SIZE);
	bb_decrypt_rounds(ciphertext, plaintext, key_offset, AES_192_ROUNDS);
};

void bb_decrypt_256(uint8_t const* ciphertext, uint8_t const* key, uint8_t* plaintext) {
	uint8_t keys[AES_256_KEY_BYTES * AES_256_NEEDED_KEYS] = {0};
	uint32_t key_size = AES_256_KEY_BYTES;
	memcpy(keys, key, key_size);
	for (uint32_t i = 1; i < AES_256_NEEDED_KEYS; i++) {
		uint8_t* read_offset = keys + ((i - 1) * key_size);
		uint8_t* write_offset = keys + (i * key_size);
		bb_key_expansion(read_offset, key_size, write_offset, i);
	}
	uint8_t* key_offset = keys + (AES_256_EXPANDED_KEY_BYTES - AES_BLOCK_SIZE);
	bb_decrypt_rounds(ciphertext, plaintext, key_offset, AES_256_ROUNDS);
};
