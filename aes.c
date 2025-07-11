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

void bb_first_byte_key_expansion(uint8_t const *key, uint8_t key_bytes, uint8_t* output, int round)
{
	uint8_t tmp[4] = {0};
	uint8_t const *last_word = key + (key_bytes - 4);
	bb_rot_word(last_word, tmp);
	bb_sbox_word(tmp, tmp);
	bb_xor_bytes(key, tmp, tmp, sizeof(tmp));
	uint8_t rcon[4] = {0};
	bb_rcon_word(round, rcon);
	bb_xor_bytes(tmp, rcon, tmp, sizeof(tmp));
	memcpy(output, tmp, sizeof(tmp));
}

void bb_other_byte_key_expansion(uint8_t const *key, uint8_t key_bytes, uint8_t* output, uint8_t byte_num)
{
	uint8_t last_offset = (byte_num - 1) * 4;
	uint8_t curr_offset = byte_num * 4;
	if (key_bytes == AES_256_KEY_BYTES && byte_num == 4) {
		bb_sbox_word(output + last_offset, output + curr_offset);
		bb_xor_bytes(output + curr_offset, key + curr_offset, output + curr_offset, 4);
	} else {
		bb_xor_bytes(output + last_offset, key + curr_offset, output + curr_offset, 4);
	}
}

/*void bb_key_expansion2(uint8_t const *key, uint8_t key_bytes, uint8_t* expansion, uint8_t expansion_size)
{
	
}*/

void bb_key_expansion(uint8_t const *round_key, uint8_t key_bytes, uint8_t* new_round_key, int round)
{
	uint8_t tmp[AES_256_KEY_BYTES] = {0};
	/*uint8_t const *last_word = round_key + (key_bytes - 4);
	bb_rot_word(last_word, tmp);
	bb_sbox_word(tmp, tmp);
	bb_xor_bytes(round_key, tmp, tmp, 4);
	uint8_t rcon[4] = {0};
	bb_rcon_word(round, rcon);
	bb_xor_bytes(tmp, rcon, tmp, 4);*/
	bb_first_byte_key_expansion(round_key, key_bytes, tmp, round);

	int nk = key_bytes / 4;
	for (int i = 1; i < nk; i++) {
		bb_other_byte_key_expansion(round_key, key_bytes, tmp, i);
	}
	memcpy(new_round_key, tmp, key_bytes);
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

void bb_encrypt(uint8_t const* plaintext, uint8_t const* key, uint8_t* ciphertext) {
	bb_add_round_key(plaintext, key, ciphertext);
	uint8_t round_key[AES_128_KEY_BYTES] = {0};
	memcpy(round_key, key, AES_128_KEY_BYTES);
	for (int i = 0; i < AES_128_ROUNDS; i++) {
		bb_sbox_state(ciphertext, ciphertext);
		bb_shift_state(ciphertext, ciphertext);
		if (i + 1 < AES_128_ROUNDS) {
			bb_mix_columns(ciphertext, ciphertext);
		}
		bb_key_expansion(round_key, sizeof(round_key), round_key, i + 1);
		bb_add_round_key(ciphertext, round_key, ciphertext);
	}
}

void bb_decrypt(uint8_t const* ciphertext, uint8_t const* key, uint8_t* plaintext) {
	uint8_t keys[AES_128_ROUNDS + 1][AES_128_KEY_BYTES] = {{0}};
	memcpy(keys[0], key, AES_128_KEY_BYTES);
	for (int i = 0; i < AES_128_ROUNDS; i++) {
		bb_key_expansion(keys[i], sizeof(keys[0]), keys[i + 1], i + 1);
	}

	bb_add_round_key(ciphertext, keys[AES_128_ROUNDS], plaintext);

	for (int i = AES_128_ROUNDS - 1; i >= 0; i--) {
		bb_inv_shift_state(plaintext, plaintext);
		bb_inv_sbox_state(plaintext, plaintext);

		bb_add_round_key(plaintext, keys[i], plaintext);

		if (i != 0) {
			bb_inv_mix_columns(plaintext, plaintext);
		}
	}
};


