/*
 * ts_over_alp.c
 *
 * Copyright © 2020 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This is a quick util for generating TS-style ALP packets from raw TS data.
 * Useful for generating data to test protocol decode of TS-style ALP packets.
 * The output file format is PCAP carrying ALP packets.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define PCAP_MAGIC_NS 0xa1b23c4d
#define LINKTYPE_ALP 289

struct pcap_file_header_t {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	uint32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network;
};

struct pcap_file_entry_t {
	uint32_t ts_sec;
	uint32_t ts_nsec;
	uint32_t incl_len;
	uint32_t orig_len;
};

struct alp_ts_state_t {
	uint8_t null_count;
	uint8_t frame_count;
	uint8_t ts_frames[16][188];
};

struct input_file_t {
	FILE *fp;
	uint32_t rewind_count;
	uint8_t rewind_frames[16][188]; /* reverse order: higher index = older */
};

typedef int (*build_alp_func_t)(FILE *output_fp, struct input_file_t *input_file, bool filter_null_frames);

static uint16_t ts_get_pid(uint8_t *ts_frame)
{
	uint16_t pid;
	pid = (uint16_t)(ts_frame[1] & 0x1F) << 8;
	pid |= (uint16_t)ts_frame[2];
	return pid;
}

static bool input_file_open(struct input_file_t *input_file, const char *input_filename)
{
	input_file->fp = fopen(input_filename, "rb");
	if (!input_file->fp) {
		return false;
	}

	while (1) {
		int c = fgetc(input_file->fp);
		if ((c == 0x47) || (c < 0)) {
			break;
		}
	}

	input_file->rewind_count = 0;
	return true;
}

static bool input_file_read_frame_internal(struct input_file_t *input_file, uint8_t *ts_frame)
{
	if (input_file->rewind_count > 0) {
		memcpy(ts_frame, input_file->rewind_frames[input_file->rewind_count - 1], 188);
		input_file->rewind_count--;
		return true;
	}

	ts_frame[0] = 0x47;
	size_t offset = 1;

	while (1) {
		size_t needed = 188 - offset;
		if (fread(ts_frame + offset, 1, needed, input_file->fp) != needed) {
			return false;
		}

		int c = fgetc(input_file->fp);
		if ((c == 0x47) || (c < 0)) {
			return true;
		}

		uint8_t *ptr = ts_frame + 1;
		uint8_t *end = ts_frame + 188;
		while (ptr < end) {
			if (*ptr++ == 0x47) {
				break;
			}
		}

		if (ptr < end) {
			offset = 188 - (ptr - ts_frame) + 1;
			memmove(ts_frame + 1, ptr, offset - 1);
			continue;
		}

		if (ptr == end) {
			offset = 1;
			continue;
		}

		while (1) {
			int c = fgetc(input_file->fp);
			if (c == 0x47) {
				offset = 1;
				break;
			}
			if (c < 0) {
				return false;
			}
		}
	}
}

static bool input_file_read_frame(struct input_file_t *input_file, uint8_t *ts_frame, bool filter_null_frames)
{
	if (!filter_null_frames) {
		return input_file_read_frame_internal(input_file, ts_frame);
	}

	while (1) {
		if (!input_file_read_frame_internal(input_file, ts_frame)) {
			return false;
		}

		if (ts_get_pid(ts_frame) != 0x1FFF) {
			return true;
		}
	}
}

static void input_file_rewind_frame(struct input_file_t *input_file, uint8_t *ts_frame)
{
	if (input_file->rewind_count >= 16) {
		fprintf(stderr, "internal error: invalid rewind\n");
		return;
	}

	memcpy(input_file->rewind_frames[input_file->rewind_count], ts_frame, 188);
	input_file->rewind_count++;
}

static bool ts_valid_for_hdm(uint8_t *ts_frame0, uint8_t *ts_frame1)
{
	if (ts_frame0[1] != ts_frame1[1]) {
		return false;
	}
	if (ts_frame0[2] != ts_frame1[2]) {
		return false;
	}
	if ((ts_frame0[3] & 0xF0) != (ts_frame1[3] & 0xF0)) {
		return false;
	}
	if (((ts_frame0[3] + 1) & 0x0F) != (ts_frame1[3] & 0x0F)) {
		return false;
	}
	return true;
}

static bool write_alp_full(FILE *output_fp, struct alp_ts_state_t *state)
{
	if (state->null_count > 128) {
		fprintf(stderr, "internal error: hdm=0 dnp=%u\n", state->null_count);
		return false;
	}
	if ((state->frame_count < 1) || (state->frame_count > 16)) {
		fprintf(stderr, "internal error: hdm=0 numts=%u\n", state->frame_count);
		return false;
	}

	uint8_t alp_header[2];
	alp_header[0] = 0xE0 | ((state->frame_count & 0x0F) << 1);
	size_t alp_header_len = 1;

	if (state->null_count > 0) {
		alp_header[0] |= 0x01;
		alp_header[1] = state->null_count & 0x7F;
		alp_header_len++;
	}
		
	size_t length = alp_header_len + (state->frame_count * 187);

	struct pcap_file_entry_t file_entry;
	file_entry.ts_sec = 0;
	file_entry.ts_nsec = 0;
	file_entry.incl_len = (uint32_t)length;
	file_entry.orig_len = (uint32_t)length;

	if (fwrite(&file_entry, sizeof(file_entry), 1, output_fp) != 1) {
		fprintf(stderr, "write failed\n");
		return false;
	}

	if (fwrite(alp_header, 1, alp_header_len, output_fp) != alp_header_len) {
		fprintf(stderr, "write failed\n");
		return false;
	}

	for (uint8_t index = 0; index < state->frame_count; index++) {
		if (fwrite(state->ts_frames[index] + 1, 1, 187, output_fp) != 187) {
			fprintf(stderr, "write failed\n");
			return false;
		}
	}

	return true;
}

static bool write_alp_hdm(FILE *output_fp, struct alp_ts_state_t *state)
{
	if (state->null_count > 127) {
		fprintf(stderr, "internal error: hdm=1 dnp=%u\n", state->null_count);
		return false;
	}
	if ((state->frame_count < 2) || (state->frame_count > 16)) {
		fprintf(stderr, "internal error: hdm=1 numts=%u\n", state->frame_count);
		return false;
	}

	uint8_t alp_header[2];
	alp_header[0] = 0xE0 | ((state->frame_count & 0x0F) << 1) | 0x01;
	alp_header[1] = 0x80 | (state->null_count & 0x7F);
	size_t alp_header_len = 2;

	size_t length = alp_header_len + 187 + ((state->frame_count - 1) * 184);

	struct pcap_file_entry_t file_entry;
	file_entry.ts_sec = 0;
	file_entry.ts_nsec = 0;
	file_entry.incl_len = (uint32_t)length;
	file_entry.orig_len = (uint32_t)length;

	if (fwrite(&file_entry, sizeof(file_entry), 1, output_fp) != 1) {
		fprintf(stderr, "write failed\n");
		return false;
	}

	if (fwrite(alp_header, 1, alp_header_len, output_fp) != alp_header_len) {
		fprintf(stderr, "write failed\n");
		return false;
	}

	if (fwrite(state->ts_frames[0] + 1, 1, 187, output_fp) != 187) {
		fprintf(stderr, "write failed\n");
		return false;
	}

	for (uint8_t index = 1; index < state->frame_count; index++) {
		if (fwrite(state->ts_frames[index] + 4, 1, 184, output_fp) != 184) {
			fprintf(stderr, "write failed\n");
			return false;
		}
	}

	return true;
}

#define BUILD_ALP_RESULT_ERROR -1
#define BUILD_ALP_RESULT_COMPLETE 0
#define BUILD_ALP_RESULT_CONTINUE 1

/*
 * Least bytes: Start a new ALP packet any time header-deletion-mode can be used and any time a null TS frame is encountered.
 * This approach saves bytes but it usually results in the TS data being spread across many small ALP packets.
 */
static int build_alp_least_bytes(FILE *output_fp, struct input_file_t *input_file, bool filter_null_frames)
{
	struct alp_ts_state_t state;
	state.null_count = 0;
	state.frame_count = 0;

	if (!input_file_read_frame(input_file, state.ts_frames[0], filter_null_frames)) {
		return BUILD_ALP_RESULT_COMPLETE;
	}

	state.frame_count = 1;

	if (ts_get_pid(state.ts_frames[0]) == 0x1FFF) {
		while (1) {
			if (!input_file_read_frame(input_file, state.ts_frames[1], filter_null_frames)) {
				return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_COMPLETE : BUILD_ALP_RESULT_ERROR;
			}

			state.null_count++;
			memcpy(state.ts_frames[0], state.ts_frames[1], 188);

			if (state.null_count == 128) {
				break;
			}

			if (ts_get_pid(state.ts_frames[0]) != 0x1FFF) {
				break;
			}
		}
	}

	if (!input_file_read_frame(input_file, state.ts_frames[1], filter_null_frames)) {
		return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_COMPLETE : BUILD_ALP_RESULT_ERROR;
	}

	if (ts_get_pid(state.ts_frames[1]) == 0x1FFF) {
		input_file_rewind_frame(input_file, state.ts_frames[1]);
		return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
	}

	state.frame_count++;

	if (ts_valid_for_hdm(state.ts_frames[0], state.ts_frames[1]) && (state.null_count <= 127)) {
		while (1) {
			if (!input_file_read_frame(input_file, state.ts_frames[state.frame_count], filter_null_frames)) {
				return write_alp_hdm(output_fp, &state) ? BUILD_ALP_RESULT_COMPLETE : BUILD_ALP_RESULT_ERROR;
			}

			if (!ts_valid_for_hdm(state.ts_frames[state.frame_count - 1], state.ts_frames[state.frame_count])) {
				input_file_rewind_frame(input_file, state.ts_frames[state.frame_count]);
				return write_alp_hdm(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
			}

			state.frame_count++;
			if (state.frame_count == 16) {
				return write_alp_hdm(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
			}
		}
	}

	while (1) {
		if (!input_file_read_frame(input_file, state.ts_frames[state.frame_count], filter_null_frames)) {
			return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_COMPLETE : BUILD_ALP_RESULT_ERROR;
		}

		if (ts_get_pid(state.ts_frames[state.frame_count]) == 0x1FFF) {
			input_file_rewind_frame(input_file, state.ts_frames[state.frame_count]);
			return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
		}

		if (ts_valid_for_hdm(state.ts_frames[state.frame_count - 1], state.ts_frames[state.frame_count])) {
			input_file_rewind_frame(input_file, state.ts_frames[state.frame_count]);
			input_file_rewind_frame(input_file, state.ts_frames[state.frame_count - 1]);
			state.frame_count--;
			return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
		}

		state.frame_count++;
		if (state.frame_count == 16) {
			return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
		}
	}
}

/*
 * Least packets: Fill each ALP packet with 16 frames even if it outputting some null TS frames and/or not being able to use
 * header-deletion-mode. This approach requires fewer ALP packets to encode the TS data.
 *
 * Logic:
 * 1) Up to 128 null TS frames can be skipped before the first useful TS frame.
 * 2) Prepare to write 16 TS frames including null TS frames.
 * 3) Walk back any trailing null TS frames.
 * 4) Use header-deleteion-mode if it can be applied to all TS frames in the ALP packet.
 */
static int build_alp_least_packets(FILE *output_fp, struct input_file_t *input_file, bool filter_null_frames)
{
	struct alp_ts_state_t state;
	state.null_count = 0;
	state.frame_count = 0;

	if (!input_file_read_frame(input_file, state.ts_frames[0], filter_null_frames)) {
		return BUILD_ALP_RESULT_COMPLETE;
	}

	state.frame_count = 1;

	if (ts_get_pid(state.ts_frames[0]) == 0x1FFF) {
		while (1) {
			if (!input_file_read_frame(input_file, state.ts_frames[1], filter_null_frames)) {
				return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_COMPLETE : BUILD_ALP_RESULT_ERROR;
			}

			state.null_count++;
			memcpy(state.ts_frames[0], state.ts_frames[1], 188);

			if (state.null_count == 128) {
				break;
			}

			if (ts_get_pid(state.ts_frames[0]) != 0x1FFF) {
				break;
			}
		}
	}

	/* Read a total of 16 frames to fill ALP packet */
	while (state.frame_count < 16) {
		if (!input_file_read_frame(input_file, state.ts_frames[state.frame_count], filter_null_frames)) {
			break;
		}

		state.frame_count++;
	}

	/* Drop any trailing null TS frames */
	while (state.frame_count > 1) {
		if (ts_get_pid(state.ts_frames[state.frame_count - 1]) != 0x1FFF) {
			break;
		}

		input_file_rewind_frame(input_file, state.ts_frames[state.frame_count - 1]);
		state.frame_count--;
	}

	/* Can header-deletion-mode be used? */
	if (state.null_count == 128) {
		return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
	}

	if (state.frame_count < 2) {
		return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
	}

	for (uint8_t index = 1; index < state.frame_count; index++) {
		if (!ts_valid_for_hdm(state.ts_frames[index - 1], state.ts_frames[index])) {
			return write_alp_full(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
		}
	}

	return write_alp_hdm(output_fp, &state) ? BUILD_ALP_RESULT_CONTINUE : BUILD_ALP_RESULT_ERROR;
}

static int help(void)
{
	printf("usage: ts_over_alp [options] <input ts filename> <output pcap filename>\n");
	printf("  --least-bytes         target the smallest byte count at the expense of packet count (default)\n");
	printf("  --least-packets       target the smallest packet count at the exepnse of byte count\n");
	printf("  --filter-null-frames  filter out null frames before encoding\n");
	return 1;
}

int main(int argc, char *argv[])
{
	const char *input_filename = NULL;
	const char *output_filename = NULL;
	build_alp_func_t build_alp_func = build_alp_least_bytes;
	bool filter_null_frames = false;

	argv++; argc--;

	while (argc > 0) {
		const char *arg = *argv++; argc--;

		if (strncmp(arg, "--", 2) == 0) {
			if (strcmp(arg + 2, "least-bytes") == 0) {
				build_alp_func = build_alp_least_bytes;
				continue;
			}

			if (strcmp(arg + 2, "least-packets") == 0) {
				build_alp_func = build_alp_least_packets;
				continue;
			}

			if (strcmp(arg + 2, "filter-null-frames") == 0) {
				filter_null_frames = true;
				continue;
			}

			if (strcmp(arg + 2, "help") == 0) {
				return help();
			}

			fprintf(stderr, "ignoring invalid argument: %s\n", arg);
			continue;
		}

		if (!input_filename) {
			input_filename = arg;
			continue;
		}

		if (!output_filename) {
			output_filename = arg;
			continue;
		}

		fprintf(stderr, "too many filenames: %s\n", arg);
		return 1;
	}

	if (!output_filename) {
		return help();
	}

	struct input_file_t input_file;
	if (!input_file_open(&input_file, input_filename)) {
		fprintf(stderr, "unable to open file %s\n", input_filename);
		return 1;
	}

	FILE *output_fp = fopen(output_filename, "wb");
	if (!output_fp) {
		fprintf(stderr, "failed to create file %s\n", output_filename);
		return 1;
	}

	struct pcap_file_header_t file_header;
	file_header.magic_number = PCAP_MAGIC_NS;
	file_header.version_major = 2;
	file_header.version_minor = 4;
	file_header.thiszone = 0;
	file_header.sigfigs = 0;
	file_header.snaplen = 262144;
	file_header.network = LINKTYPE_ALP;

	if (fwrite(&file_header, sizeof(file_header), 1, output_fp) != 1) {
		fprintf(stderr, "write failed\n");
		return 1;
	}

	while (1) {
		int ret = build_alp_func(output_fp, &input_file, filter_null_frames);
		if (ret == BUILD_ALP_RESULT_ERROR) {
			return 1;
		}
		if (ret == BUILD_ALP_RESULT_COMPLETE) {
			break;
		}
	}

	fclose(output_fp);
	fclose(input_file.fp);
	return 0;
}
