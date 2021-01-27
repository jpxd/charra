/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file attester_tcp.c
 * @author Jan Dahms (jan.philipp.dahms@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2021-01-01
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include "common/charra_log.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/cbor_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* logging */
#define LOG_NAME "attester"
// #define LOG_LEVEL_CBOR LOG_DEBUG
#define LOG_LEVEL_CHARRA CHARRA_LOG_INFO
// #define LOG_LEVEL_CHARRA CHARRA_LOG_DEBUG

/* config */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5000
#define CBOR_ENCODER_BUFFER_LENGTH 20480 // 20 KiB should be sufficient

/* --- main --------------------------------------------------------------- */

int create_connection()
{
    char host_ip[] = SERVER_IP;
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(host_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SERVER_PORT);

    int sock =  socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
		//fprintf(stderr, "socket: %s , errno %d\n", strerror(errno), errno);
		charra_log_error("[" LOG_NAME "] Unable to create socket.");
		return -1;
    }
    charra_log_info("[" LOG_NAME "] Socket created, connecting.");

    int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));
    if (err != 0) {
        charra_log_error("[" LOG_NAME "] Socket unable to connect.");
        return -1;
    }
    charra_log_info("[" LOG_NAME "] Successfully connected to server.");
    return sock;
}

void close_connection(int sock)
{
    if (sock != -1) {
        charra_log_info("[" LOG_NAME "] Shutting down socket.");
        shutdown(sock, 0);
        close(sock);
    }
}

int main(void) {
	/* set CHARRA log level*/
	charra_log_set_level(LOG_LEVEL_CHARRA);
	charra_log_info("[" LOG_NAME "] Starting up.");

	/* create connection */
	uint8_t rxtx_buffer[4*1024];
    int sock = create_connection();
	if (sock == -1) {
		return 1;
	}

    // Receive data
    charra_log_info("[" LOG_NAME "] Waiting for request");
    int data_len = recv(sock, rxtx_buffer, sizeof(rxtx_buffer), 0);
    if (data_len < 0) {
        charra_log_error("[" LOG_NAME "] Receiving failed.");
        return 1;
    }
    charra_log_info("[" LOG_NAME "] Received request.");

	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	TSS2_RC tss_r = 0;
	ESYS_TR sig_key_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC* public_key = NULL;

	/* unmarshal data */
	charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
	msg_attestation_request_dto req = {0};
	if ((charra_r = unmarshal_attestation_request(data_len, rxtx_buffer, &req)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto error;
	}

	/* --- TPM quote --- */

	charra_log_info("[" LOG_NAME "] Preparing TPM quote data.");

	/* nonce */
	if (req.nonce_len > sizeof(TPMU_HA)) {
		charra_log_error("[" LOG_NAME "] Nonce too long.");
		goto error;
	}
	TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
	qualifying_data.size = req.nonce_len;
	memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);

	charra_log_info("Received nonce of length %d:", req.nonce_len);
	charra_print_hex(req.nonce_len, req.nonce, "                                   0x", "\n", false);

	/* PCR selection */
	TPML_PCR_SELECTION pcr_selection = {0};
	if ((charra_r = charra_pcr_selections_to_tpm_pcr_selections(req.pcr_selections_len, req.pcr_selections, &pcr_selection)) !=
		CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] PCR selection conversion error.");
		goto error;
	}

	/* initialize ESAPI */
	ESYS_CONTEXT* esys_ctx = NULL;
	if ((tss_r = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Esys_Initialize.");
		goto error;
	}

	/* load TPM key */
	charra_log_info("[" LOG_NAME "] Loading TPM key.");
	if ((charra_r = charra_load_tpm2_key(esys_ctx, req.sig_key_id_len,
			 req.sig_key_id, &sig_key_handle,
			 &public_key)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not load TPM key.");
		goto error;
	}

	/* do the TPM quote */
	charra_log_info("[" LOG_NAME "] Do TPM Quote.");
	TPM2B_ATTEST* attest_buf = NULL;
	TPMT_SIGNATURE* signature = NULL;
	if ((tss_r = tpm2_quote(esys_ctx, sig_key_handle, &pcr_selection,
			 &qualifying_data, &attest_buf, &signature)) != TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] TPM2 quote.");
		goto error;
	} else {
		charra_log_info("[" LOG_NAME "] TPM Quote successful.");
	}

	/* --- send response data --- */

	/* prepare response */
	charra_log_info("[" LOG_NAME "] Preparing response.");
	msg_attestation_response_dto res = {
		.attestation_data_len = attest_buf->size,
		.attestation_data = {0}, // must be memcpy'd, see below
		.tpm2_signature_len = sizeof(*signature),
		.tpm2_signature = {0},
		.tpm2_public_key_len = sizeof(*public_key),
		.tpm2_public_key = {0}}; // must be memcpy'd, see below
	memcpy(res.attestation_data, attest_buf->attestationData,
		res.attestation_data_len);
	memcpy(res.tpm2_signature, signature, res.tpm2_signature_len);
	memcpy(res.tpm2_public_key, public_key, res.tpm2_public_key_len);

	/* marshal response */
	charra_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
	uint32_t res_buf_len = 0;
	uint8_t* res_buf = NULL;
	marshal_attestation_response(&res, &res_buf_len, &res_buf);

	/* send data */
	int err = send(sock, res_buf, res_buf_len, 0);
    if (err < 0) {
        charra_log_error("[" LOG_NAME "] Error occurred during sending");
        return 1;
    }

error:
	/* flush handles */
	if (sig_key_handle != ESYS_TR_NONE) {
		if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
			charra_log_error(
				"[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
		}
	}
	/* finalize ESAPI */
	Esys_Finalize(&esys_ctx);
	
	/* close connection */
	close_connection(sock);

	return 0;
}
