/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file verifier_tcp.c
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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include "common/charra_log.h"
#include "core/charra_dto.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "core/charra_rim_mgr.h"
#include "util/charra_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* logging */
#define LOG_NAME "verifier"
// #define LOG_LEVEL_CBOR LOG_DEBUG
#define LOG_LEVEL_CHARRA CHARRA_LOG_DEBUG
// #define LOG_LEVEL_CHARRA CHARRA_LOG_DEBUG

/* config */
#define PORT 5000
#define RXTXBUFSIZE 20480
#define CBOR_ENCODER_BUFFER_LENGTH 20480   // 20 KiB should be sufficient
#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"
static const uint8_t TPM_PCR_SELECTION[TPM2_MAX_PCRS] = {0, 1, 2, 3, 4, 5, 6, 7, 10};
static const uint32_t TPM_PCR_SELECTION_LEN = 9;

/* --- function forward declarations -------------------------------------- */

static CHARRA_RC create_attestation_request(msg_attestation_request_dto* attestation_request);

/* --- main --------------------------------------------------------------- */


void handle_connection(int sock) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	CHARRA_RC charra_err = CHARRA_RC_SUCCESS;
	TSS2_RC tss_r = 0;

	uint8_t* rxtx_buf = calloc(0, RXTXBUFSIZE);
	charra_log_info("[" LOG_NAME "] Starting up.");

	/* create attestation request */
	msg_attestation_request_dto req = {0};
	if (create_attestation_request(&req) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
		goto error;
	}

	/* marshal attestation request */
	charra_log_info("[" LOG_NAME "] Marshaling attestation request data to CBOR.");
	uint32_t req_buf_len = 0;
	uint8_t* req_buf = NULL;
	if ((charra_err = marshal_attestation_request(&req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Marshaling attestation request data failed.");
		goto error;
	}

	/* copy request into rxtx_buf */
	memcpy(rxtx_buf, req_buf, req_buf_len);

	/* send request */
	charra_log_info("[" LOG_NAME "] Sending request message.");
	int err = send(sock, rxtx_buf, req_buf_len, 0);
    if (err < 0) {
        charra_log_error("[" LOG_NAME "] Error occurred during sending: errno %d", errno);
        goto error;
    }

	/* --- receive incoming data --- */
	ESYS_TR sig_key_handle = ESYS_TR_NONE;
	TPMT_TK_VERIFIED* validation = NULL;

	/* read data */
    charra_log_info("[" LOG_NAME "] Waiting for response");
    int data_len = recv(sock, rxtx_buf, RXTXBUFSIZE, 0);
    if (data_len < 0) {
        charra_log_error("[" LOG_NAME "] Recv failed: errno %d", errno);
        goto error;
    }
	charra_log_info("[" LOG_NAME "] Received data of length %zu.", data_len);

	/* unmarshal data */
	charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
	msg_attestation_response_dto res = {0};
	if ((charra_err = unmarshal_attestation_response(data_len, rxtx_buf, &res)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto error;
	}

	/* verify data */
	if (res.attestation_data_len > sizeof(TPM2B_ATTEST)) {
		charra_log_error("[" LOG_NAME "] Length of attestation data exceeds maximum allowed size.");
		goto error;
	}
	if (res.tpm2_signature_len > sizeof(TPMT_SIGNATURE)) {
		charra_log_error("[" LOG_NAME "] Length of signature exceeds maximum allowed size.");
		goto error;
	}

	/* --- verify TPM Quote --- */
	charra_log_info("[" LOG_NAME "] Starting verification.");

	/* initialize ESAPI */
	ESYS_CONTEXT* esys_ctx = NULL;
	if ((tss_r = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Esys_Initialize.");
		goto error;
	}

	/* load TPM key */
	charra_log_info("[" LOG_NAME "] Loading TPM key.");
	charra_r = charra_load_external_public_key(esys_ctx, (TPM2B_PUBLIC*)res.tpm2_public_key, &sig_key_handle);
	if (charra_r == CHARRA_RC_SUCCESS) {
		charra_log_info("[" LOG_NAME "] External public key loaded.");
	} else {
		charra_log_error("[" LOG_NAME "] Loading external public key failed.");
		goto error;
	}

	/* prepare verification */
	charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
	TPM2B_ATTEST attest = {0};
	attest.size = res.attestation_data_len;
	memcpy(attest.attestationData, res.attestation_data, res.attestation_data_len);
	TPMT_SIGNATURE signature;
	memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

	/* --- verify attestation signature --- */
	bool attestation_result_signature = false;
	{
		charra_log_info("[" LOG_NAME "] Verifying TPM Quote signature ...");

		if ((charra_r = charra_verify_tpm2_quote_signature_with_tpm(esys_ctx,
				 sig_key_handle, TPM2_ALG_SHA256, &attest, &signature,
				 &validation)) == CHARRA_RC_SUCCESS) {
			charra_log_info("[" LOG_NAME "]     => TPM Quote signature is valid!");
			attestation_result_signature = true;
		} else {
			charra_log_error("[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
		}
	}

	/* unmarshal attestation data */
	TPMS_ATTEST attest_struct = {0};
	charra_r = charra_unmarshal_tpm2_quote(
		res.attestation_data_len, res.attestation_data, &attest_struct);

	/* --- verify nonce --- */
	bool attestation_result_nonce = false;
	{
		charra_log_info("[" LOG_NAME "] Verifying nonce ...");

		attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
			req.nonce_len, req.nonce, &attest_struct);
		if (attestation_result_nonce == true) {
			charra_log_info("[" LOG_NAME"]     => Nonce in TPM Quote is valid! (matches the one sent)");
		} else {
			charra_log_error("[" LOG_NAME "]     => Nonce in TPM Quote is NOT valid! (does not match the one sent)");
		}
	}

	/* --- verify PCRs --- */
	bool attestation_result_pcrs = false;
	{
		charra_log_info("[" LOG_NAME "] Verifying PCRs ...");

		/* get reference PCRs */
		uint8_t* reference_pcrs[TPM2_MAX_PCRS] = {0};
		if ((charra_r = charra_get_reference_pcrs_sha256(TPM_PCR_SELECTION,
				 TPM_PCR_SELECTION_LEN, reference_pcrs)) != CHARRA_RC_SUCCESS) {
			charra_log_error("[" LOG_NAME "] Error getting reference PCRs.");
			goto error;
		}

		/* compute PCR composite digest from reference PCRs */
		uint8_t pcr_composite_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
		/* TODO use crypto-agile (generic) version
		 * charra_compute_pcr_composite_digest_from_ptr_array(), once
		 * implemented, instead of hash_sha256_array() (then maybe remove
		 * hash_sha256_array() function) */
		charra_r = hash_sha256_array(reference_pcrs, TPM_PCR_SELECTION_LEN, pcr_composite_digest);
		charra_log_info(
			"[" LOG_NAME
			"] Computed PCR composite digest from reference PCRs is:");
		charra_print_hex(sizeof(pcr_composite_digest), pcr_composite_digest,
			"                                   0x", "\n", false);
		charra_log_info(
			"[" LOG_NAME "] Actual PCR composite digest from TPM Quote is:");
		charra_print_hex(attest_struct.attested.quote.pcrDigest.size,
			attest_struct.attested.quote.pcrDigest.buffer,
			"                                   0x", "\n", false);

		/* compare reference PCR composite with actual PCR composite */
		attestation_result_pcrs = charra_verify_tpm2_quote_pcr_composite_digest(
			&attest_struct, pcr_composite_digest, TPM2_SHA256_DIGEST_SIZE);
		if (attestation_result_pcrs == true) {
			charra_log_info(
				"[" LOG_NAME
				"]     => PCR composite digest is valid! (matches the "
				"one from reference PCRs)");
		} else {
			charra_log_error(
				"[" LOG_NAME
				"]     => PCR composite digest is NOT valid! (does "
				"not match the one from reference PCRs)");
		}
	}

	/* --- output result --- */

	bool attestation_result = attestation_result_signature &&
							  attestation_result_nonce &&
							  attestation_result_pcrs;

	/* print attestation result */
	charra_log_info("[" LOG_NAME "] +----------------------------+");
	if (attestation_result) {
		charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
	} else {
		charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
	}
	charra_log_info("[" LOG_NAME "] +----------------------------+");

error:
	/* flush handles */
	if (sig_key_handle != ESYS_TR_NONE) {
		if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
			charra_log_error("[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
		}
	}

	/* free ESAPI objects */
	if (validation != NULL) {
		Esys_Free(validation);
	}

	/* finalize ESAPI */
	if (esys_ctx != NULL) {
		Esys_Finalize(&esys_ctx);
	}

	/* free memory */
	free(rxtx_buf);
}


int main() {
    charra_log_set_level(LOG_LEVEL_CHARRA);
	
	struct sockaddr_in server, client;
    int sock, fd;
    unsigned int len;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        charra_log_error("[" LOG_NAME "] Failed to create server socket.");
        return 1;
    }

	int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
		charra_log_error("[" LOG_NAME "] Setsockopt(SO_REUSEADDR) failed");
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
		charra_log_error("[" LOG_NAME "] Setsockopt(SO_REUSEPORT) failed");
	}
    
    memset( &server, 0, sizeof (server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if (bind(sock,(struct sockaddr*)&server, sizeof(server)) < 0) {
        charra_log_error("[" LOG_NAME "] Failed to bind server socket.");
		return 1;
    }
    if (listen(sock, 5) == -1 ) {
        charra_log_error("[" LOG_NAME "] Failed to listen on server socket.");
		return 1;
    }

    for (;;) {
        charra_log_info("[" LOG_NAME "] Waiting for new connection.");
		len = sizeof(client);
        fd = accept(sock, (struct sockaddr*)&client, &len);
        if (fd < 0) {
            charra_log_error("[" LOG_NAME "] Failed to accept new new client.");
        }
        charra_log_info("[" LOG_NAME "] Handling new connection.");
        handle_connection(fd);
		charra_log_info("[" LOG_NAME "] Closing connection.");
        close(fd);
    }
    return 0;
}

/* --- function definitions ----------------------------------------------- */

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto* attestation_request) {
	CHARRA_RC err = CHARRA_RC_ERROR;

	/* generate nonce */
	uint32_t nonce_len = 20;
	uint8_t nonce[nonce_len];
	if ((err = charra_get_random_bytes_from_tpm(nonce_len, nonce) !=
			   CHARRA_RC_SUCCESS)) {
		charra_log_error("Could not get random bytes for nonce.");
		return err;
	}
	charra_log_info("Generated nonce of length %d:", nonce_len);
	charra_print_hex(
		nonce_len, nonce, "                                   0x", "\n", false);

	/* build attestation request */
	msg_attestation_request_dto req = {.hello = false,
		.sig_key_id_len = TPM_SIG_KEY_ID_LEN,
		.sig_key_id = {0}, // must be memcpy'd, see below
		.nonce_len = nonce_len,
		.nonce = {0}, // must be memcpy'd, see below
		.pcr_selections_len = 1,
		.pcr_selections = {{
			.tcg_hash_alg_id = TPM2_ALG_SHA256,
			.pcrs_len = 9,
			.pcrs = {0} // must be memcpy'd, see below
		}}};
	memcpy(req.sig_key_id, TPM_SIG_KEY_ID, TPM_SIG_KEY_ID_LEN);
	memcpy(req.nonce, nonce, nonce_len);
	memcpy(req.pcr_selections->pcrs, TPM_PCR_SELECTION, TPM_PCR_SELECTION_LEN);

	/* set output param(s) */
	*attestation_request = req;

	/* return result */
	return CHARRA_RC_SUCCESS;
}
