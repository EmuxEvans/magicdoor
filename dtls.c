
#include "dtls.h"

SSL_CTX *dtls_ctx = NULL;
SSL *dtls_ssl = NULL;
SSL_SESSION *dtls_session = NULL;

int dtls_state;
//struct keepalive_info dtls_times;
unsigned char dtls_session_id[32];
unsigned char dtls_secret[48];

int ssl_init()
{
    SSL_library_init();
    return 0;
}

int start_dtls_handshake(SSL *dtls_ssl, int dtls_fd)
{
    ssl_init();
    STACK_OF(SSL_CIPHER) *ciphers;
    const SSL_METHOD *dtls_method;
    SSL_CIPHER *dtls_cipher;
    //char* cipher_suites = "AES128-SHA:AES256-SHA";
    char* cipher_suites = "AES128-SHA";
    BIO *dtls_bio;
    int errnum;

    if (!dtls_ctx) {
        dtls_method = DTLSv1_client_method();
        dtls_ctx = SSL_CTX_new(dtls_method);
        if (!dtls_ctx) {
	    printf("Initialise DTLSv1 CTX failed\n");
	    return -1;
        }
        SSL_CTX_set_read_ahead(dtls_ctx, 1);
        if (!SSL_CTX_set_cipher_list(dtls_ctx, cipher_suites)) {
	    printf("Set DTLS cipher list failed\n");
	    SSL_CTX_free(dtls_ctx);
	    dtls_ctx = NULL;
	    return -2;
        }
    }

    if (!dtls_session) {
	/* We're going to "resume" a session which never existed. Fake it... */
	dtls_session = SSL_SESSION_new();
	if (!dtls_session) {
	    printf("Initialise DTLSv1 session failed\n");
	    return -3;
	}
	dtls_session->ssl_version = 0x0100; /* DTLS1_BAD_VER */
    }

    /* Do this every time; it may have changed due to a rekey */
    RAND_bytes(dtls_secret, sizeof(dtls_secret));
    dtls_session->master_key_length = sizeof(dtls_secret);
    memcpy(dtls_session->master_key, dtls_secret, sizeof(dtls_secret));

    dtls_session->session_id_length = sizeof(dtls_session_id);
    memcpy(dtls_session->session_id, dtls_session_id, sizeof(dtls_session_id));

    dtls_ssl = SSL_new(dtls_ctx);
    SSL_set_connect_state(dtls_ssl);

    ciphers = SSL_get_ciphers(dtls_ssl);
    if (sk_SSL_CIPHER_num(ciphers) != 1) {
            printf("Not precisely one DTLS cipher\n");
            SSL_CTX_free(dtls_ctx);
            SSL_free(dtls_ssl);
            SSL_SESSION_free(dtls_session);
            dtls_ctx = NULL;
            dtls_session = NULL;
            return -4;
    }
    dtls_cipher = sk_SSL_CIPHER_value(ciphers, 0);

    /* Set the appropriate cipher on our session to be resumed */
    dtls_session->cipher = dtls_cipher;
    dtls_session->cipher_id = dtls_cipher->id;

    /* Add the generated session to the SSL */
    if (!SSL_set_session(dtls_ssl, dtls_session)) {
            printf("SSL_set_session() failed with old protocol version 0x%x\n", 
                   dtls_session->ssl_version);
            return -5;
    }

    dtls_bio = BIO_new_socket(dtls_fd, BIO_NOCLOSE);
    /* Set non-blocking */
    BIO_set_nbio(dtls_bio, 1);
    SSL_set_bio(dtls_ssl, dtls_bio, dtls_bio);

    SSL_set_options(dtls_ssl, SSL_OP_CISCO_ANYCONNECT);

    return 0;
}

int dtls_try_handshake()
{
	int ret = SSL_do_handshake(dtls_ssl);
	if (ret == 1) {
		printf("Established DTLS connection (using OpenSSL). Ciphersuite.\n");
		return 0;
	}

	ret = SSL_get_error(dtls_ssl, ret);
	printf("DTLS handshake failed: %d\n", ret);
	return -1;
}

void dtls_shutdown()
{
    SSL_CTX_free(dtls_ctx);
    SSL_SESSION_free(dtls_session);
}

void dtls_close(int* dtls_fd)
{
    if (dtls_ssl) {
        DTLS_FREE(dtls_ssl);
        close(*dtls_fd);
        dtls_ssl = NULL;
	*dtls_fd = -1;
    }
}

