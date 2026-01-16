#if !defined(__MBEDTLS_SOCKET_TEMPLATE_H__)
#define __MBEDTLS_SOCKET_TEMPLATE_H__

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#if !defined(MBEDTLS_NET_POLL_READ)
/* compat for older mbedtls */
#define	MBEDTLS_NET_POLL_READ	1
#define	MBEDTLS_NET_POLL_WRITE	1

int
mbedtls_net_poll(mbedtls_net_context * ctx, uint32_t rw, uint32_t timeout)
{
	/* XXX this is not ideal but good enough for an example */
	usleep(300);
	return 1;
}
#endif

struct mbedtls_context {
    mbedtls_net_context net_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_crt;
    mbedtls_x509_crt client_crt;    /* 客户端证书 */
    mbedtls_pk_context client_key;   /* 客户端私钥 */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

void failed(const char *fn, int rv);
void cert_verify_failed(uint32_t rv);
void mbedtls_context_init(struct mbedtls_context *ctx);
void mbedtls_context_free(struct mbedtls_context *ctx);
void open_nb_socket(struct mbedtls_context *ctx,
                    const char *hostname,
                    const char *port,
                    const char *ca_file);
void open_nb_socket_2wayauth(struct mbedtls_context *ctx,
                            const char *hostname,
                            const char *port,
                            const char *ca_file,
                            const char *client_cert_file,
                            const char *client_key_file,
                            const char *client_key_password);


void failed(const char *fn, int rv) {
    char buf[100];
    mbedtls_strerror(rv, buf, sizeof(buf));
    printf("%s failed with %x (%s)\n", fn, -rv, buf);
    exit(1);
}

void cert_verify_failed(uint32_t rv) {
    char buf[512];
    mbedtls_x509_crt_verify_info(buf, sizeof(buf), "\t", rv);
    printf("Certificate verification failed (%0" PRIx32 ")\n%s\n", rv, buf);
    exit(1);
}

/*
    Initialize mbedtls_context structure. 
    Call this function before using the context.
*/
void mbedtls_context_init(struct mbedtls_context *ctx) {
    /* Initialize all components to zero state */
    mbedtls_net_init(&ctx->net_ctx);
    mbedtls_ssl_init(&ctx->ssl_ctx);
    mbedtls_ssl_config_init(&ctx->ssl_conf);
    mbedtls_x509_crt_init(&ctx->ca_crt);
    mbedtls_x509_crt_init(&ctx->client_crt);
    mbedtls_pk_init(&ctx->client_key);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
}

/*
    Free mbedtls_context structure.
    Call this function when done using the context.
*/
void mbedtls_context_free(struct mbedtls_context *ctx) {
    if (ctx == NULL) return;
    
    /* Free all allocated resources */
    mbedtls_net_free(&ctx->net_ctx);
    mbedtls_ssl_free(&ctx->ssl_ctx);
    mbedtls_ssl_config_free(&ctx->ssl_conf);
    mbedtls_x509_crt_free(&ctx->ca_crt);
    mbedtls_x509_crt_free(&ctx->client_crt);
    mbedtls_pk_free(&ctx->client_key);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
}

/*
    A template for opening a non-blocking mbed TLS connection.
*/
void open_nb_socket(struct mbedtls_context *ctx,
                    const char *hostname,
                    const char *port,
                    const char *ca_file) {
    const unsigned char *additional = (const unsigned char *)"MQTT-C";
    size_t additional_len = 6;
    int rv;

    mbedtls_net_context *net_ctx = &ctx->net_ctx;
    mbedtls_ssl_context *ssl_ctx = &ctx->ssl_ctx;
    mbedtls_ssl_config *ssl_conf = &ctx->ssl_conf;
    mbedtls_x509_crt *ca_crt = &ctx->ca_crt;
    mbedtls_entropy_context *entropy = &ctx->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg = &ctx->ctr_drbg;

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    rv = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                               additional, additional_len);
    if (rv != 0) {
        failed("mbedtls_ctr_drbg_seed", rv);
    }

    mbedtls_x509_crt_init(ca_crt);
    rv = mbedtls_x509_crt_parse_file(ca_crt, ca_file);
    if (rv != 0) {
        failed("mbedtls_x509_crt_parse_file", rv);
    }

    mbedtls_ssl_config_init(ssl_conf);
    rv = mbedtls_ssl_config_defaults(ssl_conf,  MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rv != 0) {
        failed("mbedtls_ssl_config_defaults", rv);
    }
    mbedtls_ssl_conf_ca_chain(ssl_conf, ca_crt, NULL);
    mbedtls_ssl_conf_authmode(ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(ssl_conf, mbedtls_ctr_drbg_random, ctr_drbg);

    mbedtls_net_init(net_ctx);
    rv = mbedtls_net_connect(net_ctx, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (rv != 0) {
        failed("mbedtls_net_connect", rv);
    }
    rv = mbedtls_net_set_nonblock(net_ctx);
    if (rv != 0) {
        failed("mbedtls_net_set_nonblock", rv);
    }

    mbedtls_ssl_init(ssl_ctx);
    rv = mbedtls_ssl_setup(ssl_ctx, ssl_conf);
    if (rv != 0) {
        failed("mbedtls_ssl_setup", rv);
    }
    rv = mbedtls_ssl_set_hostname(ssl_ctx, hostname);
    if (rv != 0) {
        failed("mbedtls_ssl_set_hostname", rv);
    }
    mbedtls_ssl_set_bio(ssl_ctx, net_ctx,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    for (;;) {
        rv = mbedtls_ssl_handshake(ssl_ctx);
        uint32_t want = 0;
        if (rv == MBEDTLS_ERR_SSL_WANT_READ) {
            want |= MBEDTLS_NET_POLL_READ;
        } else if (rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
            want |= MBEDTLS_NET_POLL_WRITE;
        } else {
            break;
        }
        rv = mbedtls_net_poll(net_ctx, want, (uint32_t)-1);
        if (rv < 0) {
            failed("mbedtls_net_poll", rv);
        }
    }
    if (rv != 0) {
        failed("mbedtls_ssl_handshake", rv);
    }
    uint32_t result = mbedtls_ssl_get_verify_result(ssl_ctx);
    if (result != 0) {
        if (result == (uint32_t)-1) {
            failed("mbedtls_ssl_get_verify_result", (int)result);
        } else {
            cert_verify_failed(result);
        }
    }
}

/*
    A template for opening a non-blocking mbed TLS connection with 2-way authentication.
    Based on altcp_tls_mbedtls.c implementation from lwip.
*/
void open_nb_socket_2wayauth(struct mbedtls_context *ctx,
                            const char *hostname,
                            const char *port,
                            const char *ca_file,
                            const char *client_cert_file,
                            const char *client_key_file,
                            const char *client_key_password) {
    const unsigned char *additional = (const unsigned char *)"MQTT-C";
    size_t additional_len = 6;
    int rv;

    mbedtls_net_context *net_ctx = &ctx->net_ctx;
    mbedtls_ssl_context *ssl_ctx = &ctx->ssl_ctx;
    mbedtls_ssl_config *ssl_conf = &ctx->ssl_conf;
    mbedtls_x509_crt *ca_crt = &ctx->ca_crt;
    mbedtls_x509_crt *client_crt = &ctx->client_crt;
    mbedtls_pk_context *client_key = &ctx->client_key;
    mbedtls_entropy_context *entropy = &ctx->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg = &ctx->ctr_drbg;

    /* Initialize entropy and random number generator */
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    rv = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                               additional, additional_len);
    if (rv != 0) {
        failed("mbedtls_ctr_drbg_seed", rv);
    }

    /* Load CA certificate for server verification */
    mbedtls_x509_crt_init(ca_crt);
    if (ca_file != NULL) {
        rv = mbedtls_x509_crt_parse_file(ca_crt, ca_file);
        if (rv != 0) {
            failed("mbedtls_x509_crt_parse_file (CA)", rv);
        }
    }

    /* Load client certificate for client authentication */
    mbedtls_x509_crt_init(client_crt);
    rv = mbedtls_x509_crt_parse_file(client_crt, client_cert_file);
    if (rv != 0) {
        failed("mbedtls_x509_crt_parse_file (client cert)", rv);
    }

    /* Load client private key */
    mbedtls_pk_init(client_key);
    rv = mbedtls_pk_parse_keyfile(client_key, client_key_file, 
                                  client_key_password ? client_key_password : "");
    if (rv != 0) {
        failed("mbedtls_pk_parse_keyfile", rv);
    }

    /* Configure SSL */
    mbedtls_ssl_config_init(ssl_conf);
    rv = mbedtls_ssl_config_defaults(ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rv != 0) {
        failed("mbedtls_ssl_config_defaults", rv);
    }

    /* Set CA chain for server certificate verification */
    if (ca_file != NULL) {
        mbedtls_ssl_conf_ca_chain(ssl_conf, ca_crt, NULL);
        mbedtls_ssl_conf_authmode(ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        mbedtls_ssl_conf_authmode(ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    /* Configure client certificate and key for 2-way authentication */
    rv = mbedtls_ssl_conf_own_cert(ssl_conf, client_crt, client_key);
    if (rv != 0) {
        failed("mbedtls_ssl_conf_own_cert", rv);
    }

    mbedtls_ssl_conf_rng(ssl_conf, mbedtls_ctr_drbg_random, ctr_drbg);

    /* Establish network connection */
    mbedtls_net_init(net_ctx);
    rv = mbedtls_net_connect(net_ctx, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (rv != 0) {
        failed("mbedtls_net_connect", rv);
    }
    rv = mbedtls_net_set_nonblock(net_ctx);
    if (rv != 0) {
        failed("mbedtls_net_set_nonblock", rv);
    }

    /* Setup SSL context */
    mbedtls_ssl_init(ssl_ctx);
    rv = mbedtls_ssl_setup(ssl_ctx, ssl_conf);
    if (rv != 0) {
        failed("mbedtls_ssl_setup", rv);
    }
    rv = mbedtls_ssl_set_hostname(ssl_ctx, hostname);
    if (rv != 0) {
        failed("mbedtls_ssl_set_hostname", rv);
    }
    mbedtls_ssl_set_bio(ssl_ctx, net_ctx,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Perform SSL handshake with 2-way authentication */
    for (;;) {
        rv = mbedtls_ssl_handshake(ssl_ctx);
        uint32_t want = 0;
        if (rv == MBEDTLS_ERR_SSL_WANT_READ) {
            want |= MBEDTLS_NET_POLL_READ;
        } else if (rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
            want |= MBEDTLS_NET_POLL_WRITE;
        } else {
            break;
        }
        rv = mbedtls_net_poll(net_ctx, want, (uint32_t)-1);
        if (rv < 0) {
            failed("mbedtls_net_poll", rv);
        }
    }
    if (rv != 0) {
        failed("mbedtls_ssl_handshake", rv);
    }

    /* Verify server certificate */
    uint32_t result = mbedtls_ssl_get_verify_result(ssl_ctx);
    if (result != 0) {
        if (result == (uint32_t)-1) {
            failed("mbedtls_ssl_get_verify_result", (int)result);
        } else {
            cert_verify_failed(result);
        }
    }

    printf("2-way TLS authentication successful!\n");
}

#endif
