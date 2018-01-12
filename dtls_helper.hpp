#pragma once 

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include <assert.h>
#define CHECK(x) assert((x)>=0)
#define MAX_DTLS_BUF 1024

void udp_close(int sd);
int connect( gnutls_session_t* session, const char* serverip, int port, int* handshake_status );

void global_gnutls_init();
void global_gnutls_cleanup();

void create_dtls_session( 
        gnutls_session_t* session, 
        const char* serverip, 
        int port, 
        const char* secret, 
        gnutls_psk_client_credentials_t *dtls_credential,
        int* handshake_status
        );


void destroy_dtls_session( gnutls_session_t* session, int socket_fd,gnutls_psk_client_credentials_t* dtls_credential );

void send_keep_alive( gnutls_session_t *tls_session);
