#pragma once
#include <stdint.h>
#include <gnutls/gnutls.h>
#include <vector>

#include "dtls_helper.hpp"
class DtlsPskConnection
{
    public:
        DtlsPskConnection();
        ~DtlsPskConnection();
        void cleanup();


        bool connect( const char* serverip, int port, const char* secret ); 

        void keep_alive();

        void send( const uint8_t* data, uint16_t len );
        void send( const std::vector<uint8_t>& data );


        bool ready();
    private:

        void receive_thread( gnutls_session_t *tls_session);

        gnutls_session_t session;
        gnutls_psk_client_credentials_t dtls_credential;
        int socket_fd;
        int handshake_status;

        char ip[64];
};
