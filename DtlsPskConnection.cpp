#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <string.h>

#include "DtlsPskConnection.hpp"
#include "dtls_helper.hpp"

DtlsPskConnection::DtlsPskConnection(){
}

DtlsPskConnection::~DtlsPskConnection(){
    cleanup();
}

void DtlsPskConnection::cleanup(){
    destroy_dtls_session( &session, socket_fd, &dtls_credential );
}

bool DtlsPskConnection::ready(){
    return handshake_status == 1;
}

bool DtlsPskConnection::connect( const char* serverip, int port, const char* secret ){

    sprintf(ip, "%s", serverip );
    create_dtls_session( &session, serverip, port, secret, &dtls_credential, &handshake_status );

    std::thread(&DtlsPskConnection::receive_thread, this, &session).detach();

    return true;
}

void DtlsPskConnection::send( const uint8_t* data, uint16_t len ){
    if( !ready() ){ printf("*** [%s] not ready to send \n", ip); }


    int ret = gnutls_record_send(session, data, len );

    if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
        fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
    } else if (ret < 0) {
        fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
        exit(1);
    }
    else{
        printf("*** sent to [%s]: %d bytes\n", ip, ret );
    }
}

void DtlsPskConnection::send( const std::vector<uint8_t>& data ){

    send( data.data(), data.size() );
}


/// TODO: handle error and destroy the connection
void DtlsPskConnection::receive_thread( gnutls_session_t *tls_session){

    char buffer[256];
    int ii;
    while ( 1 ){
        std::this_thread::sleep_for(std::chrono::seconds(1));
        int ret = gnutls_record_recv(*tls_session, buffer, MAX_DTLS_BUF);
        if (ret == 0) {
            printf("- Peer has closed the TLS connection\n");

            return;
        } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
            //fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
        } else if (ret < 0) {
            fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
            return;
        }

        if (ret > 0) {
            printf("- Received from [%s]%d bytes: ", ip, ret);
            for (ii = 0; ii < ret; ii++) {
                printf("0x%X ", buffer[ii] );
                //fputc(buffer[ii], stdout);
            }
            printf("\n" );
        }
    }
}
