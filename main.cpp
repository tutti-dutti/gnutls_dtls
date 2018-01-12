#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <thread>

#include "DtlsPskConnection.hpp"

#define SECRET_KEY "ABCDEF1231231231213"

const char* serverip = "::ffff:172.16.99.97";
int port = 123123;

int main(void)
{
    global_gnutls_init();

    DtlsPskConnection dtls;
    dtls.connect( serverip, port, SECRET_KEY);

    while (1){

        uint8_t buff[3] = { 0x99, 0x98, 0x97}; // some dummy data
        dtls.send( buff, 3 );

        //dtls.keep_alive();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    global_gnutls_cleanup();

    return 0;
}

