#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <thread>

#include "dtls_helper.hpp"
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>


// TODO: error handling
//
#define LOG_LEVEL 9

// GnuTLS will call this function whenever there is a new debugging log message.
void print_logs(int level, const char* msg)
{
    printf("GnuTLS [%d]: %s", level, msg);
}

// GnuTLS will call this function whenever there is a new audit log message.
void print_audit_logs(gnutls_session_t session, const char* message)
{
    printf("GnuTLS Audit: %s", message);
}


static int hex2int(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return c - 'a' + 0xa;
  } else if (c >= 'A' && c <= 'F') {
    return c - 'A' + 0xa;
  } else {
    return -1;
  }
}

static int parse_psk(unsigned char* cfg_psk, const char *psk) {
  int val;
  int psk_len = 0;
  const char *s = psk;
  while (*s && psk_len < 256) {
    val = hex2int(*s++);
    if (val < 0) break;
    cfg_psk[psk_len] = ((val) & 0xf) << 4;
    val = hex2int(*s++);
    if (val < 0) break;
    cfg_psk[psk_len] |= (val & 0xf);

    psk_len++;
  }

  return psk_len;
}

void error_exit(const char *msg) 
{
    printf("ERROR: %s", msg);
    exit(1);
}

void udp_close(int sd)
{
        close(sd);
}

int udp_connect( const char* SERVER, int port)
{
    int err, sd;
    struct sockaddr_in sa;

    sd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, SERVER, &sa.sin_addr);

    int one = 1;
    setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

    int rc = ioctl(sd, FIONBIO, (char *)&one);
    if (rc < 0)
    {
        perror("ioctl() failed");
        close(sd);
        exit(-1);
    }


    err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
    if (err < 0) {
        fprintf(stderr, "Connect error\n");
        return -1;
    }

    return sd;
}

int udp6_connect( const char* SERVER, int port)
{
    int err, sd;
    //struct sockaddr_in sa;
    struct sockaddr_in6 sa;

    //sd = socket(AF_INET, SOCK_DGRAM, 0);
    sd = socket(PF_INET6, SOCK_DGRAM, 0);

    memset(&sa, '\0', sizeof(sa));
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    inet_pton(AF_INET6, SERVER, &sa.sin6_addr);

    int one = 1;
    setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

    int rc = ioctl(sd, FIONBIO, (char *)&one);
    if (rc < 0)
    {
        perror("ioctl() failed");
        close(sd);
        exit(-1);
    }


    err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
    if (err < 0) {
        fprintf(stderr, "Connect error\n");
        return -1;
    }

    return sd;
}


void set_credential( gnutls_session_t* session, gnutls_psk_client_credentials_t * cred, const char* secret )
{
    int res;
    res = gnutls_psk_allocate_client_credentials(cred);
    if (res != 0) {
        error_exit("gnutls_psk_allocate_client_credentials() failed.\n");
    }

    // Construct the pre-shared key in GnuTLS's 'datum' structure, whose
    // definition is as follows:
    //      typedef struct {
    //          unsigned char *data;
    //          unsigned int size;
    //      } gnutls_datum_t;
    gnutls_datum_t key;
    key.size = strlen(secret);
    key.data = (unsigned char*)malloc(key.size);
    key.size = parse_psk( key.data, secret);


    // Put the username and key into the structure we use to tell GnuTLs what
    // the credentials are. The example server doesn't care about usernames, so
    // we use "Alice" here.
    res = gnutls_psk_set_client_credentials(*cred, "test", &key, GNUTLS_PSK_KEY_RAW);
    memset(key.data, 0, key.size);
    free(key.data);
    key.data = NULL;
    key.size = 0;
    // You could instead use a callback to give the credentials to GnuTLS. See
    // gnutls_psk_set_client_credentials_function().
    if (res != 0) {
        error_exit("gnutls_psk_set_client_credentials() failed.\n");
    }
    // Pass our credentials (which contains the username and key) to GnuTLS.
    res = gnutls_credentials_set(*session, GNUTLS_CRD_PSK, *cred);

    if (res != 0) {
        error_exit("gnutls_credentials_set() failed.\n");
    }



    /* Use default priorities */
    //CHECK(gnutls_set_default_priority(session));
    const char *error = NULL;
    res = gnutls_priority_set_direct(
            *session,
            "SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128:+PSK:+DHE-PSK",
            &error
            );
    if (res != GNUTLS_E_SUCCESS) {
        error_exit("gnutls_priority_set_direct() failed.\n");
    }

}


// dont' need lock, only this thread write this status
// I don't want the node to block waiting fo this status, 
// move on if it is not set as done
void hand_shake_on_thread( gnutls_session_t* session, int* handshake_status, const char* serverip ){

    int ret;
    /* Perform the TLS handshake */
    do {
        ret = gnutls_handshake(*session);
    }
    while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
    /* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */

    if (ret < 0) {
        gnutls_perror(ret);
        printf("*** Handshake failed\n");
        *handshake_status = 0;
    } else {

        *handshake_status = 1;
        char *desc;

        desc = gnutls_session_get_desc(*session);
        printf("- Session info: [%s] [%s]\n", serverip, desc);
        gnutls_free(desc);
    }

}



// TODO:
// do handshake on a thread
// add some form of atomic to notif handshake in complete
// add some form of atomic to notif handshake in complete
//
int connect( gnutls_session_t* session, const char* serverip, int port, int* handshake_status ){

    int socket_fd;

    /* connect to the peer */
    socket_fd= udp6_connect(serverip, port );

    gnutls_transport_set_int(*session, socket_fd);

    /* set the connection MTU */
    //gnutls_dtls_set_mtu(*session, 1000);
    gnutls_dtls_set_timeouts(*session, 1000, 60000);

    std::thread( hand_shake_on_thread, session, handshake_status, serverip ).detach();

    return socket_fd;
}

void global_gnutls_init()
{
    if (gnutls_check_version("3.1.4") == NULL) {
        fprintf(stderr, "GnuTLS 3.1.4 or later is required for this example\n");
        exit(1);
    }
    /* for backwards compatibility with gnutls < 3.3.0 */
    CHECK(gnutls_global_init());

    gnutls_global_set_log_level(LOG_LEVEL);
    gnutls_global_set_log_function(print_logs);
    gnutls_global_set_audit_log_function(print_audit_logs);
}

void global_gnutls_cleanup(){
    gnutls_global_deinit();
}

void create_dtls_session( 
        gnutls_session_t* session, 
        const char* serverip, 
        int port, 
        const char* secret, 
        gnutls_psk_client_credentials_t *dtls_credential, 
        int* handshake_status){

    /* Initialize TLS session */
    CHECK(gnutls_init(session, GNUTLS_CLIENT | GNUTLS_DATAGRAM));

    set_credential( session, dtls_credential, secret );

    connect( session, serverip, port, handshake_status);

}


void destroy_dtls_session( gnutls_session_t* session, int socket_fd,gnutls_psk_client_credentials_t* dtls_credential ){

    CHECK(gnutls_bye(*session, GNUTLS_SHUT_WR));

    udp_close(socket_fd);

    gnutls_deinit(*session);

    gnutls_psk_free_client_credentials(*dtls_credential);

}

