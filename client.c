#include "dtls.h"

int connect_dtls_socket()
{
    return 0;
}

int dtls_reconnect(int* dtls_fd)
{
    dtls_close(dtls_fd);
    return connect_dtls_socket();
}

int main(int argc, char* argv[])
{
    printf("hello, dtls client\n");
    socklen_t addrlen;
    SSL *dtls_ssl;
    int dtls_fd = 0;
    int dtls_local_port = 5000;
    int ret = 0, sndbuf = 0;

    dtls_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dtls_fd < 0) {
        printf("Open UDP socket for DTLS failed\n");
        return -1;
    }

    sndbuf = 1500* 2;
    setsockopt(dtls_fd, SOL_SOCKET, SO_SNDBUF, (void *)&sndbuf, sizeof(sndbuf));

    struct sockaddr_in addr;
    addrlen = sizeof(struct sockaddr_in);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(dtls_local_port);

    if (connect(dtls_fd, (struct sockaddr *)&addr, addrlen)) {
        printf("UDP (DTLS) connect:\n");
        close(dtls_fd);
        return -3;
    }

    fcntl(dtls_fd, F_SETFL, fcntl(dtls_fd, F_GETFL) | O_NONBLOCK);
    fcntl(dtls_fd, F_SETFD, fcntl(dtls_fd, F_GETFD) | FD_CLOEXEC);

    ret = start_dtls_handshake(dtls_ssl, dtls_fd);
    if (ret) {
        close(dtls_fd);
        return ret;
    }
    return dtls_try_handshake();
}