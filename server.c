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
    struct sockaddr_in dtls_addr;
    socklen_t addrlen;
    SSL *dtls_ssl;
    int dtls_fd = 0;
    int dtls_bind_addrlen = 0;
    int dtls_local_port = 5000;
    int ret = 0;
    int sndbuf = 0;
    unsigned char recv_buffer[1000];
    int max_buffer_lengh = 1000;

    dtls_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dtls_fd < 0) {
        printf("Open UDP socket for DTLS failed\n");
        return -1;
    }

    sndbuf = 1500* 2;
    setsockopt(dtls_fd, SOL_SOCKET, SO_SNDBUF, (void *)&sndbuf, sizeof(sndbuf));
    dtls_bind_addrlen = sizeof(dtls_addr);
    dtls_addr.sin_family = AF_INET;
    dtls_addr.sin_addr.s_addr = INADDR_ANY;
    dtls_addr.sin_port = htons(dtls_local_port);

    if (bind(dtls_fd, (struct sockaddr *)&dtls_addr, dtls_bind_addrlen)) {
        printf("Bind UDP socket for DTLS\n");
        close(dtls_fd);
        return -2;  
    }

    fcntl(dtls_fd, F_SETFL, fcntl(dtls_fd, F_GETFL) | O_NONBLOCK);
    fcntl(dtls_fd, F_SETFD, fcntl(dtls_fd, F_GETFD) | FD_CLOEXEC);

    
    
    while(1) {
        int len = 1500;
        len = DTLS_RECV(dtls_ssl, recv_buffer, max_buffer_lengh);
        if(len < 0) {
            printf("len less than 0\n");
            break;
        } else {
            printf("len is %d\n", len);
        }
    }
    
    /*
    ret = start_dtls_handshake(dtls_ssl, dtls_fd);
    if (ret) {
        close(dtls_fd);
        return ret;
    }*/
    close(dtls_fd);
    return 0;
}