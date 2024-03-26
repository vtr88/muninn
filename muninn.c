#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 13337

typedef struct {
    SSL *ssl;
    int clientfd;
} ssl_connection;

void *handle_connection(void *arg) {
    ssl_connection *conn = (ssl_connection *)arg;

    const int buffer_size = 2048;
    char buffer[buffer_size];
    int bytes_read;

    while ((bytes_read = SSL_read(conn->ssl, buffer, buffer_size - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);

        if (strstr(buffer, "\r\n\r\n") != NULL || strstr(buffer, "\n\n") != NULL) {
            break;
        }
    }

    printf("\nClient disconnected.\n");
    SSL_shutdown(conn->ssl);
    SSL_free(conn->ssl);
    close(conn->clientfd);
    free(conn);
    return NULL;
}

int main() {
    int sockfd, clientfd; 
    struct sockaddr_in servidoraddr, clienteaddr; 
    socklen_t client_addr_len = sizeof(clienteaddr);
    pthread_t thread_id;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    servidoraddr.sin_family = AF_INET;
    servidoraddr.sin_port = htons(PORT);
    servidoraddr.sin_addr.s_addr = INADDR_ANY; 

    int binder = bind(sockfd, (struct sockaddr*)&servidoraddr, sizeof(servidoraddr));
    if(binder == -1) {
        perror("error binding");
        exit(EXIT_FAILURE);
    } 

    if (listen(sockfd, 10) == -1) {
        perror("Error listening");
        exit(EXIT_FAILURE);
    }

    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "yourpasswordhere");
    SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

    X509 *ca_cert = NULL;
    FILE *ca_file = fopen("ca.pem", "r");
    if (!ca_file) {
        perror("Error opening CA certificate file");
        exit(EXIT_FAILURE);
    }
    
    ca_cert = PEM_read_X509(ca_file, NULL, NULL, NULL);
    fclose(ca_file);

    if (!SSL_CTX_add_extra_chain_cert(ctx, ca_cert)) {
        perror("Error adding CA certificate");
        exit(EXIT_FAILURE);
    }

    printf("munnin listening on port %d...\n\n", PORT);

    while(1) {
        SSL *ssl;
        ssl = SSL_new(ctx);
        clientfd = accept(sockfd, (struct sockaddr*)&clienteaddr, &client_addr_len);

        if (clientfd == -1) {
            perror("Error accepting connection");
            continue;
        }

        SSL_set_fd(ssl, clientfd);

        int accepted = SSL_accept(ssl);
        SSL_get_error(ssl, accepted);

        if (accepted <= 0) {
            int ssl_error = SSL_get_error(ssl, accepted);
            switch (ssl_error) {
                case SSL_ERROR_NONE:
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    fprintf(stderr, "SSL connection closed by peer\n");
                    break;
                case SSL_ERROR_SYSCALL:
                    perror("SSL_accept");
                    break;
                case SSL_ERROR_SSL:
                    fprintf(stderr, "SSL handshake error: %s\n", ERR_error_string(ERR_get_error(), NULL));
                    break;
                default:
                    fprintf(stderr, "SSL_accept error: %d\n", ssl_error);
                    break;
            }
            close(clientfd);
            SSL_free(ssl);
            break;
        }

        ssl_connection *conn = malloc(sizeof(ssl_connection));
        conn->ssl = ssl;
        conn->clientfd = clientfd;

        if (pthread_create(&thread_id, NULL, handle_connection, (void *)conn) != 0) {
            perror("Failed to create thread");
            continue;
        }

        pthread_detach(thread_id);
    }
    close(sockfd);
    return 0;
}
