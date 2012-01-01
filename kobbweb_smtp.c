#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define VERIFY_SSL_impl(x, line) if (!(x)) { \
    unsigned long error_code = ERR_get_error(); \
    char error_buf[512]; \
    SSL_load_error_strings(); \
    ERR_error_string_n(error_code, error_buf, sizeof error_buf); \
    error_buf[511] = 0; \
    fprintf(stderr, __FILE__ "(" line "): %s", error_buf); \
    abort(); \
}
#define VERIFY_impl(x, line) if (!(x)) { perror(__FILE__ "(" line "): " #x); abort(); } else (void)0
#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define VERIFY_SSL(x) VERIFY_SSL_impl(x, STRINGIZE(__LINE__))
#define VERIFY(x) VERIFY_impl(x, STRINGIZE(__LINE__)) 
#define UNUSED(x) (void)x

struct kw_text_chunk_t
{
    struct kw_text_chunk_t *next;
    const char *text;
};

enum kw_state_t
{
    STATE_NEW,
    STATE_SSL_START,
    STATE_SSL_ACCEPT,
    STATE_HANDLE_COMMAND,
    STATE_DONE
};

struct kw_connection_t;

typedef int (*kw_transmit_function_t)(struct kw_connection_t *, void *, size_t);

#define CONNECTION_BUFFER_SIZE (16 * 1024 * 1024)

struct kw_connection_t
{
    int fd;
    int valid;
    SSL *ssl;
    enum kw_state_t state;
    kw_transmit_function_t read;
    kw_transmit_function_t write;
    char *buffer;
};

static struct kw_connection_t **kw_connections;
static size_t kw_current_connection;
static size_t kw_num_connections;
static SSL_CTX *kw_ssl_ctx;

static int
kw_socket_open(int port)
{
    int socket_fd;
    struct sockaddr_in addr;
    const int LISTEN_BACKLOG = 50;

    memset(&addr, 0, sizeof addr);
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    VERIFY(socket_fd != -1);

    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_family = AF_INET;

    VERIFY(bind(socket_fd, (struct sockaddr *)&addr, sizeof addr) == 0);
    VERIFY(listen(socket_fd, LISTEN_BACKLOG) == 0);

    return socket_fd;
}

static void
kw_accept_and_add_to_epoll_list(int epoll_fd, int socket_fd)
{
    int new_connection_fd;
    struct epoll_event event;
    struct sockaddr_in connection;
    socklen_t size = sizeof connection;

    new_connection_fd = accept(socket_fd, (struct sockaddr *)&connection, &size);
    VERIFY(new_connection_fd != -1);
    fcntl(new_connection_fd, F_SETFD, O_NONBLOCK);
    event.events = EPOLLIN | EPOLLOUT;
    event.data.fd = new_connection_fd;
    VERIFY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_connection_fd, &event) != -1);
}

static void
kw_remove_from_epoll_list(int epoll_fd, int socket_fd)
{
    VERIFY(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket_fd, NULL) != -1);
}

static int
kw_read(struct kw_connection_t *conn, void *data, size_t size)
{
    UNUSED(conn);
    UNUSED(data);
    UNUSED(size);
    return 0;
}

static int
kw_write(struct kw_connection_t *conn, void *data, size_t size)
{
    UNUSED(conn);
    UNUSED(data);
    UNUSED(size);
    return 0;
}

static int
kw_read_ssl(struct kw_connection_t *conn, void *data, size_t size)
{
    UNUSED(conn);
    UNUSED(data);
    UNUSED(size);
    return 0;
}

static int
kw_write_ssl(struct kw_connection_t *conn, void *data, size_t size)
{
    UNUSED(conn);
    UNUSED(data);
    UNUSED(size);
    return 0;
}

static void
kw_initialize_connection(struct kw_connection_t *conn)
{
    VERIFY(conn->valid == 0);

    conn->fd = -1;
    conn->ssl = NULL;
    conn->state = STATE_NEW;
    conn->read = kw_read;
    conn->write = kw_write;
}

static struct kw_connection_t *
kw_allocate_connection()
{
    size_t allocation_size;
    size_t new_num_elements;
    size_t i;
    struct kw_connection_t *new_connections;
    char *new_blocks;

    if (kw_current_connection != kw_num_connections)
    {
        struct kw_connection_t *conn = kw_connections[kw_current_connection++]; 
        kw_initialize_connection(conn);
        return conn;
    }

#define REALLOCATION_DELTA 16
    new_num_elements = kw_num_connections + REALLOCATION_DELTA;
    allocation_size = sizeof(struct kw_connection_t *) * new_num_elements;
    kw_connections = realloc(kw_connections, allocation_size);

    new_connections = calloc(REALLOCATION_DELTA, sizeof(struct kw_connection_t));
    new_blocks = malloc(REALLOCATION_DELTA * CONNECTION_BUFFER_SIZE);

    for (i = kw_num_connections; i < new_num_elements; ++i)
    {
        kw_connections[i] = new_connections + i;
        kw_connections[i]->buffer = &new_blocks[i * CONNECTION_BUFFER_SIZE];
    }

    kw_num_connections = new_num_elements;
    return kw_allocate_connection();
}

static struct kw_connection_t *
kw_acquire_connection(int fd)
{
    size_t i;
    struct kw_connection_t *conn;

    for (i = 0; i < kw_current_connection; ++i)
    {
        if (kw_connections[i]->fd == fd)
            return kw_connections[i];
    }

    conn = kw_allocate_connection();
    conn->state = STATE_NEW;
    conn->fd = fd;
    conn->valid = 1;

    return conn;
}

static void
kw_start_tls(struct kw_connection_t *conn)
{
    SSL *ssl;
    ssl = SSL_new(kw_ssl_ctx);
    SSL_set_fd(ssl, conn->fd);
    conn->ssl = ssl;
}

static void
kw_accept_tls(struct kw_connection_t *conn)
{
    VERIFY_SSL(SSL_accept(conn->ssl));
    conn->read = kw_read_ssl;
    conn->write = kw_write_ssl;
}

static void
kw_release_connection(struct kw_connection_t *conn, int fd)
{
    size_t i;

    VERIFY(conn->valid);
    VERIFY(conn->fd == fd);

    if (conn->ssl)
        SSL_free(conn->ssl);
    conn->valid = 0;

    for (i = 0; i < kw_current_connection; ++i)
    {
        if (kw_connections[i] == conn)
            break;
    }
    VERIFY(i < kw_current_connection);

    --kw_current_connection;
    kw_connections[i] = kw_connections[kw_current_connection];
    kw_connections[kw_current_connection] = conn;
}

static void
kw_send_greeting(struct kw_connection_t *conn)
{
    static const char greeting[] = "220 mx.kobbwebb.net ESMTP\x0D\x0A";
    static const size_t greeting_length = sizeof greeting;
    write(conn->fd, greeting, greeting_length);
}

static void
kw_handle_command(struct kw_connection_t *conn)
{
    conn->state = STATE_DONE;
}

static int
handle_connection(int fd)
{
    struct kw_connection_t *conn;
    int rv = 0;

    conn = kw_acquire_connection(fd);
    VERIFY(conn->valid);

    switch (conn->state)
    {
        case STATE_NEW:
            kw_send_greeting(conn);
            conn->state = STATE_HANDLE_COMMAND;
            break;
        case STATE_HANDLE_COMMAND:
            kw_handle_command(conn);
            break;
        case STATE_SSL_START:
            kw_start_tls(conn);
            conn->state = STATE_SSL_ACCEPT;
            break;
        case STATE_SSL_ACCEPT:
            kw_accept_tls(conn);
            conn->state = STATE_HANDLE_COMMAND;
            break;
        case STATE_DONE:
            kw_release_connection(conn, fd);
            rv = 1;
            break;
        default: 
            break;
    }

    return rv;
}

static void
kw_initialize_ssl_ctx()
{
    const SSL_METHOD *method;

    method = SSLv23_server_method();
    kw_ssl_ctx = SSL_CTX_new(method);
    VERIFY_SSL(kw_ssl_ctx != NULL);

    VERIFY_SSL(SSL_CTX_use_certificate_file(kw_ssl_ctx, "kobbweb_smtp.crt", SSL_FILETYPE_PEM) == 1);
    /* TODO: Use a keystore instead of the unencrypted key below. */
    VERIFY_SSL(SSL_CTX_use_PrivateKey_file(kw_ssl_ctx, "kobbweb_smtp.key", SSL_FILETYPE_PEM) == 1);
    VERIFY_SSL(SSL_CTX_load_verify_locations(kw_ssl_ctx, NULL, "/usr/lib/ssl/certs"));
    SSL_CTX_set_verify(kw_ssl_ctx, SSL_VERIFY_PEER, NULL);
}

static int
find_fd(int array[], int element, size_t array_size)
{
    size_t i;

    for (i = 0; i < array_size; ++i)
        if (array[i] == element)
            return array[i];

    return -1;
}

int
main(void)
{
    int epoll_fd;
#define MAX_NUM_EVENTS 128
    struct epoll_event event;
    struct epoll_event events[MAX_NUM_EVENTS];
    int sockets[2] = { 25, 587 };
    int socket_fds[2] = { -1, -1 };
    size_t i;

    SSL_library_init();
    kw_initialize_ssl_ctx();
    epoll_fd = epoll_create1(0);
    VERIFY(epoll_fd >= 0);

    for (i = 0; i < sizeof sockets / sizeof sockets[0]; ++i)
    {
        int socket = sockets[i];
        socket_fds[i] = kw_socket_open(socket);

        event.events = EPOLLIN;
        event.data.fd = socket_fds[i];
        VERIFY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fds[i], &event) == 0);
    }

    for (;;)
    {
        int num_ready_fds;
        int i;

        num_ready_fds = epoll_wait(epoll_fd, events, MAX_NUM_EVENTS, -1);
        VERIFY(num_ready_fds != -1);

        for (i = 0; i < num_ready_fds; ++i)
        {
            int current_fd = events[i].data.fd;
            int socket_fd = find_fd(socket_fds, current_fd, sizeof socket_fds / sizeof socket_fds[0]);

            if (socket_fd != -1)
            {
                kw_accept_and_add_to_epoll_list(epoll_fd, socket_fd);
            }
            else if (handle_connection(current_fd))
            {
                kw_remove_from_epoll_list(epoll_fd, current_fd);
                close(current_fd);

                /* TODO: Remove this. Temporarily exiting after each successful connection
                         to ease debuggability so that I don't have to break out of syscalls. */
                return 0;
            }
        }
    }
}
