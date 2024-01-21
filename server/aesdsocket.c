#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef USE_AESD_CHAR_DEVICE
#include <sys/ioctl.h>
#include "../aesd-char-driver/aesd_ioctl.h"
#define DATA_FILE_NAME "/dev/aesdchar"
#define AESDCHAR_IOCSEEKTO_CMD "AESDCHAR_IOCSEEKTO:"
#else
#define DATA_FILE_NAME "/var/tmp/aesdsocketdata"
#endif

#define BUFFER_SIZE 256
#define PORT "9000"

#define LOG_IDENT "aesdsocket"

#define TIMER_INTERVAL_SEC 10

atomic_int is_canceled = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _thread_args
{
    pthread_mutex_t * mutex;
    atomic_int * canceled;
    atomic_int finished;
    int sock_fd;
} thread_args;
typedef struct node
{   
    TAILQ_ENTRY(node) nodes;
    pthread_t thread;

    thread_args args;
} list_node;

void log_message_form(const char* formString, const char* msgString)
{
    printf(formString, msgString);

    openlog(LOG_IDENT, LOG_PID, LOG_USER);
    syslog(LOG_INFO, formString, msgString);
    closelog();
}

void log_message(const char* msgString)
{
    log_message_form("%s\n", msgString);
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int receive_message_and_append_file(int sockfd, FILE *data_file)
{
    char buf[BUFFER_SIZE];
    int is_more_data = 1;
    do {
    
        ssize_t len = recv(sockfd, buf, BUFFER_SIZE, 0);
        if (len <= 0 || is_canceled)
        {
            break;
        }

        char *new_line_char = memchr(buf, '\n', len);

        if(new_line_char != NULL)
        {
            is_more_data = 0;
            len = new_line_char - buf + 1;
        }

        const size_t cmd_len = sizeof(AESDCHAR_IOCSEEKTO_CMD) - 1;

        if (len > cmd_len && strncmp(buf, AESDCHAR_IOCSEEKTO_CMD, cmd_len) == 0)
        {
            struct aesd_seekto seekto;
            const char *write_cmd_str = buf + cmd_len;
            char *write_cmd_separator = memchr(write_cmd_str, ',', len - cmd_len);
            seekto.write_cmd = strtoul(write_cmd_str, &write_cmd_separator, 10);

            seekto.write_cmd_offset = strtoul(write_cmd_separator + 1, NULL, 10);

            ioctl(fileno(data_file), AESDCHAR_IOCSEEKTO, &seekto);
        }
        else
        {
            int ret = fwrite(buf, len, 1, data_file);

            if (ret <= 0)
            {
                log_message("Cannot modify file");
                return -1;
            }
        }

    } while (is_more_data && !is_canceled);

    return is_canceled;
}

int send_message_from_file(int sockfd, FILE *data_file)
{
    unsigned char buffer[BUFFER_SIZE];

    size_t len_read = 0;
    do
    {

        len_read = fread(buffer, 1, BUFFER_SIZE, data_file);
        if (len_read == 0 || is_canceled)
        {
            break;
        }

        unsigned char *p_data = buffer;
        size_t len_data = len_read;
        ssize_t len_send = -1;
        do
        {
            len_send = send(sockfd, p_data, len_data, 0);
            if (len_send == -1)
            {
                log_message("Cannot send data");
                return -1;
            }
        } while (len_send < p_data - buffer);

    } while (!feof(data_file) && !is_canceled);

    return is_canceled;
}

void sigchld_handler(int signal)
{
    switch (signal)
    {
    case SIGINT:
    case SIGTERM:
    case SIGKILL:
    {
        is_canceled = 1;
    }

    default:
    {
        // Don't react
    }
    }
}

void *worker(void *arg)
{
    thread_args *e = (thread_args *)arg;

    FILE *data_file = fopen(DATA_FILE_NAME, "w+");
    if (data_file == NULL)
    {
        log_message("Cannot open file: " DATA_FILE_NAME);
        close(e->sock_fd);
        return NULL;
    }

    if (receive_message_and_append_file(e->sock_fd, data_file) == 0)
    {
        pthread_mutex_lock(e->mutex);
        send_message_from_file(e->sock_fd, data_file);
        pthread_mutex_unlock(e->mutex);
    }
    close(e->sock_fd);
    e->sock_fd = -1;

    return NULL;
}

#ifndef USE_AESD_CHAR_DEVICE
void *timer(void *arg)
{
    thread_args *e = (thread_args *)arg;

    time_t start_time = time(NULL);

    while (!(*e->canceled))
    {
        usleep(100);
        time_t current_time = time(NULL);
        if (difftime(current_time, start_time) < TIMER_INTERVAL_SEC)
        {
            continue;
        }

        start_time = current_time;

        pthread_mutex_lock(e->mutex);

        FILE *data_file = fopen(DATA_FILE_NAME, "w+");
        if (data_file == NULL)
        {
            log_message("Cannot open file: " DATA_FILE_NAME);
            break;
        }

        struct tm *tmp = localtime(&current_time);

        if (tmp == NULL)
        {
            log_message("error: localtime");
            break;
        }

        char buff[BUFFER_SIZE];
        strftime(buff, BUFFER_SIZE, "timestamp: %Y, %m, %d, %H, %M, %S\n", tmp);
        int ret = fputs(buff, data_file);

        if (ret <= 0)
        {
            fclose(data_file);
            log_message("Cannot modify file");
            break;
        }

        fclose(data_file);

        pthread_mutex_unlock(e->mutex);
    }
    return NULL;
}
#endif

int main(int argc, char *argv[])
{
    const char *arg_string = argv[1];

    if (argc == 2 && strncmp(arg_string, "-d", strlen(arg_string)) == 0)
    {
        log_message("Run as a daemon ...");

        pid_t pid = fork();

        if (pid > 0)
        {
            exit(EXIT_SUCCESS); // main process
        }
        if (pid < 0)
        {
            exit(EXIT_FAILURE); // fail
        }

        if (setsid() < 0)
        {
            exit(EXIT_FAILURE);
        }

        if (chdir("/"))
        {
            exit(EXIT_FAILURE);
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        if (open("/dev/null", O_RDONLY) == -1)
        {
            log_message("failed to reopen stdin");
        }
        if (open("/dev/null", O_WRONLY) == -1)
        {
            log_message("failed to reopen stdout");
        }
        if (open("/dev/null", O_RDWR) == -1)
        {
            log_message("failed to reopen stderr");
        }

        log_message("Done!");
    }

    struct sigaction sig_action;
    memset(&sig_action, 0, sizeof sig_action);

    sig_action.sa_handler = sigchld_handler;

    if (sigaction(SIGINT, &sig_action, NULL) == -1)
    {
        log_message("sigaction failed");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sig_action, NULL) == -1)
    {
        log_message("sigaction failed");
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints;

    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *servinfo = NULL;
    int rv;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        log_message_form("Error in getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    int sock_fd = -1;

    for (struct addrinfo *p = servinfo; p != NULL; p = p->ai_next)
    {
        sock_fd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol);
        if (sock_fd == -1)
        {
            continue;
        }
        int is_ok = 1;
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &is_ok, sizeof(is_ok)) == -1)
        {
            break;
        }

        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sock_fd);
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);
    servinfo = NULL;

    if (sock_fd == -1)
    {
        log_message("server: failed to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock_fd, 5) == -1)
    {
        exit(EXIT_FAILURE);
    }

#ifndef USE_AESD_CHAR_DEVICE
    thread_args args = {};
    args.sock_fd = -1;
    args.mutex = &mutex;
    args.canceled = &is_canceled;
    pthread_t timer_thread;
    pthread_create(&timer_thread, NULL, timer, &args);
#endif

    log_message("server: waiting for connections...");

    TAILQ_HEAD(list_node, node) head;
    TAILQ_INIT(&head);

    while(!is_canceled)
    {
        struct sockaddr_storage their_addr;
        socklen_t sin_size = sizeof their_addr;
        int accepted_sock_fd = accept(sock_fd, (struct sockaddr *)&their_addr, &sin_size);
        if (accepted_sock_fd == -1) {
            continue;
        }

        char s[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr),
                  s, sizeof s);

        log_message_form("Accepted connection from %s\n", s);

        list_node * e = malloc(sizeof(list_node));
        if (e == NULL)
        {
            log_message("malloc failed");

            close(accepted_sock_fd);
            break;
        }

        e->args.sock_fd = accepted_sock_fd;
        e->args.mutex = &mutex;
        e->args.canceled = &is_canceled;
        e->args.finished = 0;

        TAILQ_INSERT_TAIL(&head, e, nodes);

        pthread_create(&e->thread, NULL, worker, &e->args);

        list_node *np = NULL;

        TAILQ_FOREACH(np, &head, nodes)
        {
            if(np->args.finished)
            {
                pthread_join(np->thread, NULL);

                TAILQ_REMOVE(&head, np, nodes);
                free(np);
            }
        }
    }
    {
        list_node * np = TAILQ_FIRST(&head);
        while (np != NULL)
        {
            pthread_join(np->thread, NULL);

            list_node * n_next = TAILQ_NEXT(np, nodes);
            free(np);
            np = n_next;
        }
    }

    close(sock_fd);
    shutdown(sock_fd, SHUT_RDWR);

#ifndef USE_AESD_CHAR_DEVICE
    pthread_join(timer_thread, NULL);

    remove(DATA_FILE_NAME);
#endif

    return 0;
}
