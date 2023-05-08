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

#define DATA_FILE_NAME "/var/tmp/aesdsocketdata"

#define BUFFER_SIZE 256
#define PORT "9000"

#define LOG_IDENT "aesdsocket"

int is_canceled = 0;

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

int receive_message_and_append_file(int sockfd)
{
    FILE * data_file = fopen(DATA_FILE_NAME, "ab");
    if(data_file == NULL)
    {
        log_message("Cannot open file: " DATA_FILE_NAME);
        return -1;
    }

    unsigned char buf[BUFFER_SIZE];
    int is_more_data = 1;
    do {
    
        ssize_t len = recv(sockfd, buf, BUFFER_SIZE, 0);
        if(is_canceled)
        {
            break;
        }

        unsigned char * new_line_char = memchr(buf,'\n', len);

        if(new_line_char != NULL)
        {
            is_more_data = 0;
            len = new_line_char - buf + 1;
        }

        int ret = fwrite(buf, len, 1,  data_file);

        if(ret <= 0)
        {
            fclose(data_file);
            log_message("Cannot modify file");
            return -1;
        }

    } while (is_more_data && !is_canceled);

    fclose(data_file);
    return is_canceled;
}

int send_message_from_file(int sockfd)
{
    FILE * data_file = fopen(DATA_FILE_NAME, "rb");
    if(data_file == NULL)
    {
        log_message("Cannot open file: " DATA_FILE_NAME);
        return -1;
    }

    unsigned char buffer[BUFFER_SIZE];

    size_t len_read = 0;
    do {

        len_read = fread(buffer, 1, BUFFER_SIZE, data_file);
        if(len_read == 0 || is_canceled)
        {
            break;
        }

        unsigned char * p_data = buffer;
        size_t len_data = len_read;
        ssize_t len_send = -1;
        do
        {
            len_send = send(sockfd, p_data, len_data, 0);
            if (len_send == -1)
            {
                fclose(data_file);
                log_message("Cannot send data");
                return -1;
            }
        } while (len_send < p_data - buffer);
        

    } while (!feof(data_file) && !is_canceled);

    fclose(data_file);
    return is_canceled;

}

void sigchld_handler(int signal)
{
    is_canceled = 1;
}

int main(int argc, char* argv[] )
{
    const char * arg_string = argv[1];

    if(argc == 2 && strncmp(arg_string, "-d", strlen(arg_string)) == 0)
    {
        log_message("Run as a daemon ...");
        
        pid_t pid = fork();

        if(pid > 0)
        {
            exit(EXIT_SUCCESS);   // main process
        }
        if(pid < 0)
        {
            exit(EXIT_FAILURE);   // fail
        }

        if(setsid() < 0)
        {
            exit(EXIT_FAILURE);
        }

        if(chdir("/"))
        {
            exit(EXIT_FAILURE);
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        if (open("/dev/null",O_RDONLY) == -1) {
            log_message("failed to reopen stdin");
        }
        if (open("/dev/null",O_WRONLY) == -1) {
            log_message("failed to reopen stdout");
        }
        if (open("/dev/null",O_RDWR) == -1) {
            log_message("failed to reopen stderr");
        }

        log_message("Done!");
    }

    struct sigaction sig_action;
    memset(&sig_action, 0, sizeof sig_action);

    sig_action.sa_handler = sigchld_handler;

    if (sigaction(SIGINT, &sig_action, NULL) == -1) {
        log_message("sigaction failed");
        EXIT_FAILURE;
    }
    if (sigaction(SIGTERM, &sig_action, NULL) == -1) {
        log_message("sigaction failed");
        EXIT_FAILURE;
    }

    int sock_fd;

    struct sockaddr_storage their_addr;
    socklen_t sin_size;

    char s[INET6_ADDRSTRLEN];
    int rv;

    struct addrinfo hints;

    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *servinfo = NULL;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        log_message_form("Error in getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for(struct addrinfo * p = servinfo; p != NULL; p = p->ai_next) {
        sock_fd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol);
        if (sock_fd == -1) {
            continue;
        }
        int is_ok = 1;
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &is_ok, sizeof(is_ok)) == -1) {
            break;
        }

        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);
    servinfo = NULL;

    if (sock_fd == -1) {
       log_message("server: failed to bind");
       EXIT_FAILURE;
    }

    if (listen(sock_fd, 5) == -1) {
        close(sock_fd);
        EXIT_FAILURE;
    }

    log_message("server: waiting for connections...");

    while(!is_canceled)
    {
        sin_size = sizeof their_addr;
        int new_fd = accept(sock_fd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);

        log_message_form("Accepted connection from %s\n", s);

        if(receive_message_and_append_file(new_fd) == 0)
        {
            if(send_message_from_file(new_fd))
            {
                close(new_fd);
                break;
            }
        }

        close(new_fd);

    }

    close(sock_fd);

    remove(DATA_FILE_NAME);
    
    return 0;
}
