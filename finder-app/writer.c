#include <stdio.h>
#include <string.h>
#include <syslog.h>

void log_error(const char *ident, const char* msgString)
{
    openlog(ident, LOG_PID, LOG_USER);
    syslog(LOG_ERR, "%s", msgString);
    closelog();
}

int main(int argc, char* argv[] )
{

    const char * programName = argv[0];
    const char * fileName = argv[1];
    const char * string = argv[2];

    if(argc != 3)
    {
        log_error(programName, "Required two parameters");
        return 1;
    }


    if(strlen(fileName) == 0)
    {
        log_error(programName, "File name is empty");
        return 1;
    }

    if(strlen(string) == 0)
    {
        log_error(programName, "String is empty");
        return 1;
    }

    FILE * file = fopen(fileName, "a");
    if(file == NULL)
    {
        log_error(programName, "Cannot open file");
        return 1;
    }
    
    int ret = fputs(string, file);
    fclose(file);

    if(ret <= 0)
    {
        log_error(programName, "Cannot modify file");
        return 1;
    }

    openlog(programName, LOG_PID, LOG_USER);
    syslog(LOG_DEBUG, "Writing %s to %s", string, fileName);
    closelog();

    return 0;
}
