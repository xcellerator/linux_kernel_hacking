#include <stdio.h>
#include <stdlib.h>
#include <utmp.h>

#define UTMP_SIZE 384
#define BUFSIZE (UTMP_SIZE * 32)

int main(void)
{
    int print_info(struct utmp *buf, int entry);
    int get_cmdline(pid_t pid, char *buf);

    FILE *fp;
    struct utmp *buf;

    /*
     * Open /var/run/utmp and check for errors
     */
    fp = fopen("/var/run/utmp", "r");
    if(fp < 0)
        return -1;

    /*
     * Allocate ourselves a buffer to copy the contents of /var/run/utmp into
     */
    buf = malloc(BUFSIZE);
    if(!buf)
        return -1;

    /*
     * Copy the contents of /var/run/utmp into our buffer
     */
    fread((void *)buf, sizeof(struct utmp), BUFSIZE / sizeof(struct utmp), fp);

    /*
     * Loop over each UTMP_SIZE'th chunk of the buffer, calling print_info on each entry
     */
    for ( int entry = 0 ; (entry * sizeof(struct utmp)) < BUFSIZE ; entry++ )
    {
        print_info(buf, entry);
    }
   
    /*
     * Clean up and return
     */
    free(buf);
    fclose(fp);
    return 0;
}

/*
 * print_info() takes a buffer of utmp structures, and an entry offset
 * to which structure we want. It then neatly prints out some of the
 * entries within the struct.
 */
int print_info( struct utmp *buf, int entry )
{
    int get_cmdline(pid_t pid, char *buf);

    /*
     * Jump ahead to the entry we want
     */
    buf += entry;

    /*
     * If ut_type is EMPTY, then the entry tells us nothing, so don't bother
     */
    if(buf->ut_type == EMPTY)
        return 0;

    printf("[Entry %d]\n", entry);
    /*
     * ut_type tells us what kind of record this entry is
     * EMPTY:           contains nothing of interest
     * RUN_LVL:         change in runlevel
     * BOOT_TIME:       stores time the system botted (ut_tv)
     * NEW_TIME:        stores time the sysclock changed (ut_tv)
     * OLD_TIME:        stores time before sysclock changed (ut_tv)
     * INIT_PROCESS:    process information about init (PID 1)
     * LOGIN_PROCESS:   process information about a login session
     * USER_PROCESS:    process information about a "normal" process
     * DEAD_PROCESS:    process was terminated
     */
    printf(" ut_type = ");
    switch(buf->ut_type)
    {
        case EMPTY:
            printf("EMPTY\n");
            break;

        case RUN_LVL:
            printf("RUN_LVL\n");
            break;

        case BOOT_TIME:
            printf("BOOT_TIME\n");
            break;

        case NEW_TIME:
            printf("NEW_TIME\n");
            break;

        case OLD_TIME:
            printf("OLD_TIME\n");
            break;

        case INIT_PROCESS:
            printf("INIT_PROCESS\n");
            break;

        case LOGIN_PROCESS:
            printf("LOGIN_PROCESS\n");
            break;

        case USER_PROCESS:
            printf("USER_PROCESS\n");
            break;

        case DEAD_PROCESS:
            printf("DEAD_PROCESS\n");
            break;
    }

    /*
     * ut_pid is the PID of the process associated with the logon
     * To get the name of the process, we call get_cmdline()
     */
    printf(" ut_pid = %d", buf->ut_pid);
    char *cmdline = malloc(1024);
    if (cmdline != NULL)
    {
        get_cmdline(buf->ut_pid, cmdline);
        printf(" - \"%s\"\n", cmdline);
        free(cmdline);
    }
    else
        printf("\n");

    /*
     * u_line is the name of the TTY under /dev
     */
    printf(" ut_line = %s\n", buf->ut_line);

    /*
     * ut_user is the name of the user associated to the logon
     */
    printf(" ut_user = %s\n", buf->ut_user);

    printf("\n");

    return 0;
}

/*
 * get_cmdline() opens up /proc/<PID>/cmdline and copies the contents into a buffer
 */
int get_cmdline(pid_t pid, char *cmdline)
{
    FILE *fp;
    char filename[255], contents[1024];

    /*
     * Form the correct pathname
     */
    sprintf(filename, "/proc/%d/cmdline", pid);

    fp = fopen(filename, "r");
    if(fp != NULL)
    {
        /*
         * Copy from the file descriptor into contents, and then from contents into
         * cmdline (which is passed as an argument).
         */
        fgets(contents, 1024, fp);
        sprintf(cmdline, "%s", contents);
    }

    return 0;
}
