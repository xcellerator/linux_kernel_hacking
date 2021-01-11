/*
 * See "man utmp"
 */

#define EMPTY           0
#define RUN_LVL         1
#define BOOT_TIME       2
#define NEW_TIME        3
#define OLD_TIME        4
#define INIT_PROCESS    5
#define LOGIN_PROCESS   6
#define USER_PROCESS    7
#define DEAD_PROCESS    8
#define ACCCOUNTING     9

#define UT_LINESIZE     32
#define UT_NAMESIZE     32
#define UT_HOSTSIZE     256

struct exit_status {
    short int e_termination;
    short int e_exit;
};

struct utmp {
    short       ut_type;
    pid_t       ut_pid;
    char        ut_line[UT_LINESIZE];
    char        ut_id[4];
    char        ut_user[UT_NAMESIZE];
    char        ut_host[UT_HOSTSIZE];
    struct      exit_status     ut_exit;

#if defined __WORDSIZE_COMPAT32
    int32_t     ut_session;
    struct {
        int32_t tv_sec;
        int32_t tv_usec;
    } ut_tv;
#else
    long        ut_session;
//    struct      timeval ut_tv;
#endif

    int32_t     ut_addr_v6[4];
    char        __unused[20];
};

