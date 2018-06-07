/* pcsk.c - run a program as a daemon (that cannot daemonise itself) */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/resource.h>

#define TRUE		1
#define FALSE		0
#define UNDEF		INT_MAX
#define DUMMY_STRING	"dummy string"

#define PCSK_VERSION	"0.0.6"
#define PCSK_REVISION	"0"

/* a log line can be this long - will be wrapped if longer */
#define LOGLINE_MAX	256

/* allocate memory initially for this many groups before calling getgrouplist */
#define GETGROUPLIST_INIT_NGROUPS	15

/* typedefs */

/* process roles */
typedef enum { proc_main, proc_spawner } procrole_t;

/* operating styles */
typedef enum { once, inetd, anticron } opstyle_t;

/* persona data */
typedef struct persona_t {
	uid_t uid;
	gid_t gid;
	int ngroups;
	gid_t *groups;
	int empty;
} persona_t;

/* ########################################################*/
/* constant globals */

/* default pidfile name prefix */
#define default_pidfilename_prefix	"/var/run/"

/* default pidfile name suffix */
#define default_pidfilename_suffix	"-pcsk.pid"

/* default logfile (where own log goes) */
#define default_logfilename_prefix	"/var/run/"

/* default logfile name suffix */
#define default_logfilename_suffix	"-pcsk.log"

/* default max count of failed attempts in one run */
#define default_maxattempts		5

/* default time to wait between attempts to start */
#define default_delay			0

/* minimal runtime to regard an attempt successful (seconds) */
#define default_minruntime		60

/* default secs to add to delay */
#define default_increment		5

/* default operating style */
#define default_opstyle			once

/* default to logstderr */
#define default_logstderr		FALSE

/* default to logstdout */
#define default_logstdout		FALSE

/* default to quiet logging */
#define default_quiet			FALSE

/* default time to wait before sending SIGKILL after sending SIGTERM */
#define default_kill_grace		120

/* default time to wait in certain error conditions (sec) */
#define error_delay			10

/* default to finish_on_exit0 */
#define default_finish_on_exit0		FALSE

/* ########################################################*/


/* prototypes */
int main(int argc, char *argv[], char *env[]);
void pcsk(void);
void pcsk_daemon(void);
void setup_sigactions(void);
void reset_sigactions(void);
int manage_delay(int *delay_now, int *counter, int last, int runtime);
void spawn_child(void);
void parse_exitcode(int status, int runtime);
void wait_and_process_io(int *status);
pid_t wait_child(int *status);
void collect_output(int file, char *buf, size_t buflen, char **ptr);
void check_for_termination(void);
int already_running(void);
void logit(const char *first, ...);
void writelog(const char *string);
void cleanup(void);
void sigalrm_handler(int signum);
void sigterm_handler(int signum);
void sigio_handler(int signum);
void sigchld_handler(int signum);
void set_async_io(int fd);
void set_sa_restart(int signum, int state);
void my_sleep(unsigned int secs);
void change_persona_into(persona_t persona);
void change_persona_back(persona_t persona);
const char *pcsk_version(void);
void usage(void);
void print_version(void);

/* globals */
char *pidfilename;
char *logfilename;
char *dir;
int maxattempts;
int delay;
int minruntime;
int increment;
char *giveupcmdline;
int logstdout;
int logstderr;
int quiet;
int ch_root;
int kill_grace;
int finish_on_exit0;
char *finish_if_this_file_exists;
opstyle_t opstyle;
persona_t oldpersona, usepersona, progpersona;
char *progusername, *progshell, *proghome;
char *program;
char **prog_and_args;
FILE *pidfile;
FILE *logfile;
char *cmdline;
pid_t pid;
int daemonised;
procrole_t proc_role = proc_main;
int devnull;
int logsock_stderr[2], logsock_stdout[2], sock_sync[2];
int child_stderr, child_stdout;
int volatile haschild = FALSE;
int volatile got_sigalrm = FALSE;
int volatile got_sigterm = FALSE;
int volatile got_sigio = FALSE;
int volatile got_sigchld = FALSE;
int volatile terminating = FALSE;
int volatile term_signum = 0;


/* ------------------------------------------------------------------- */

/* option parsing, etc. */
int main(int argc, char *argv[], char *env[])
{
	int opt_0 = UNDEF;
	int opt_a = UNDEF;
	int opt_c = UNDEF;
	char *opt_d = NULL;
	int opt_e = UNDEF;
	char *opt_F = NULL;
	char *opt_g = NULL;
	int opt_i = UNDEF;
	int opt_k = UNDEF;
	char *opt_l = NULL;
	int opt_m = UNDEF;
	int opt_o = UNDEF;
	char *opt_p = NULL;
	int opt_q = UNDEF;
	int opt_R = UNDEF;
	int opt_r = UNDEF;
	char *opt_U = NULL;
	char *opt_u = NULL;
	int opt_w = UNDEF;
	int c;
	int i;
	struct rlimit rl;

	getrlimit(RLIMIT_NOFILE, &rl);
	if (rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;
	for (i = STDERR_FILENO + 1; i < rl.rlim_max; i++)
		(void) close(i);

	/* copy default values */
	logstderr = default_logstderr;
	logstdout = default_logstdout;
	quiet = default_quiet;
	maxattempts = default_maxattempts;
	delay = default_delay;
	minruntime = default_minruntime;
	increment = default_increment;
	opstyle = default_opstyle;
	kill_grace = default_kill_grace;
	oldpersona.empty = TRUE;
	usepersona.empty = TRUE;
	progpersona.empty = TRUE;
	finish_on_exit0 = default_finish_on_exit0;

	/* parsing options */
	while ((c = getopt(argc, argv, "0ad:c:eF:g:i:k:l:m:op:qRrsU:u:w:vhH?")) != -1) {
		switch (c) {
			case '0':
				opt_0 = TRUE;
				break;
			case 'a':
				opt_a = TRUE;
				break;
			case 'c':
				opt_c = atoi(optarg);	/* FIXME */
				break;
			case 'd':
				opt_d = strdup(optarg);
				if (!opt_d) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'i':
				opt_i = atoi(optarg);	/* FIXME */
				break;
			case 'e':
				opt_e = TRUE;
				break;
			case 'F':
				opt_F = strdup(optarg);
				if (!opt_F) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'g':
				opt_g = strdup(optarg);
				if (!opt_g) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'k':
				opt_k = atoi(optarg);	/* FIXME */
				break;
			case 'l':
				opt_l = strdup(optarg);
				if (!opt_l) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'm':
				opt_m = atoi(optarg);	/* FIXME */
				break;
			case 'o':
				opt_o = TRUE;
				break;
			case 'p':
				opt_p = strdup(optarg);
				if (!opt_p) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'q':
				opt_q = TRUE;
				break;
			case 'R':
				opt_R = TRUE;
				break;
			case 'r':
			case 's':
				opt_r = TRUE;
				break;
			case 'v':
				print_version();
				exit(EXIT_SUCCESS);
				break;
			case 'U':
				opt_U = strdup(optarg);
				if (!opt_U) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'u':
				opt_u = strdup(optarg);
				if (!opt_u) {
					logit("Cannot allocate memory: %s\n", strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 'w':
				opt_w = atoi(optarg);	/* FIXME */
				break;
			case 'h':
			case 'H':
			case '?':
				usage();
				exit(EXIT_SUCCESS);
				break;
		}
	}

	/* check the number of arguments */
	if (optind == argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	/* parse the values of the options */
	/* "0d:eF:l:op:qR:U:u:" */
	if (opt_0 != UNDEF)
		finish_on_exit0 = TRUE;
	if (opt_d)
		dir = opt_d;
	if (opt_e != UNDEF)
		logstderr = TRUE;
	if (opt_F)
		finish_if_this_file_exists = opt_F;
	if (opt_k != UNDEF) {
		kill_grace = opt_k;
	}
	if (opt_l)
		logfilename = opt_l;
	if (opt_o != UNDEF)
		logstdout = TRUE;
	if (opt_p)
		pidfilename = opt_p;
	if (opt_q != UNDEF)
		quiet = TRUE;
	if (opt_R != UNDEF) {
		if (!opt_d) {
			logit("Option '-R' cannot be used without dir given with '-d'.\n");
			exit(EXIT_FAILURE);
		} else {
			ch_root = TRUE;
		}
	}
	if (opt_U) {
		struct passwd *pw;

		/* UID lookup (won't work after a chroot) */
		if (!(pw = getpwnam(opt_U))) {
			logit("Unknown username \"%s\"\n", opt_U);
			exit(EXIT_FAILURE);
		}
		usepersona.empty = FALSE;
		usepersona.uid = pw->pw_uid;
		usepersona.gid = pw->pw_gid;
		usepersona.ngroups = GETGROUPLIST_INIT_NGROUPS;
		usepersona.groups = (gid_t *) malloc(usepersona.ngroups * sizeof(gid_t));
		if (!usepersona.groups) {
			logit("Cannot allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (getgrouplist(opt_U, usepersona.gid, usepersona.groups, &usepersona.ngroups) < 0) {
			usepersona.groups = (gid_t *) realloc(usepersona.groups, usepersona.ngroups * sizeof(gid_t));
			if (!usepersona.groups) {
				logit("Cannot allocate memory: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (getgrouplist(opt_U, usepersona.gid, usepersona.groups, &usepersona.ngroups) < 0) {
			logit("Cannot get supplementary gids of \"%s\": %s\n", opt_U, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (opt_u) {
		struct passwd *pw;

		/* UID lookup (won't work after a chroot) */
		if (!(pw = getpwnam(opt_u))) {
			logit("Unknown username \"%s\"\n", opt_u);
			exit(EXIT_FAILURE);
		}
		progpersona.empty = FALSE;
		progpersona.uid = pw->pw_uid;
		progpersona.gid = pw->pw_gid;
		progpersona.ngroups = GETGROUPLIST_INIT_NGROUPS;
		progpersona.groups = (gid_t *) malloc(progpersona.ngroups * sizeof(gid_t));
		if (!progpersona.groups) {
			logit("Cannot allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (getgrouplist(opt_u, progpersona.gid, progpersona.groups, &progpersona.ngroups) < 0) {
			progpersona.groups = (gid_t *) realloc(progpersona.groups, progpersona.ngroups * sizeof(gid_t));
			if (!progpersona.groups) {
				logit("Cannot allocate memory: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (getgrouplist(opt_u, progpersona.gid, progpersona.groups, &progpersona.ngroups) < 0) {
			logit("Cannot get supplementary gids of \"%s\": %s\n", progusername, strerror(errno));
			exit(EXIT_FAILURE);
		}
		progusername = strdup(opt_u);
		progshell = strdup(pw->pw_shell);
		proghome = strdup(pw->pw_dir);
	}

	/* "ac:g:i:m:rsw:" */
	if (opt_a != UNDEF) {
		opstyle = anticron;
		if (opt_r != UNDEF) {
			logit("Option '-a' cannot be used with '-r' or '-s'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_c != UNDEF) {
			logit("Option '-c' cannot be used (makes no sense) with '-a'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_i != UNDEF) {
			logit("Option '-i' cannot be used (makes no sense) with '-a'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_m != UNDEF) {
			logit("Option '-m' cannot be used (makes no sense) with '-a'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_w != UNDEF)
			delay = opt_w;
		if (opt_g) {
			logit("Option '-g' cannot be used (makes no sense) with '-a'.\n");
			exit(EXIT_FAILURE);
		}
	} else if (opt_r != UNDEF) {
		opstyle = inetd;
		if (opt_c != UNDEF) {
			maxattempts = opt_c;
		}
		if (opt_i != UNDEF) {
			increment = opt_i;
		}
		if (opt_m != UNDEF) {
			minruntime = opt_m;
		}
		if (opt_w != UNDEF)
			delay = opt_w;
		if (opt_g) {
			giveupcmdline = opt_g;
		}
	} else {
		if (opt_c != UNDEF) {
			logit("Option '-c' cannot be used (makes no sense) without '-r' or '-s'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_i != UNDEF) {
			logit("Option '-i' cannot be used (makes no sense) without '-r' or '-s'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_m != UNDEF) {
			logit("Option '-m' cannot be used (makes no sense) without '-r' or '-s'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_w != UNDEF) {
			logit("Option '-w' cannot be used (makes no sense) without '-r' or '-s' or '-a'.\n");
			exit(EXIT_FAILURE);
		}
		if (opt_g) {
			logit("Option '-g' cannot be used (makes no sense) without '-r' or '-s'.\n");
			exit(EXIT_FAILURE);
		}
	}

	/* parse remaining args */
	/* copy program name & the argv vector */
	program = strdup(argv[optind]);
	if (!program) {
		logit("Cannot allocate memory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	prog_and_args = (char **) malloc((argc-optind+1) * sizeof(char *));
	if (!prog_and_args) {
		logit("Cannot allocate memory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < argc-optind; i++) {
		prog_and_args[i] = strdup(argv[optind+i]);
		if (!prog_and_args[i]) {
			logit("Cannot allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	prog_and_args[i] = NULL;

	/* now we can compute default pidfile name if needed */
	if (!pidfilename) {
		asprintf(&pidfilename, "%s%s%s", default_pidfilename_prefix, basename(program), default_pidfilename_suffix);
		if (!pidfilename) {
			logit("Cannot allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* now we can compute default logfile name if needed */
	if (!logfilename) {
		asprintf(&logfilename, "%s%s%s", default_logfilename_prefix, basename(program), default_logfilename_suffix);
		if (!logfilename) {
			logit("Cannot allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* check whether the paths are absolute */
	if (dir && dir[0] != '/') {
		logit("The directory given with '-d' must be an absolute path.\n");
		exit(EXIT_FAILURE);
	}
	if (pidfilename && pidfilename[0] != '/') {
		logit("The filename given with '-p' must be an absolute path.\n");
		exit(EXIT_FAILURE);
	}
	if (logfilename && logfilename[0] != '/') {
		logit("The filename given with '-l' must be an absolute path.\n");
		exit(EXIT_FAILURE);
	}
	if (finish_if_this_file_exists && finish_if_this_file_exists[0] != '/') {
		logit("The filename given with '-F' must be an absolute path.\n");
		exit(EXIT_FAILURE);
	}
	if (program[0] != '/') {
		logit("The filename given as the program executable must be an absolute path.\n");
		exit(EXIT_FAILURE);
	}

	/* spawn the daemon part */
	pcsk();

	/* clean-up */
	free(pidfilename);
	free(logfilename);
	free(giveupcmdline);
	free(program);
	free(prog_and_args);

	exit(EXIT_SUCCESS);
} /*MAIN*/


/* ------------------------------------------------------------------- */

/* spawning the daemon part */
void pcsk(void)
{
	struct stat pidfile_sb, logfile_sb, flagfile_sb;
	char *executable;
	size_t len;
	int i;

	/* chdir to the root, not to make any filesystem busy unnecessarily */
	if (chdir("/")) {
		logit("Cannot chdir to \"/\": %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!usepersona.empty || !progpersona.empty) {
		/* save old euid/egid */
		oldpersona.empty = FALSE;
		oldpersona.uid = geteuid();
		oldpersona.gid = getegid();
		oldpersona.ngroups = getgroups(0, NULL);
		oldpersona.groups = (gid_t *) malloc(oldpersona.ngroups * sizeof(gid_t));
		if (!oldpersona.groups) {
			logit("Cannot allocate memory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (getgroups(oldpersona.ngroups, oldpersona.groups) < 0) {
			logit("Cannot get current supplementary gids: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* change euid/egid if asked for */
		if (!usepersona.empty)
			change_persona_into(usepersona);
	}

	/* in cmdline concatenate prog_and_args with spaces */
	for (i = len = 0, cmdline = NULL; prog_and_args[i]; i++) {
		size_t oldlen = len;
		len += strlen(prog_and_args[i]) + 1;
		cmdline = (char *) realloc(cmdline, len + 1);
		strcpy(cmdline + oldlen, prog_and_args[i]);
		cmdline[len-1] = ' ';
	}
	if (i == 0)
		cmdline[len] = '\0';
	else
		cmdline[len-1] = '\0';

	/* check if the process is already runnig */
	if (already_running()) {
		logit("\"%s\" already running.\n", program);
		exit(EXIT_FAILURE);
	}

	/* remove the flag file */
	/* first check for symlink attacks */
	if (finish_if_this_file_exists) {
		if (!lstat(finish_if_this_file_exists, &flagfile_sb)) {
			if (!S_ISREG(flagfile_sb.st_mode)) {
				logit("The file given with '-F' (\"%s\") is not a regular file.\n", finish_if_this_file_exists);
				exit(EXIT_FAILURE);
			}
			if (unlink(finish_if_this_file_exists)) {
				logit("Cannot delete file \"%s\": %s\n", finish_if_this_file_exists, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
	}

	/* open pidfile (before forking, so that failure is seen) */
	/* first check for symlink attacks */
	if (!lstat(pidfilename, &pidfile_sb)) {
		if (!S_ISREG(pidfile_sb.st_mode)) {
			logit("pidfile (\"%s\") is not a regular file.\n", pidfilename);
			exit(EXIT_FAILURE);
		}
	}
	if (!(pidfile = fopen(pidfilename, "w"))) {
		logit("Cannot write pidfile \"%s\": %s\n", pidfilename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* open the logfile (before forking, so that failure is seen */
	/* first check for symlink attacks */
	if (!lstat(logfilename, &logfile_sb)) {
		if (!S_ISREG(logfile_sb.st_mode)) {
			logit("logfile (\"%s\") is not a regular file.\n", logfilename);
			exit(EXIT_FAILURE);
		}
	}
	if (!(logfile = fopen(logfilename, "a"))) {
		logit("Cannot append \"%s\": %s\n", logfilename, strerror(errno));
		exit(EXIT_FAILURE);
	}
	fclose(logfile);

	/* open /dev/null for reading & writing */
	if ((devnull = open("/dev/null", O_RDWR)) < 0) {
		logit("Cannot write \"/dev/null\": %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * create socket pairs (before forking, so that failure is seen)
	 * use sockets instead of pipes: O_ASYNC works on sockets but not pipes
	 */
	if (logstderr) {
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, logsock_stderr)) {
			logit("Cannot create socket pair: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		child_stderr = logsock_stderr[0];
	}
	if (logstdout) {
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, logsock_stdout)) {
			logit("Cannot create socket pair: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		child_stdout = logsock_stdout[0];
	}
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sock_sync)) {
		logit("Cannot create socket pair: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* test if the program is executable before forking */
	if (ch_root)
		asprintf(&executable, "%s/%s", dir, program);
	else
		executable = program;
	/* now we have to regain privileges */
	change_persona_back(oldpersona);
	/* change to the persona used to run the program */
	change_persona_into(progpersona);
	if (access(executable, F_OK | R_OK | X_OK)) {
		logit("\"%s\" is not executable: %s\n", program, strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* change persona back */
	change_persona_back(oldpersona);
	/* relinquish privileges */
	change_persona_into(usepersona);

	/* fork to the background */
	pid = fork();
	if (pid > 0) {		/* parent */
		/* write pidfile */
		fprintf(pidfile, "%d\n", pid);

		/* close pidfile & /dev/null */
		fclose(pidfile);

		/* done */
		return;
	} else if (pid < 0) {	/* error */
		logit("Cannot fork(): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else {		/* child */
		/* daemon part */
		pcsk_daemon();
	}
} /*pcsk*/

/* ------------------------------------------------------------------- */

/* the daemon part: spawns the program */
void pcsk_daemon(void)
{
	time_t last;
	int runtime;
	int delay_now;
	int counter;

	/* from now we log to the logfile - not stderr */
	daemonised = TRUE;

	/* close pidfile */
	fclose(pidfile);

	/* register cleanup function */
	atexit(&cleanup);

	/* redirect stdin from /dev/null */
	dup2(devnull, STDIN_FILENO);

	/* redirect stderr to /dev/null */
	dup2(devnull, STDERR_FILENO);

	/* redirect stdout to /dev/null */
	dup2(devnull, STDOUT_FILENO);

	/* close /dev/null */
	close(devnull);

	/* leave the old process-group */
	setsid();

	/* set up signal handlers */
	setup_sigactions();

	/* log that we're ready */
	logit("Starting %s v%s.", program_invocation_short_name, pcsk_version());

	/* set delay_now to default value */
	delay_now = delay;

	/* spawn the program (respawn if requested) */
	for (counter = 0;;) {
		int status;
		pid_t term_pid;

		/* check for termination signals */
		if (terminating)
			break;

		/* remember the time of the attempt */
		last = time(NULL);

		/* fork */
		pid = fork();
		if (pid == 0) {			/* child */
			/* remember the process' role */
			proc_role = proc_spawner;
			/* spawn the child */
			spawn_child();
			/* never reached */
			exit(EXIT_FAILURE);
		} else if (pid < 0) {		/* error */
			logit("Cannot fork(): %s", strerror(errno));
			logit("%s: waiting for %d seconds..", program_invocation_short_name, delay_now);
			my_sleep(delay_now);
		} else {			/* parent */
			struct stat flagfile_sb;

			/* log the attempt */
			if (!quiet)
				logit("Spawning \"%s\" (pid = %d).", cmdline, pid);

			/* let the child run */
			write(sock_sync[1], DUMMY_STRING, strlen(DUMMY_STRING));

			/* remember that we have a child */
			haschild = TRUE;

			/*
			 * wait for the child to terminate,
			 * collect & log stdout and/or stderr if asked for
			 */
			wait_and_process_io(&status);

			/* compute runtime */
			runtime = difftime(time(NULL), last);

			/* parse the exit code and log it */
			parse_exitcode(status, runtime);

			/* check if we should not respawn it */
			if (opstyle == once || terminating)
				break;
			if (finish_on_exit0 && WEXITSTATUS(status) == 0) {
				if (!quiet)
					logit("Exit status was zero (true), that means I should not respawn the program (option '-0' was given).");
				break;
			}
			if (finish_if_this_file_exists && !stat(finish_if_this_file_exists, &flagfile_sb)) {
				if (!quiet)
					logit("The file '%s' exists, that means I should not respawn the program (option '-F' was given).", finish_if_this_file_exists);
				break;
			}

			/* manage the delay & run the give-up commandline if giving up */
			if (!manage_delay(&delay_now, &counter, last, runtime))
				break;	/* gave up */

			/* wait before the next attempt */
			if (delay_now > 0) {
				if (!quiet)
					logit("Sleeping for %d seconds..", delay_now);
				my_sleep(delay_now);
			}
		}
	}

	if (opstyle == once)
		/* log it that no respawn was asked */
		if (!quiet)
			logit("Respawning was not asked for (no '-r','-s' or '-a' option was given).");

	/* log that we have finished */
	logit("Exiting.");
	cleanup();

	/* close log sockets */
	if (logstdout) {
		close(logsock_stderr[0]);
		close(logsock_stderr[1]);
	}
	if (logstderr) {
		close(logsock_stdout[0]);
		close(logsock_stdout[1]);
	}
	close(sock_sync[0]);
	close(sock_sync[1]);
} /*pcsk_daemon*/

/* ------------------------------------------------------------------- */

/* set up signal handlers of the pcsk daemon */
void setup_sigactions(void)
{
	sigset_t block_mask;
	struct sigaction sa;

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGALRM);
	sigaddset(&block_mask, SIGTERM);
	sigaddset(&block_mask, SIGINT);
	sigaddset(&block_mask, SIGQUIT);
	sigaddset(&block_mask, SIGIO);
	sigaddset(&block_mask, SIGCHLD);
	sa.sa_flags = SA_RESTART;
	sa.sa_mask = block_mask;

	sa.sa_handler = &sigalrm_handler;
	sigaction(SIGALRM, &sa, NULL);

	sa.sa_handler = &sigterm_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	sa.sa_handler = &sigio_handler;
	sigaction(SIGIO, &sa, NULL);

	sa.sa_handler = &sigchld_handler;
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGWINCH, &sa, NULL);
	sigaction(SIGPWR, &sa, NULL);

	sa.sa_handler = SIG_DFL;
	sigaction(SIGCONT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
}

/* ------------------------------------------------------------------- */

/* reset signal handlers to default */
void reset_sigactions(void)
{
	sigset_t block_mask;
	struct sigaction sa;

	sigemptyset(&block_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_mask = block_mask;

	sa.sa_handler = SIG_DFL;
	sigaction(SIGALRM, &sa, NULL);

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	sigaction(SIGIO, &sa, NULL);

	sigaction(SIGCHLD, &sa, NULL);

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGWINCH, &sa, NULL);
	sigaction(SIGPWR, &sa, NULL);

	sigaction(SIGCONT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
}

/* ------------------------------------------------------------------- */

/* manage the delay in the main loop; return false if and only if giving up */
int manage_delay(int *delay_now, int *counter, int last, int runtime)
{
	if (opstyle == inetd) {
		/* check if the runtime was long enough */
		if (runtime < minruntime) {
			/* increment the counter */
			if (++*counter >= maxattempts && maxattempts != 0) {
				/* too many failures */
				logit("Too many failures. Giving up.");

				/* run 'give-up' command line
				 * if there is one */
				if (giveupcmdline) {
					logit("Runnig give-up commandline \"%s\"..", giveupcmdline);
					system(giveupcmdline);
				}
				return FALSE;
			} else {
				/* increment the delay */
				*delay_now += increment;
			}
		} else {
			/* restore the delay value */
			*delay_now = delay;
		}
	} else if (opstyle == anticron) {
		*delay_now = delay - difftime(time(NULL), last);
		if (*delay_now < 0)
			*delay_now = 0;
	}

	return TRUE;
}

/* ------------------------------------------------------------------- */

/* spawn the child */
void spawn_child(void)
{
	char buf[strlen(DUMMY_STRING)];	/* buffer for the dummy data */

	/* reset signal handlers to default */
	reset_sigactions();

	/* redirect stderr to the child_stderr socket if asked for */
	if (logstderr) {
		dup2(logsock_stderr[1], STDERR_FILENO);
		close(logsock_stderr[0]);
		close(logsock_stderr[1]);
	}

	/* redirect stdout to the child_stdout socket if asked for */
	if (logstdout) {
		dup2(logsock_stdout[1], STDOUT_FILENO);
		close(logsock_stdout[0]);
		close(logsock_stdout[1]);
	}

	/* close the wrong end of the 'synchroniser' socket */
	close(sock_sync[1]);

	/* regain privileges */
	change_persona_back(oldpersona);

	/*
	 * some buggy software needs the conffiles in the current
	 * working directory, these need an option to change the dir;
	 * we can do a chroot if needed
	 */
	if (dir) {
		if (ch_root) {
			if (chroot(dir) || chdir("/")) {
				logit("Cannot chroot to \"%s\": %s\n", dir, strerror(errno));
				logit("Won't exec() the program.");
				exit(EXIT_FAILURE);
			}
		} else if (chdir(dir)) {
			logit("Cannot chdir to \"%s\": %s", dir, strerror(errno));
			logit("Won't exec() the program.");
			exit(EXIT_FAILURE);
		}
	}

	/* change uid if needed */
	if (!progpersona.empty) {
		/* then change persona permanently */
		if (setgid(progpersona.gid)) {
			logit("Cannot change gid to %d: %s", progpersona.gid, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (setgroups(progpersona.ngroups, progpersona.groups)) {
			logit("Cannot change supplementary gids: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (setuid(progpersona.uid)) {
			logit("Cannot change uid to %d: %s", progpersona.uid, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* environment maintainance */
		setenv("SHELL", progshell, 1);
		setenv("LOGNAME", progusername, 1);
		setenv("USER", progusername, 1);
		setenv("HOME", proghome, 1);
	}

	/* wait until the parent is ready
	 * so that entries in the logfile be
	 * in logical order */
	read(sock_sync[0], buf, sizeof(buf));
	close(sock_sync[0]);

	/* exec the program (or die) */
	execv(program, prog_and_args);
	logit("Cannot exec \"%s\": %s", program, strerror(errno));
	exit(EXIT_FAILURE);
} /*spawn_child*/

/* ------------------------------------------------------------------- */

/* parse the exit code and log it */
void parse_exitcode(int status, int runtime)
{
	if (!quiet || WEXITSTATUS(status) || WIFSIGNALED(status)) {
		char *msg;
		char *rtstr;

		asprintf(&msg, "Child process %d", pid);
		if (!msg) {
			logit("Cannot allocate memory: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (WIFSIGNALED(status)) {
			char *tmp;

			asprintf(&tmp, "%s caught signal %d,", msg, WTERMSIG(status));
			if (!tmp) {
				logit("Cannot allocate memory: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
			free(msg);
			msg = tmp;
		}
		if (runtime < 60)
			asprintf(&rtstr, "%ds", runtime);
		else {
			int hour, min, sec;

			hour = (runtime % 86400) / 3600;
			min = (runtime % 3600) / 60;
			sec = (runtime % 60);
			if (runtime < 86400)		/* 1 day */
				asprintf(&rtstr, "%02d:%02d:%02d", hour, min, sec);
			else {
				int day;

				day = runtime / 86400;
				asprintf(&rtstr, "%ddays %02d:%02d:%02d", day, hour, min, sec);
			}
		}

		logit("%s%s exited with %d exit status. Runtime: %s", msg, (WCOREDUMP(status) ? ", dumped core" : ""), WEXITSTATUS(status), rtstr);
		free(msg);
	}
} /*parse_exitcode*/

/* ------------------------------------------------------------------- */

/*
 * wait for the child to terminate,
 * collect & log stdout and/or stderr if asked for
 */
void wait_and_process_io(int *status)
{
	fd_set fd_all;
	struct timeval zerotime;
	char buf_stderr[LOGLINE_MAX+2] = "";
	char buf_stdout[LOGLINE_MAX+2] = "";
	char *ptr_stderr = buf_stderr;
	char *ptr_stdout = buf_stdout;
	sigset_t mask, oldmask;

	/* stuff needed by select */
	FD_ZERO(&fd_all);
	if (logstderr)
		FD_SET(child_stderr, &fd_all);
	if (logstdout)
		FD_SET(child_stdout, &fd_all);
	zerotime.tv_sec = 0;
	zerotime.tv_usec = 0;

	/*
	 * temporarily block the signals we are interested in,
	 * so that we cannot miss any signal
	 */
	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGIO);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	/* set async (signal driven) IO on the sockets */
	set_async_io(child_stderr);
	set_async_io(child_stdout);

	/*
	 * fake that both signals arrived so that to check for
	 * IO and child termination in the first turn
	 */
	got_sigio = got_sigchld = TRUE;

	/*
	 * wait and process IO
	 * until the child is dead AND no more IO is possible
	 */
	for (;;) {
		if (got_sigalrm) {
			/* check whether the alarm went off */
			check_for_termination();
		}
		if (got_sigterm) {
			/* check whether a termination signal was delivered */
			check_for_termination();
		}
		if (got_sigchld) {
			got_sigchld = FALSE;
			/* check if the child terminated - nonblocking */
			if (wait_child(status) == pid) {
				/* we don't have a child anymore: OK */
				haschild = FALSE;
				/* fake a SIGIO to finish with it */
				got_sigio = TRUE;
			}
		}
		if (got_sigio) {
			int ready;
			int got_any = FALSE;
			fd_set fd_got;

			got_sigio = FALSE;
			/* check if IO possible - nonblocking */
			do {
				fd_got = fd_all;
				if ((ready = select(FD_SETSIZE, &fd_got, NULL, NULL, &zerotime)) > 0) {
					got_any = TRUE;
					if (logstderr && FD_ISSET(child_stderr, &fd_got)) {
						collect_output(child_stderr, buf_stderr, LOGLINE_MAX, &ptr_stderr);
					}
					if (logstdout && FD_ISSET(child_stdout, &fd_got)) {
						collect_output(child_stdout, buf_stdout, LOGLINE_MAX, &ptr_stdout);
					}
				}
			} while (ready > 0);
			if (!got_any && !haschild)
				break;	/* no input was possible & child dead */
		}

		/*
		 * wait until something is to be done, but never miss a signal
		 * (the important signals are blocked outside
		 * - before and after - sigsuspend(),
		 * but unblocked only inside)
		 */
		while (!got_sigalrm && !got_sigterm && !got_sigio && !got_sigchld)
			sigsuspend(&oldmask);
	}

	/* now unblock these signals */
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
} /*wait_and_process_io*/

/* ------------------------------------------------------------------- */

/* nonblocking wait */
pid_t wait_child(int *status)
{
	pid_t term_pid;

	if ((term_pid = waitpid(-1, status, WNOHANG)) < 0) {
		/* error: log and continue */
		logit("Error in waitpid(): %s", strerror(errno));
		logit("Sleeping for %d seconds, and going on...", error_delay);
		my_sleep(error_delay);
	}

	return term_pid;
}

/* ------------------------------------------------------------------- */

/* read line(s) from the file descriptor, writelog() each line.
 * a line is: chars until \n, or at most LOGLINE_MAX chars
 */
void collect_output(int file, char *buf, size_t buflen, char **ptr)
{
	size_t chars_read;
	char *end = buf + buflen;
	char *eol;
	char *last;

	/* read until end of buffer */
	chars_read = read(file, *ptr, end - *ptr);
	last = *ptr + chars_read;

	/* split up at newlines and write to logfile */
	for (*ptr = buf; (*ptr < last) && (eol = memchr(*ptr, '\n', last - *ptr)); *ptr = eol + 1) {
		*eol = '\0';
		writelog(*ptr);
	}

	/* if there was any '\n', move back the remaining,
	 * write the line otherwise
	 */
	if (*ptr == buf) {
		/* if the buffer is full, write it as a partial line,
		 * leave it alone (wait for continuation) otherwise
		 */
		if (last == end) {
			*end = '+';	/* partial line marker */
			*(end+1) = '\0';
			writelog(buf);
			*ptr = buf;
		} else {
			*ptr = last;
		}
	} else if (*ptr < end) {
		/* move the remaining to the beginning of the buffer */
		memcpy(buf, *ptr, last - *ptr);
		*ptr = buf + (last - *ptr);
	} else {
		*ptr = buf;
	}
}

/* ------------------------------------------------------------------- */

/*
 * check whether a termination or alarm signal was caught,
 * and if so, log it and arrange for exiting
 */
void check_for_termination(void)
{
	if (got_sigterm) {
		got_sigterm = FALSE;
		if (!terminating) {
			logit("Caught signal %d, terminating..", term_signum);
			terminating = TRUE;
			if (haschild) {
				logit("Killing child %d with signal %d..", pid, SIGTERM);
				kill(pid, SIGTERM);
				/* arrange to send SIGKILL after some time to the child if needed */
				if (kill_grace)
					alarm(kill_grace);
			}
		}
	}
	if (got_sigalrm) {
		got_sigalrm = FALSE;
		if (terminating && haschild) {
			logit("Killing child %d with signal %d..", pid, SIGKILL);
			kill(pid, SIGKILL);
		}
	}
}

/* ------------------------------------------------------------------- */

/* check if the process is already runnig */
int already_running(void)
{
	int ret = FALSE;

	/* now we have to regain privileges */
	change_persona_back(oldpersona);

	if ((pidfile = fopen(pidfilename, "r")) > 0) {
		char *pidstr;
		size_t len;
		int pid;
		char *proc_exe;
		struct stat pcsk_sb, proc_sb;

		/* get the inode number of ourselves (the textfile of pcsk) */
		if (stat("/proc/self/exe", &pcsk_sb)) {
			logit("Cannot stat() \"%s\": %s\n", "/proc/self/exe", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* read pid number (string) */
		pidstr = NULL;
		len = 0;
		getline(&pidstr, &len, pidfile);
		fclose(pidfile);
		pid = atoi(pidstr);

		/* get the inode number of the running process (if any) */
		asprintf(&proc_exe, "/proc/%d/exe", pid);
		if (!stat(proc_exe, &proc_sb)) {
			/* compare the device and inode numbers */
			if (pcsk_sb.st_dev == proc_sb.st_dev && pcsk_sb.st_ino == proc_sb.st_ino) {
				ret = TRUE;
			}
		}
	}

	/* now relinquish privileges again */
	change_persona_into(usepersona);

	return ret;
}

/* ------------------------------------------------------------------- */

/* prints the line (said by pcsk itself) to the logfile */
void logit(const char *first, ...)
{
	va_list more;
	char *msg;
	char *line;
	size_t length;

	va_start(more, first);

	/* create a string containing the original format strings */
	if (daemonised)
		asprintf(&msg, "%s[%d]: %s", program_invocation_short_name, getpid(), first);
	else
		asprintf(&msg, "%s: %s\n", program_invocation_short_name, first);
	if (!msg)
		return;

	/* expand those format strings */
	length = vasprintf(&line, msg, more);
	if (!line)
		return;

	/* how to log it depends on whether we are daemonised */
	if (!daemonised) {
		/* write to stderr */
		fprintf(stderr, line);
	} else {
		/* append to the file */
		writelog(line);
	}

	/* free memory */
	free(msg);
	free(line);

	va_end(more);
}

/* ------------------------------------------------------------------- */

/* prepends a timestamp and appends the line to the logfile */
void writelog(const char *string)
{
	int file;
	char date[23];
	time_t now;
	char *line;
	struct stat logfile_sb;

	/* create timestamp string */
	now = time(NULL);
	strftime(date, 23, "[%Y-%m-%d %H:%M:%S] ", localtime(&now));

	/* concatenate to the timestamp */
	asprintf(&line, "%s%s\n", date, string);
	if (!line)
		return;

	/* open the logfile, but first check for symlink attacks */
	if (((!lstat(logfilename, &logfile_sb) ? S_ISREG(logfile_sb.st_mode) : errno == ENOENT) && (file = open(logfilename, O_WRONLY | O_APPEND | O_CREAT, 0666)) >= 0)) {
		/* write the string to the logfile */
		write(file, line, strlen(line));
		/* close the logfile */
		close(file);
	} else {
		/* we can't log it - it will fail,
		 * and an infinite recursion will occur
		 *
		 * now we have two choices:
		 * exit or go on without logging
		 * the latter seems better (but this is
		 * a difficult question)
		 */
	}

	/* free memory */
	free(line);
}

/* ------------------------------------------------------------------- */

/* cleanup, registered with atexit() */
void cleanup(void)
{
	/* check whether we are the main process */
	if (proc_role != proc_main)
		return;

	/* remove pidfile */
	unlink(pidfilename);
}

/* ------------------------------------------------------------------- */

/* SIGALRM handler */
void sigalrm_handler(int signum)
{
	got_sigalrm = TRUE;
}
/* ------------------------------------------------------------------- */

/* termination signal (SIGTERM, SIGINT, SIGQUIT) handler */
void sigterm_handler(int signum)
{
	got_sigterm = TRUE;
	if (!term_signum)
		term_signum = signum;
}

/* ------------------------------------------------------------------- */

/* SIGIO handler */
void sigio_handler(int signum)
{
	got_sigio = TRUE;
}

/* ------------------------------------------------------------------- */

/* SICHLD handler */
void sigchld_handler(int signum)
{
	got_sigchld = TRUE;
}

/* ------------------------------------------------------------------- */

/* set async (signal driven) IO on the sockets */
void set_async_io(int fd)
{
	fcntl(fd, F_SETOWN, getpid());
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_ASYNC);
}

/* ------------------------------------------------------------------- */

/* set SA_RESTART flag on the specified signal */
void set_sa_restart(int signum, int state)
{
	struct sigaction sa;

	sigaction(signum, NULL, &sa);
	if (state)
		sa.sa_flags |= SA_RESTART;
	else
		sa.sa_flags &= ~SA_RESTART;
	sigaction(signum, &sa, NULL);
}

/* ------------------------------------------------------------------- */

/*
 * do a sleep(), but disables SA_RESTART flag on
 * the termination & alarm signals during the sleep
 */
void my_sleep(unsigned int secs)
{
	set_sa_restart(SIGALRM, FALSE);
	set_sa_restart(SIGTERM, FALSE);
	set_sa_restart(SIGINT, FALSE);
	set_sa_restart(SIGQUIT, FALSE);
	sleep(secs);
	set_sa_restart(SIGALRM, TRUE);
	set_sa_restart(SIGTERM, TRUE);
	set_sa_restart(SIGINT, TRUE);
	set_sa_restart(SIGQUIT, TRUE);
	check_for_termination();
}

/* ------------------------------------------------------------------- */

/* change process persona to an unprivileged one */
void change_persona_into(persona_t persona)
{
	if (persona.empty)
		return;
	if (setegid(persona.gid)) {
		logit("Cannot change effective gid to %d: %s", persona.gid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (setgroups(persona.ngroups, persona.groups)) {
		logit("Cannot change supplementary gids: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (seteuid(persona.uid)) {
		logit("Cannot change effective uid to %d: %s", persona.uid, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/* ------------------------------------------------------------------- */

/* change process persona back to a privileged one */
void change_persona_back(persona_t persona)
{
	if (persona.empty)
		return;
	if (seteuid(persona.uid)) {
		logit("Cannot change effective uid to %d: %s", persona.uid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (setegid(persona.gid)) {
		logit("Cannot change effective gid to %d: %s", persona.gid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (setgroups(persona.ngroups, persona.groups)) {
		logit("Cannot change supplementary gids: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/* ------------------------------------------------------------------- */

/* returns the version string */
const char *pcsk_version(void)
{
	static char *rev = NULL;

	if (!rev)
		asprintf(&rev, "%s(rev%s)", PCSK_VERSION, PCSK_REVISION);

	return rev;
}

/* ------------------------------------------------------------------- */

/* usage (help) text */
void usage(void)
{
	printf("Usage:\n");
	printf("\t%s [-eoq] [-p pidfile] [-l logfile] [[-R] -d dir]\n" , program_invocation_short_name);
	printf("\t [-u username] [-U username] program [[--] args]\n\n");
	printf("\t%s -r|-s [-eoq] [-p pidfile] [-l logfile] [-c count] [-w wait]\n", program_invocation_short_name);
	printf("\t [-i increment] [-m minruntime] [-g giveupcmdline] [[-R] -d dir]\n");
	printf("\t [-u username] [-U username] [-0] [-F flagfile] program [[--] args]\n\n");
	printf("\t%s -a [-eoq] [-p pidfile] [-l logfile] [-w wait] [[-R] -d dir]\n", program_invocation_short_name);
	printf("\t [-u username] [-U username] [-0] [-F flagfile] program [[--] args]\n\n");
	printf("Daemonises (and optionally supervises) a script or program that cannot\n");
	printf("daemonise, or supervises a program that can, but cannot supervise itself.\n\n");
	printf("OPTIONS:\n");
	printf("\t-r,-s\tsupervise (respawn if died) the program\n");
	printf("\t-a\tanti-cron-style repeater\n");
	printf("\t\t(start the program after the previous instance terminated\n");
	printf("\t\t and at least n seconds elapsed since the starting\n");
	printf("\t\t of the previous instance)\n");
	printf("\t-c\tmax count of failed respawns allowed (give up then),\n");
	printf("\t\t0 = never give up (default: %d)\n", default_maxattempts);
	printf("\t-d\tdirectory to change into before spawning (default: /)\n");
	printf("\t-e\tlog program's stderr\n");
	printf("\t-g\tcommand line to run when giving up\n");
	printf("\t-i\tseconds to add to -w on each failed attempt (default: %d)\n", default_increment);
	printf("\t-k\tseconds to wait before sending SIGKILL to the program\n");
	printf("\t\t(0 to disable, default: %d)\n", default_kill_grace);
	printf("\t-l\tthe name of the logfile (default: %sprogram%s)\n", default_logfilename_prefix, default_logfilename_suffix);
	printf("\t-m\tminimal runtime (in secs) to regard an attempt\n");
	printf("\t\tsuccessful (default: %d)\n", default_minruntime);
	printf("\t-o\tlog program's stdout\n");
	printf("\t-p\tthe name of the pidfile (default: %sprogram%s)\n", default_pidfilename_prefix, default_pidfilename_suffix);
	printf("\t-q\tquiet logging (no log if everything is OK)\n");
	printf("\t-R\tchroot into the dir given with -d\n");
	printf("\t-u\tchange uid to username's when running program\n");
	printf("\t-U\tchange effective uid to username's\n");
	printf("\t\twhen root privileges not needed\n");
	printf("\t-v\tprint version information and exit\n");
	printf("\t-w\tseconds to wait between spawning again (default: %d)\n", default_delay);
	printf("\t-0\tdon't respawn the program if exited with 0 exit status\n");
	printf("\t-F\tdon't respawn the program if this file exists\n");
}

/* ------------------------------------------------------------------- */

void print_version(void)
{
	printf("pcsk Version %s\n\n", pcsk_version());
	printf("Written by Norbert Buchmuller <norbi@nix.hu>\n");
	printf("Copyright (C) 2004 Norbert Buchmuller\n");
	printf("\n");
	printf("This program is free software; you can redistribute it and/or modify\n");
	printf("it under the terms of the GNU General Public License as published by\n");
	printf("the Free Software Foundation; either version 2 of the License, or\n");
	printf("(at your option) any later version.\n");
	printf("\n");
	printf("This program is distributed in the hope that it will be useful,\n");
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("GNU General Public License for more details.\n");
	printf("\n");
	printf("You should have received a copy of the GNU General Public License\n");
	printf("along with this program; if not, write to the Free Software\n");
	printf("Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n");
}

/* ------------------------------------------------------------------- */

/* TODO:
 * - fix possible memory leaks
 * - GNU-style long options
 * - man page
 * - alternate logging style: do not close()/open() the logfile at every line,
 *   but instead accept a signal spec on the commandline, and reopen the
 *   logfile when that signal arrives (and do not deliver that signal to the
 *   child)
 *
 * EXTRAS:
 * - interface to achieve start-stop-daemon -like functionality
 *   (SIGKILL is still problematic) - a socket or sg like that
 * - environment cleanup (see start-stop-daemon, run, supervise)
 */

/*EOF*/
