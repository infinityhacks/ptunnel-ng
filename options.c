#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <assert.h>

#include "options.h"
#include "utils.h"
#include "ptunnel.h"
#include "md5.h"


struct options opts;

enum option_type {
	OPT_BOOL, OPT_DEC32, OPT_HEX32, OPT_STR
};

struct option_usage {
	const char *short_help;
	int required;
	enum option_type otype;
	union {
		int32_t num;
		uint32_t unum;
		const char *str;
	};
	const char *long_help;
};

static const struct option_usage usage[] = {
	{"magic",        0, OPT_HEX32,  {.unum = 0xdeadc0de},
		"Set ptunnel magic hexadecimal number. (32-bit unsigned)\n"
		"This will be prefixed in all ICMP packets\n"
		"and can be used to bypass Cisco IPS\n"
		"This value has to be the same on the server and client!\n"
	},
	{"address",      1, OPT_DEC32,         {.unum = 0},
		"Set address of peer running packet forwarder. This causes\n"
		"ptunnel to operate in forwarding mode - the absence of this\n"
		"option causes ptunnel to operate in proxy mode.\n"
	},
	{"port",         1, OPT_DEC32,  {.unum = 2222},
		"Set TCP listening port (only used when operating in forward mode)\n"
	},
	{"address",      1, OPT_STR,    {.str = "127.0.0.1"},
		"Set remote proxy destination address if client\n"
		"Restrict to only this destination address if server\n"
	},
	{"port",         1, OPT_DEC32,  {.unum = 22},
		"Set remote proxy destination port if client\n"
		"Restrict to only this destination port if server\n"
	},
	{"connections",  0, OPT_DEC32,  {.unum = kMax_tunnels},
		"Set maximum number of concurrent tunnels\n"
	},
	{"level",        0, OPT_DEC32,  {.num = kLog_event},
		"Verbosity level (-1 to 4, where -1 is no output, and 4 is all output)\n"
		"The special level 5 (or higher) includes xfer logging (lots of output)\n"
	},
	{"interface",    0, OPT_STR,   {.str = "eth0"},
		"Enable libpcap on the given device.\n"
	},
	{"file",         0, OPT_STR,    {.str = "/var/log/ptunnel.log"},
		"Specify a file to log to, rather than printing to standard out.\n"
	},
	{NULL,           0, OPT_BOOL,   {.num = 0},
		"Client only. Enables continuous output of statistics (packet loss, etc.)\n"
	},
	{"password",     0, OPT_STR,    {.str = NULL},
		"Set password (must be same on client and proxy)\n"
		"If no password is set, you will be asked during runtime.\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Toggle use of UDP instead of ICMP. Proxy will listen on port 53 (must be root).\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Run proxy in unprivileged mode. This causes the proxy to forward\n"
		"packets using standard echo requests, instead of crafting custom echo replies.\n"
		"Unprivileged mode will only work on some systems, and is in general less reliable\n"
		"than running in privileged mode.\n"
	},
#ifndef WIN32
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Run in background, the PID will be written in the file supplied as argument\n"
	},
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Output debug to syslog instead of standard out.\n"
	},
	{"user",         0, OPT_STR,    {.str = "nobody"},
		"When started in privileged mode, drop down to user's rights as soon as possible\n"
	},
	{"group",        0, OPT_STR,    {.str = "nogroup"},
		"When started in privileged mode, drop down to group's rights as soon as possible\n"
	},
	{"directory",    0, OPT_STR,    {.str = "/var/lib/ptunnel"},
		"When started in privileged mode, restrict file access to the specified directory\n"
	},
#endif
#ifdef HAVE_SELINUX
	{NULL,           0, OPT_BOOL,   {.unum = 0},
		"Set SELinux context when all there is left to do are network I/O operations\n"
		"To combine with -chroot you will have to `mount --bind /proc /chrootdir/proc`\n"
	},
#endif
	{"help",         0, OPT_STR,    {.str = NULL}, "this\n"},
	{NULL,0,OPT_BOOL,{.unum=0},NULL}
};

static struct option long_options[] = {
	{"magic",       required_argument, 0, 'm'},
	{"proxy",       required_argument, 0, 'p'},
	{"listen",      optional_argument, 0, 'l'},
	{"remote-adr",  optional_argument, 0, 'r'},
	{"remote-port", optional_argument, 0, 'R'},
	{"connections", required_argument, 0, 'c'},
	{"verbosity",   required_argument, 0, 'v'},
	{"libpcap",     required_argument, 0, 'a'},
	{"logfile",     optional_argument, 0, 'o'},
	{"statistics",        no_argument, 0, 's'},
	{"passwd",      required_argument, 0, 'x'},
	{"udp",               no_argument, &opts.udp, 1 },
	{"unprivileged",      no_argument, &opts.unprivileged, 1 },
#ifndef WIN32
	{"daemon",            no_argument, 0, 'd'},
	{"syslog",            no_argument, 0, 'S'},
#endif
#ifndef WIN32
	{"user",        required_argument, 0, 'u'},
	{"group",       required_argument, 0, 'g'},
	{"chroot",      required_argument, 0, 't'},
#endif
#ifdef HAVE_SELINUX
	{"setcon",            no_argument, 0, 'e'},
#endif
	{"help",              no_argument, 0, 'h'},
	{NULL,0,0,0}
};


static const void *get_default_optval(enum option_type opttype, const char *optname) {
	for (unsigned i = 0; i < ARRAY_SIZE(long_options); ++i) {
		if (strncmp(long_options[i].name, optname, strlen(long_options[i].name)) == 0) {
			assert(usage[i].otype == opttype);
			return &usage[i].str;
		}
	}
	assert(NULL);
	return NULL;
}

static void set_options_defaults(void) {
	memset(&opts, 0, sizeof(opts));
	opts.magic           = *(uint32_t *)  get_default_optval(OPT_HEX32, "magic");
	opts.mode            = kMode_proxy;
	opts.given_proxy_ip  = *(uint32_t *)  get_default_optval(OPT_DEC32, "proxy");
	opts.tcp_listen_port = *(uint32_t *)  get_default_optval(OPT_DEC32, "listen");
	opts.given_dst_hostname = strdup(*(char **) get_default_optval(OPT_STR, "remote-adr"));
	opts.given_dst_port  = *(uint32_t *)  get_default_optval(OPT_DEC32, "remote-port");
	opts.max_tunnels     = *(uint32_t *)  get_default_optval(OPT_DEC32, "connections");
	opts.log_level       = *(int *)       get_default_optval(OPT_DEC32, "verbosity");
	opts.pcap_device     = strdup((char *)get_default_optval(OPT_STR,   "libpcap"));
	opts.log_file        = fopen(*(char **) get_default_optval(OPT_STR,   "logfile"), "a");
	opts.print_stats     = *(int *)       get_default_optval(OPT_BOOL,  "statistics");
#ifndef WIN32
#endif
}

static void print_multiline(const char *prefix, const char *multiline) {
	const char sep[] = "\n";
	const char *start, *end;

	start = multiline;
	do {
		if (start) {
			end = strstr(start, sep);
			if (end) {
				printf("%s%.*s\n", prefix, (int)(end-start), start);
				start = end + strlen(sep);
			}
		}
	} while (start && end);
}

static void print_long_help(unsigned index, int required_state) {
	const char spaces[] = "            ";

	if (usage[index].required != required_state)
		return;
	if (!long_options[index].name)
		return;

	if (isalpha(long_options[index].val)) {
		printf("%.*s-%c --%s\n", 4, spaces, long_options[index].val, long_options[index].name);
	} else {
		printf("%.*s--%s\n", 4, spaces, long_options[index].name);
	}

	if (usage[index].long_help) {
		print_multiline(&spaces[4], usage[index].long_help);
	}

	switch (usage[index].otype) {
		case OPT_BOOL:
			break;
		case OPT_DEC32:
			printf("%s(default: %d)\n", spaces, usage[index].num);
			break;
		case OPT_HEX32:
			printf("%s(default: 0x%X)\n", spaces, usage[index].unum);
			break;
		case OPT_STR:
			if (usage[index].str)
				printf("%s(default: %s)\n", spaces, usage[index].str);
			break;
	}
}

static void print_short_help(unsigned index, int required_state) {
	const char *ob = (required_state == 0 ? "[" : "");
	const char *cb = (required_state == 0 ? "]" : "");

	if (usage[index].required != required_state)
		return;
	if (!long_options[index].name)
		return;

	if (!usage[index].short_help && isalpha(long_options[index].val)) {
		printf(" %s-%c%s", ob, long_options[index].val, cb);
	}
	else if (!usage[index].short_help) {
		printf(" %s--%s%s", ob, long_options[index].name, cb);
	}
	else if (isalpha(long_options[index].val)) {
		printf(" %s-%c <%s>%s", ob, long_options[index].val, usage[index].short_help, cb);
	}
	else {
		printf(" %s--%s <%s>%s", ob, long_options[index].name, usage[index].short_help, cb);
	}
}

void print_usage(const char *arg0) {
	unsigned i;

	printf("ptunnel-ng v%d.%.2d\n\nUsage: %s", kMajor_version, kMinor_version, arg0);
	/* print (short)help argument line */
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_short_help(i, 1);
	}
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_short_help(i, 0);
	}

	printf("%s", "\n\n");
	/* print (long)help lines */
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_long_help(i, 1);
	}
	for (i = 0; i < ARRAY_SIZE(usage); ++i) {
		print_long_help(i, 0);
	}
}

int parse_options(int argc, char **argv) {
	int c = 0, optind = -1, has_logfile = 0;
	struct hostent *host_ent;
	md5_state_t state;
#ifndef WIN32
	struct passwd *pwnam;
	struct group *grnam;
#endif

	assert( ARRAY_SIZE(long_options) == ARRAY_SIZE(usage) );

	/* set defaults */
	set_options_defaults();

	/* parse command line arguments */
	while (1) {
		c = getopt_long(argc, argv, "m:p:l::r::R::c:v:a:o::sdSx:u:g:t:eh", &long_options[0], &optind);
		if (c == -1) break;

		switch (c) {
			case 'm':
				opts.magic = strtoul(optarg, NULL, 16);
				break;
			case 'p':
				opts.mode = kMode_forward;
				if (NULL == (host_ent = gethostbyname(optarg))) {
					pt_log(kLog_error, "Failed to look up %s as proxy address\n", optarg);
					return 1;
				}
				opts.given_proxy_ip = *(uint32_t*)host_ent->h_addr_list[0];
				break;
			case 'l':
				if (optarg)
					opts.tcp_listen_port = strtoul(optarg, NULL, 10);
				break;
			case 'r':
				if (optarg)
					opts.given_dst_hostname = strdup(optarg);
				break;
			case 'R':
				if (optarg)
					opts.given_dst_port = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				opts.max_tunnels = strtoul(optarg, NULL,10);
				if (opts.max_tunnels > kMax_tunnels)
					opts.max_tunnels = kMax_tunnels;
				break;
			case 'v':
				opts.log_level = strtol(optarg, NULL, 10);
				break;
			case 'a':
				if (opts.pcap_device)
					free(opts.pcap_device);
				opts.pcap_device = strdup(optarg);
				break;
			case 'o':
				if (optarg) {
					if (opts.log_file)
						fclose(opts.log_file);			
					opts.log_file = fopen(optarg, "a");
				}
				if (!opts.log_file) {
					pt_log(kLog_error, "Failed to open log file: \"%s\", Cause: %s\n", (optarg ? optarg : "default"), strerror(errno));
					pt_log(kLog_error, "Reverting log to standard out.\n");
				} else {
					has_logfile = 1;
				}
				break;
			case 's':
				opts.print_stats = !opts.print_stats;
				break;
			case 'x':
				opts.password_digest = (unsigned char *)calloc(MD5_LEN, sizeof(unsigned char));
				pt_log(kLog_debug, "Password set - unauthenicated connections will be refused.\n");
				//  Compute the password digest
				md5_init(&state);
				md5_append(&state, (md5_byte_t*)optarg, strlen(optarg));
				md5_finish(&state, opts.password_digest);
				//  Hide the password in process listing
				memset(optarg, '*', strlen(optarg));
				break;
#ifndef WIN32
			case 'd':
				opts.daemonize = true;
				if (NULL == (opts.pid_file = fopen(optarg, "w")))
					pt_log(kLog_error, "%s: %s\n", optarg, strerror(errno));
				break;
			case 'S':
				opts.use_syslog = 1;
				break;
			case 'u':
				errno = 0;
				if (NULL == (pwnam = getpwnam(optarg))) {
					pt_log(kLog_error, "%s: %s\n", optarg, errno ? strerror(errno) : "unknown user");
					exit(1);
				}
				opts.uid = pwnam->pw_uid;
				if (!opts.gid)
					opts.gid = pwnam->pw_gid;
				break;
			case 'g':
				errno = 0;
				if (NULL == (grnam = getgrnam(optarg))) {
					pt_log(kLog_error, "%s: %s\n", optarg, errno ? strerror(errno) : "unknown group");
					exit(1);
				}
				opts.gid = grnam->gr_gid;
				break;
			case 't':
				opts.root_dir = strdup(optarg);
				break;
#else
			case 'd':
			case 'S':
			case 'u':
			case 'g':
			case 't':
				pt_log(kLog_error, "%s: feature not supported", optarg);
				exit(1);
#endif
			case 'e':
#ifdef HAVE_SELINUX
				opts.selinux_context = strdup(optarg);
				break;
#else
				pt_log(kLog_error, "%s: feature not supported", optarg);
				exit(1);
#endif
			case 'h':
				print_usage(argv[0]);
				_exit(EXIT_SUCCESS);
			case 0: /* long opt only */
				break;
			default:
				pt_log(kLog_error, "%s: option unknown", optarg);
				break;
		}
	}

	if (NULL == (host_ent = gethostbyname(opts.given_dst_hostname))) {
		pt_log(kLog_error, "Failed to look up %s as destination address\n", opts.given_dst_hostname);
		return 1;
	}
	opts.given_dst_ip = *(uint32_t*)host_ent->h_addr_list[0];

	if (!has_logfile) {
		if (opts.log_file)
			fclose(opts.log_file);
		opts.log_file = stdout;
	}

	return 0;
}