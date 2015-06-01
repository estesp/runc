#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <sched.h>
#include <signal.h>
#include <endian.h>
#include <stdint.h>
#include <inttypes.h>

/* All arguments should be above stack, because it grows down */
struct clone_arg {
	/*
	 * Reserve some space for clone() to locate arguments
	 * and retcode in this place
	 */
	char stack[4096] __attribute__ ((aligned(8)));
	char stack_ptr[0];
	jmp_buf *env;
};

#define pr_perror(fmt, ...) fprintf(stderr, "nsenter: " fmt ": %m\n", ##__VA_ARGS__)

static int child_func(void *_arg)
{
	struct clone_arg *arg = (struct clone_arg *)_arg;
	longjmp(*arg->env, 1);
}

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#define _GNU_SOURCE
#include "syscall.h"
#if defined(__NR_setns) && !defined(SYS_setns)
#define SYS_setns __NR_setns
#endif
#ifdef SYS_setns
int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#endif

static int clone_parent(jmp_buf * env, int flags) __attribute__ ((noinline));
static int clone_parent(jmp_buf * env, int flags)
{
	struct clone_arg ca;
	int child;

	ca.env = env;
	child = clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD | flags, &ca);

	return child;
}

// get init pipe from the parent. It's used to read bootstrap data, and to
// write pid to after nsexec finishes setting up the environment.
static int get_init_pipe()
{
	char buf[PATH_MAX], *initpipe;
	int pipenum = -1;
	initpipe = getenv("_LIBCONTAINER_INITPIPE");
	if (initpipe == NULL) {
		return -1;
	}
	pipenum = atoi(initpipe);
	snprintf(buf, sizeof(buf), "%d", pipenum);
	if (strcmp(initpipe, buf)) {
		pr_perror("Unable to parse _LIBCONTAINER_INITPIPE");
		exit(1);
	}

	return pipenum;
}

// namespacesLength returns the number of additional namespaces to setns. The
// argument is a comma-separated string of namespace paths.
static int namespacesLength(char *nspaths)
{
	int size = 0, i = 0;
	for (i = 0; nspaths[i]; i++) {
		if (nspaths[i] == ',') {
			size += 1;
		}
	}
	return size + 1;
}

static uint32_t readint32(char *buf, int *start)
{
	union {
		uint32_t n;
		char arr[4];
	} num;
	int i = 0;
	for (i = 0; i < 4; i++) {
		num.arr[i] = buf[*start + i];
	}
	*start += 4;
	return be32toh(num.n);
}

static uint8_t readint8(char *buf, int *start)
{
	union {
		uint8_t n;
		char arr[1];
	} num;
	num.arr[0] = buf[*start];
	*start += 1;
	return num.n;
}

static void writedata(int fd, char *data, int start, int len)
{
	int written = 0;
	while (written < len) {
		size_t nbyte, i;
		if ((len - written) < 1024) {
			nbyte = len - written;
		} else {
			nbyte = 1024;
		}
		i = write(fd, data + start + written, nbyte);
		if (i == -1) {
			pr_perror("failed to write data to %d", fd);
			exit(1);
		}
		written += i;
	}
}

void nsexec()
{
	jmp_buf env;
	int child, pipenum = -1;

	uint64_t total;
	uint32_t cloneflags = -1;
	int consolefd = -1;
	int uidmap_start, uidmap_len = -1;
	int gidmap_start, gidmap_len = -1;

	// if we dont have init pipe, then just return to the parent
	pipenum = get_init_pipe();
	if (pipenum == -1) {
		return;
	}
	if (read(pipenum, &total, 8) != 8 || total <= 0) {
		pr_perror("Invalid total size of bootstrap data");
		exit(1);
	}
	total = be64toh(total);

	// pre-allocate the bootstrap data
	char data[total];
	int i = 0;
	while (i < total) {
		size_t nbyte, nread;
		if ((total - i) < 1024) {
			nbyte = total - i;
		} else {
			nbyte = 1024;
		}
		nread = read(pipenum, data + i, nbyte);
		if (nread < 0) {
			pr_perror("Failed to read from fd %d", pipenum);
			exit(1);
		}
		i += nread;
	}

	// pre-processing the data to get offset of what we interested in
	int start = 0;
	while (start < total) {
		uint8_t namelen = readint8(data, &start);
		if (strncmp(data + start, "clone_flags", namelen) == 0) {
			// process clone_flags
			start = start + namelen;
			cloneflags = readint32(data, &start);
		} else if (strncmp(data + start, "console_path", namelen) == 0) {
			// process console_paths
			start = start + namelen;
			uint32_t consolelen = readint32(data, &start);
			char console[consolelen + 1];
			strncpy(console, data + start, consolelen);
			console[consolelen] = '\0';
			// get the console path before setns because it may change mnt namespace
			consolefd = open(console, O_RDWR);
			if (consolefd < 0) {
				pr_perror("Failed to open console %s", console);
				exit(1);
			}
			start = start + consolelen;
		} else if (strncmp(data + start, "ns_paths", namelen) == 0) {
			// process ns_paths
			start = start + namelen;
			uint32_t nspaths_len = readint32(data, &start);
			char nspaths[nspaths_len + 1];
			strncpy(nspaths, data + start, nspaths_len);
			nspaths[nspaths_len] = '\0';

			// if custom namespaces are required, open all descriptors and perform
			// setns on them
			int nslen = namespacesLength(nspaths);
			int fds[nslen];
			char *nslist[nslen];
			int i = -1;
			char *ns, *saveptr;
			for (i = 0; i < nslen; i++) {
				char *str = NULL;
				if (i == 0) {
					str = nspaths;
				}
				ns = strtok_r(str, ",", &saveptr);
				if (ns == NULL) {
					break;
				}
				fds[i] = open(ns, O_RDONLY);
				if (fds[i] == -1) {
					pr_perror("Failed to open %s", ns);
					exit(1);
				}
				nslist[i] = ns;
			}
			for (i = 0; i < nslen; i++) {
				if (setns(fds[i], 0) != 0) {
					pr_perror("Failed to setns to %s", nslist[i]);
					exit(1);
				}
				close(fds[i]);
			}

			start = start + nspaths_len;
		} else if (strncmp(data + start, "uid_map", namelen) == 0) {
			// process uid_map
			start = start + namelen;
			uidmap_len = readint32(data, &start);
			uidmap_start = start;
			start = start + uidmap_len;
		} else if (strncmp(data + start, "gid_map", namelen) == 0) {
			// process gid_map
			start = start + namelen;
			gidmap_len = readint32(data, &start);
			gidmap_start = start;
			start = start + gidmap_len;
		}
	}
	// required clone_flags to be passed
	if (cloneflags == -1) {
		pr_perror("missing clone_flags");
		exit(1);
	}

	if (setjmp(env) == 1) {
		// Child
		if (consolefd != -1) {
			if (setsid() == -1) {
				pr_perror("setsid failed");
				exit(1);
			}
			if (ioctl(consolefd, TIOCSCTTY, 0) == -1) {
				pr_perror("ioctl TIOCSCTTY failed");
				exit(1);
			}
			if (dup3(consolefd, STDIN_FILENO, 0) != STDIN_FILENO) {
				pr_perror("Failed to dup 0");
				exit(1);
			}
			if (dup3(consolefd, STDOUT_FILENO, 0) != STDOUT_FILENO) {
				pr_perror("Failed to dup 1");
				exit(1);
			}
			if (dup3(consolefd, STDERR_FILENO, 0) != STDERR_FILENO) {
				pr_perror("Failed to dup 2");
				exit(1);
			}
		}
		// Finish executing, let the Go runtime take over.
		return;
	}
	// Parent

	// We must fork to actually enter the PID namespace, use CLONE_PARENT
	// so the child can have the right parent, and we don't need to forward
	// the child's exit code or resend its death signal.
	child = clone_parent(&env, cloneflags);
	if (child < 0) {
		pr_perror("Unable to fork");
		exit(1);
	}
	// if we specifies uid_map and gid_map, writes the data to /proc files
	if (uidmap_start > 0 && uidmap_len > 0) {
		char buf[PATH_MAX];
		if (snprintf(buf, sizeof(buf), "/proc/%d/uid_map", child) < 0) {
			pr_perror("failed to construct uid_map file for %d", child);
			exit(1);
		}
		int fd = open(buf, O_RDWR);
		writedata(fd, data, uidmap_start, uidmap_len);
	}
	if (gidmap_start > 0 && gidmap_len > 0) {
		{
			// write setgroups. This is needed since kernel 3.19, because you can't
			// write gid_map without disabling setgroups() system call.
			char buf[PATH_MAX];
			if (snprintf(buf, sizeof(buf), "/proc/%d/setgroups", child) < 0) {
				pr_perror("failed to construct setgroups file for %d", child);
				exit(1);
			}
			int fd = open(buf, O_RDWR);
			if (write(fd, "allow", 5) != 5) {
				// If the kernel is too old to support /proc/PID/setgroups,
				// write will return ENOENT; this is OK.
				if (errno != ENOENT) {
					pr_perror("failed to write allow to %s", buf);
					exit(1);
				}
			}
		}
		{
			// write gid mappings
			char buf[PATH_MAX];
			if (snprintf(buf, sizeof(buf), "/proc/%d/gid_map", child) < 0) {
				pr_perror("failed to construct gid_map file for %d", child);
				exit(1);
			}
			int fd = open(buf, O_RDWR);
			writedata(fd, data, gidmap_start, gidmap_len);
		}
	}
	// finish setting up the environment, write back pid of the child to the
	// parent to finish the bootstrap process
	char buf[PATH_MAX];
	int len = snprintf(buf, sizeof(buf), "{ \"pid\" : %d }\n", child);
	if (write(pipenum, buf, len) != len) {
		pr_perror("Unable to send a child pid");
		kill(child, SIGKILL);
		exit(1);
	}

	exit(0);
}
