#!/usr/bin/env python3
"""
Patch open-iscsi 2.1.10 for cross-compiling to Android (aarch64 / bionic).

Usage:  python3 ois_patch.py <path-to-open-iscsi-source>

Why each patch exists:
  * libkmod   - Android has no libkmod, and no /lib/modules to modprobe from.
                The iSCSI transports we use (iscsi_tcp) are built into our
                custom kernel, so "load the module" becomes a successful no-op.
  * libmount  - not present in the NDK; upstream only pulls in the header with
                no actual API usage in initiator_common.c.
  * SysV IPC  - bionic supports neither SysV shared memory nor SysV semaphores.
                Upstream usr/log.c funnels log messages to a forked logger child
                through a shm ring buffer guarded by semaphores; we replace it
                with a straight-to-syslog() version (Android's syslog() forwards
                to logd, so everything still shows up in logcat).
  * libpthread / libdl / librt - merged into bionic's libc, no separate .so to
                link against.
  * libcrypto - taken from pkg-config (absent) so we add -lcrypto by hand.
  * -Werror   - clang flags several GNU-extension patterns that upstream relies
                on; they are warnings, not real bugs.
  * isns / libsystemd / libcap - not needed for a direct iSCSI initiator.
"""

import os
import re
import sys
import time

# --------------------------------------------------------------------------
# Replacement for usr/log.c : no SysV IPC, no forked logger child.
# --------------------------------------------------------------------------
LOG_C = r'''/*
 * iSCSI Safe Logging and Tracing Library -- Android/bionic port.
 *
 * Upstream ships log messages from iscsid to a forked logger child through a
 * System V shared-memory ring buffer guarded by a System V semaphore set.
 * Android's bionic libc provides neither SysV shared memory nor SysV
 * semaphores, so this port drops the ring buffer (and the logger child) and
 * writes messages straight to syslog(). bionic's syslog() forwards to logd,
 * so the output is still reachable through `logcat`.
 *
 * Based on usr/log.c from open-iscsi:
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *   Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 *   Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "iscsi_util.h"
#include "log.h"

#define LOGDBG 0

#if LOGDBG
#define logdbg(file, fmt, args...) fprintf(file, fmt, ##args)
#else
#define logdbg(file, fmt, args...) do {} while (0)
#endif

char *log_name;
int log_level = 0;
struct logarea *la = NULL;

static void (*log_func)(int prio, void *priv, const char *fmt, va_list ap);
static void *log_func_priv;

#define LOG_BUF_SIZE 2048

/*
 * bionic does export vsyslog(), but staying with vsnprintf()+syslog() keeps us
 * compatible with every API level and gives us one place to format.
 */
static void log_vsyslog(int prio, const char *fmt, va_list ap)
{
	char buf[LOG_BUF_SIZE];
	va_list ap2;

	va_copy(ap2, ap);
	vsnprintf(buf, sizeof(buf), fmt, ap2);
	va_end(ap2);

	syslog(prio, "%s", buf);
}

void log_do_log_daemon(int prio,
		       __attribute__((unused))void *priv,
		       const char *fmt,
		       va_list ap)
{
	log_vsyslog(prio, fmt, ap);
}

void log_do_log_std(int prio,
		    __attribute__((unused))void *priv,
		    const char *fmt,
		    va_list ap)
{
	if (prio == LOG_INFO) {
		vfprintf(stdout, fmt, ap);
		fprintf(stdout, "\n");
	} else {
		fprintf(stderr, "%s: ", log_name);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

void log_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_func(LOG_WARNING, log_func_priv, fmt, ap);
	va_end(ap);
}

void log_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_func(LOG_ERR, log_func_priv, fmt, ap);
	va_end(ap);
}

void log_debug(int level, const char *fmt, ...)
{
	if (log_level > level) {
		va_list ap;
		va_start(ap, fmt);
		log_func(LOG_DEBUG, log_func_priv, fmt, ap);
		va_end(ap);
	}
}

void log_info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_func(LOG_INFO, log_func_priv, fmt, ap);
	va_end(ap);
}

/*
 * NOTE: log_init() must return >= 0 for both callbacks. iscsid treats a
 * negative value as a hard failure and exits; it also only calls
 * log_close(log_pid) when log_pid >= 0. Upstream returned the PID of the
 * forked logger child here, but we have no child, so we return 0 -- meaning
 * log_close() becomes a plain closelog() and never signals anyone.
 */
int log_init(char *program_name, int size,
	     void (*func)(int prio, void *priv, const char *fmt, va_list ap),
	     void *priv)
{
	logdbg(stderr, "enter log_init\n");
	log_name = program_name;
	log_func = func;
	log_func_priv = priv;

	if (log_func == log_do_log_daemon) {
		openlog(log_name, 0, LOG_DAEMON);
		setlogmask(LOG_UPTO(LOG_DEBUG));
	}

	return 0;
}

void log_close(pid_t pid)
{
	(void)pid;
	closelog();
}
'''


# --------------------------------------------------------------------------
# mntcheck.c replacements: /proc-based mount detection instead of libmount
# --------------------------------------------------------------------------
MOUNT_HELPERS = r"""/*
 * Android (bionic) has no libmount, and open-iscsi only needs "is this block
 * device still mounted/swapped on?" so it can refuse a logout. Answer that by
 * scraping the same tables libmount would have parsed: /proc/mounts and
 * /proc/swaps.
 */

static int _dev_in_proc_file(const char *devpath, const char *procfile)
{
	FILE *f;
	char line[4096];
	const char *tail;
	int found = 0;

	f = fopen(procfile, "re");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		char *src = strtok(line, " \\t\\n");

		if (!src)
			continue;
		if (!strcmp(src, devpath)) {
			found = 1;
			break;
		}
		/* /proc/mounts may name the device by basename rather than by
		 * full path (/dev/block/sdX vs /dev/sdX), so compare both. */
		tail = strrchr(devpath, '/');
		tail = tail ? tail + 1 : devpath;
		if (!strcmp(src, tail)) {
			found = 1;
			break;
		}
	}

	fclose(f);
	return found;
}

static int _dev_path_in_use(const char *devpath)
{
	if (_dev_in_proc_file(devpath, "/proc/mounts"))
		return 1;
	if (_dev_in_proc_file(devpath, "/proc/swaps"))
		return 1;
	return 0;
}
"""

BLOCKDEV_CHECK_MNTS = r"""static int blockdev_check_mnts(char *syspath)
{
	char *devname = NULL;
	char *_devname = NULL;
	int rc = 0;

	devname = sysfs_get_uevent_devname(syspath);
	if (!devname)
		goto out;

	_devname = calloc(1, PATH_MAX);
	if (!_devname)
		goto out;
	snprintf(_devname, PATH_MAX, "/dev/%s", devname);

	rc = _dev_path_in_use(_devname);
out:
	free(devname);
	free(_devname);
	return rc;
}
"""

def read(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


def write(path, text):
    """Write with retries -- Windows AV/indexer can briefly lock a file we
    just rewrote, which would otherwise abort the patch half-way through."""
    last = None
    for _attempt in range(20):
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(text)
            return
        except PermissionError as exc:
            last = exc
            time.sleep(0.15)
    raise SystemExit('FATAL cannot write %s: %s' % (path, last))


def sub_once(path, pattern, repl, flags=0, required=True):
    """Regex-replace the first occurrence; complain loudly if nothing matched."""
    text = read(path)
    new, n = re.subn(pattern, repl, text, count=1, flags=flags)
    if n == 0:
        msg = 'NO MATCH in %s: %s' % (path, pattern[:70])
        if required:
            raise SystemExit('FATAL ' + msg)
        print('WARN  ' + msg)
        return
    write(path, new)
    print('patched %-42s (%s)' % (path, pattern[:44]))


def sed_drop(path, needles, required=False):
    """Drop any line containing one of `needles`."""
    lines = read(path).splitlines(True)
    kept, dropped = [], 0
    for line in lines:
        if any(n in line for n in needles):
            dropped += 1
            continue
        kept.append(line)
    write(path, ''.join(kept))
    print('%-8s %-42s (%d lines removed)' % ('sedded', path, dropped))


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: ois_patch.py <open-iscsi-src-dir>')
    root = sys.argv[1]
    os.chdir(root)
    print('patching open-iscsi source at: %s' % os.getcwd())

    # ---------------------------------------------------------------- libkmod
    sed_drop('usr/transport.c', ['#include <libkmod.h>'])
    sub_once(
        'usr/transport.c',
        r'int transport_load_kmod\(char \*transport_name\)\s*\{.*?\n\}\n',
        'int transport_load_kmod(char *transport_name)\n'
        '{\n'
        '\t/*\n'
        '\t * On Android there is no libkmod and no /lib/modules tree, and the\n'
        '\t * transports we use (iscsi_tcp) are already built into the kernel,\n'
        '\t * so there is nothing to load. Report success.\n'
        '\t */\n'
        '\tlog_debug(1, "transport_load_kmod(%s): built-in, skipping",\n'
        '\t\t  transport_name);\n'
        '\treturn 0;\n'
        '}\n',
        flags=re.DOTALL,
    )

    sed_drop('libopeniscsiusr/iface.c', ['#include <libkmod.h>'])
    sub_once(
        'libopeniscsiusr/iface.c',
        r'static int _load_kernel_module\(struct iscsi_context \*ctx, '
        r'const char \*drv_name\)\s*\{.*?return rc;\n\}\n',
        'static int _load_kernel_module(struct iscsi_context *ctx, '
        'const char *drv_name)\n'
        '{\n'
        '\t(void)ctx;\n'
        '\t(void)drv_name;\n'
        '\t/*\n'
        '\t * On Android there is no libkmod and no /lib/modules tree, and the\n'
        '\t * transports we use (iscsi_tcp) are already built into the kernel,\n'
        '\t * so there is nothing to load. Report success.\n'
        '\t */\n'
        '\treturn LIBISCSI_OK;\n'
        '}\n',
        flags=re.DOTALL,
    )
    # libkmod never exists here, so its pkg-config lines only add noise.
    # NOTE: the Makefiles invoke pkg-config through the $(PKG_CONFIG) variable,
    # so match on the argument rather than the command name.
    for mk in ('libopeniscsiusr/Makefile', 'usr/Makefile'):
        sed_drop(mk, ['--cflags libkmod', '--libs libkmod'])

    # --------------------------------------------------------------- libmount
    # initiator_common.c only pulls in the header without using any API.
    sed_drop('usr/initiator_common.c', ['#include <libmount'])

    # usr/mntcheck.c really DOES use libmount: it parses mtab + swaps to decide
    # whether a session is still in use (which blocks a logout). bionic has no
    # libmount, so read /proc/mounts and /proc/swaps directly instead.
    sed_drop('usr/mntcheck.c', ['#include <libmount'])
    sub_once(
        'usr/mntcheck.c',
        r'static struct libmnt_table \*mtab, \*swaps;\n'
        r'static struct libmnt_cache \*mntcache;\n',
        MOUNT_HELPERS,
    )
    sub_once(
        'usr/mntcheck.c',
        r'static void libmount_cleanup\(void\)\s*\{.*?\n\}\n',
        'static void libmount_cleanup(void)\n'
        '{\n'
        '\t/* nothing to free: we parse /proc directly */\n'
        '}\n',
        flags=re.DOTALL,
    )
    sub_once(
        'usr/mntcheck.c',
        r'static int libmount_init\(void\)\s*\{.*?\n\}\n',
        'static int libmount_init(void)\n'
        '{\n'
        '\t/* nothing to set up: /proc/mounts is read on demand */\n'
        '\treturn 0;\n'
        '}\n',
        flags=re.DOTALL,
    )
    sub_once(
        'usr/mntcheck.c',
        r'static int blockdev_check_mnts\(char \*syspath\)\s*\{.*?\n\}\n',
        BLOCKDEV_CHECK_MNTS,
        flags=re.DOTALL,
    )

    # --------------------------------------------------------------- SysV IPC
    # Drop <sys/sem.h> and every semaphore field; nothing outside log.c touches
    # struct logarea, and log.c is about to be replaced wholesale.
    text = read('usr/log.h')
    text = re.sub(r'union semun\s*\{[^}]*\};', '', text, count=1)
    text = text.replace('#include <sys/sem.h>\n', '')
    for field in ('\tstruct sembuf ops[1];\n', '\tint semid;\n',
                  '\tunion semun semarg;\n'):
        text = text.replace(field, '')
    write('usr/log.h', text)
    print('patched usr/log.h (dropped sys/sem.h + semaphore fields)')

    if 'logarea_init' in read('usr/log.c'):
        write('usr/log.c', LOG_C)
        print('replaced usr/log.c (no SysV IPC, straight to syslog)')
    else:
        print('WARN usr/log.c already replaced?')

    # --------------------------------------------------------- usr/Makefile
    # Order matters: strip the pkg-config lines FIRST, then edit the in-memory
    # text, then write once. (An earlier version alternated read/write and
    # silently lost every edit.)
    mku = 'usr/Makefile'
    sed_drop(mku, [
        '--cflags libkmod', '--libs libkmod',
        '--cflags libsystemd', '--libs libsystemd',
        '--cflags libcap', '--libs libcap',
        '--cflags libcrypto', '--libs libcrypto',
    ])

    text = read(mku)
    # libs that do not exist on Android / that we do not want
    for token in ('-DISNS_SUPPORTED', '-lisns', '-lmount', '-lcap', '-lrt',
                  '-Werror'):
        text = text.replace(token, '')

    # Normalise the three link rules to:
    #     $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lcrypto $(ISCSI_LIB)
    # Moving $(LDFLAGS) in front of -lcrypto matters: our OpenSSL install prefix
    # reaches the linker as -L/opt/ossl/lib inside LDFLAGS, and -L must be seen
    # before the -l that needs it.
    link_line, n_links = re.subn(
        r'\t\$\(CC\) \$\(CFLAGS\) \$\^ -o \$@[^\n]*\$\(LDFLAGS\) \$\(ISCSI_LIB\)',
        '\t$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lcrypto $(ISCSI_LIB)',
        text)
    assert n_links == 3, 'expected 3 link rules, rewrote %d' % n_links
    write(mku, link_line)
    print('patched usr/Makefile: flags cleaned + %d link rules normalised'
          % n_links)

    # Fail loudly if any forbidden flag survived.
    check = read(mku)
    for bad in ('-Werror', '-DISNS_SUPPORTED', '-lisns', '-lmount', '-lrt',
                '--cflags libkmod', '--libs libsystemd'):
        assert bad not in check, 'usr/Makefile still contains %r' % bad
    assert '-lcrypto' in check, 'usr/Makefile lost -lcrypto'
    print('verified usr/Makefile (no forbidden flags, -lcrypto present)')

    # ------------------------------------------------ libopeniscsiusr/Makefile
    text = read('libopeniscsiusr/Makefile').replace('-Werror', '')
    write('libopeniscsiusr/Makefile', text)

    # -------------------------------------------------------- sanity checks
    print('\n=== residual references (must all be empty) ===')
    residual = 0
    # Only unresolved EXTERNAL symbols really matter here: anything still
    # pulled from libmount, libkmod, SysV IPC or libcap would fail to link.
    # (Our own local stubs libmount_init/libmount_cleanup are filtered out
    # below, and so are mentions inside comments and string literals.)
    pat = re.compile(r'\b(kmod_[a-z_]+|libmnt_[a-z_]+|mnt_[a-z_]+|'
                     r'shmget|shmat|shmdt|shmctl|semget|semop|semctl|'
                     r'union semun)\b')
    is_comment = re.compile(r'^\s*(\*|//)')
    is_stub = re.compile(r'\b(static void libmount_cleanup|'
                         r'static int libmount_init)\b')
    targets = []
    for d in ('usr', 'libopeniscsiusr', 'include', 'utils', 'sysdeps'):
        for name in sorted(os.listdir(d)):
            if name.endswith(('.c', '.h')):
                targets.append(os.path.join(d, name))
    for path in targets:
        for i, line in enumerate(read(path).splitlines(), 1):
            if is_comment.match(line) or is_stub.search(line):
                continue
            if pat.search(line):
                print('  %s:%d: %s' % (path, i, line.strip()[:90]))
                residual += 1
    print('residual count = %d' % residual)
    if residual:
        raise SystemExit('FATAL: leftover references after patching')
    print('OK: source tree is clean of unavailable dependencies')


if __name__ == '__main__':
    main()
