#include <sys/types.h>
#include <sys/cdefs.h>
#include <machine/cpufunc.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <vm/vm.h>

#if 1
static __inline void
clac(void)
{

	__asm __volatile("clac" : : : "memory");
}

static __inline void
stac(void)
{

	__asm __volatile("stac" : : : "memory");
}
#endif

#define TEST_STRING	"Write from kernel to user-space. De ha mar sikerul, akkor: http://www.youtube.com/watch?v=wT8NO5FDS7E"

const char *agreement = "shoot my foot!!!11oneone!!";
static bool allow_tests = false;
static char *buf = NULL;
static caddr_t us_addr_in=NULL;
static volatile caddr_t us_addr=NULL;

MALLOC_DECLARE(M_SMAP_TEST);
MALLOC_DEFINE(M_SMAP_TEST, "smap test", "Intel SMAP test malloc area");

SYSCTL_DECL(_debug);
SYSCTL_NODE(_debug,  OID_AUTO, smap, CTLFLAG_RD, 0,
   "Intel SMAP test cases.");

static int
sysctl_debug_smap_agreement(SYSCTL_HANDLER_ARGS)
{
	int error=0;

	error = sysctl_handle_string(oidp, buf, 4096, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (strcmp(buf, agreement) == 0) {
		printf("{+} SMAP tests enabled!\n");
		allow_tests = true;
	} else {
		printf("{+} SMAP tests disabled!\n");
		allow_tests = false;
	}

	return (error);
}

SYSCTL_PROC(_debug_smap, OID_AUTO, agreement_string,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_agreement,
    "A", "shoot my foot!!!11oneone!!");

static int
sysctl_debug_smap_us_addr(SYSCTL_HANDLER_ARGS)
{
	int error=0;

	error = sysctl_handle_long(oidp, &us_addr_in, 0, req);
	if (error != 0 || req->newptr == NULL) {
		return (error);
	}

	us_addr = us_addr_in;
	printf("{+} us_addr set to %p\n", us_addr);

	return (error);
}

SYSCTL_PROC(_debug_smap, OID_AUTO, us_addr,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_us_addr,
    "L", "user-space address");


static int
sysctl_debug_smap_test0(SYSCTL_HANDLER_ARGS)
{
	int error=0;
	long val;

	printf("{#} TEST: not allowed read address from kernel to user-space\n");

	if(!allow_tests) {
		printf("{-} tests are disabled\n");
		return (ENOSYS);
	}

	error = sysctl_handle_long(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL) {
		return (error);
	}

	switch (val) {
	case	0:
		break;
	case	1:
		printf("{#} derefable user-space memory region from kernel\n");

		printf("{-} %p\n", us_addr);
		val = 0;
		break;
	default:
		val = 0;
		return (EINVAL);
		break;
	}

	return (error);
}
SYSCTL_PROC(_debug_smap, OID_AUTO, test0,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_test0,
    "L", "print out the userspace buffer address");

static int
sysctl_debug_smap_not_allowed_read(SYSCTL_HANDLER_ARGS)
{
	int error=0;
	long val;
	volatile char t;

	printf("{#} TEST: not allowed read from kernel to user-space\n");

	if(!allow_tests) {
		printf("{-} tests are disabled\n");
		return (ENOSYS);
	}

	error = sysctl_handle_long(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL) {
		return (error);
	}

	switch (val) {
	case	0:
		break;
	case	1:
		printf("{#} read user-space memory region from kernel\n");

		t = *us_addr;
		printf("{+} us_buf: %s\n", us_addr);

		val = 0;
		break;
	default:
		val = 0;
		return (EINVAL);
		break;
	}

	return (error);
}
SYSCTL_PROC(_debug_smap, OID_AUTO, test_not_allowed_read,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_not_allowed_read,
    "L", "read from userspace buffer");

static int
sysctl_debug_smap_not_allowed_write(SYSCTL_HANDLER_ARGS)
{
	int error=0;
	long val;

	printf("{#} TEST: not allowed write from kernel to user-space\n");

	if(!allow_tests) {
		printf("{-} tests are disabled\n");
		return (ENOSYS);
	}

	error = sysctl_handle_long(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL) {
		return (error);
	}

	switch (val) {
	case	0:
		break;
	case	1:
		printf("{#} write user-space memory region from kernel\n");

		printf("{#} write \"%s\" from kernel to user-space buffer\n", TEST_STRING);
		*us_addr = 0;
		strcpy(us_addr, TEST_STRING);

		val = 0;
		break;
	default:
		val = 0;
		return (EINVAL);
		break;
	}

	return (error);
}
SYSCTL_PROC(_debug_smap, OID_AUTO, test_not_allowed_write,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_not_allowed_write,
    "L", "write to userspace buffer");

static int
sysctl_debug_smap_allowed_read(SYSCTL_HANDLER_ARGS)
{
	int error=0;
	long val;
	volatile char t;

	printf("{#} TEST: allowed read from kernel to user-space\n");

	if(!allow_tests) {
		printf("{-} tests are disabled\n");
		return (ENOSYS);
	}

	error = sysctl_handle_long(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL) {
		return (error);
	}

	switch (val) {
	case	0:
		break;
	case	2:
		printf("{#} read user-space memory region from kernel\n");

		stac();
		t = *us_addr;
		printf("{+} us_buf: %s\n", us_addr);
		clac();

		val = 0;
		break;
	default:
		val = 0;
		return (EINVAL);
		break;
	}

	return (error);
}
SYSCTL_PROC(_debug_smap, OID_AUTO, test_allowed_read,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_allowed_read,
    "L", "allowed read from userspace buffer");

static int
sysctl_debug_smap_allowed_write(SYSCTL_HANDLER_ARGS)
{
	int error=0;
	long val;

	printf("{#} TEST: allowed write from kernel to user-space\n");

	if(!allow_tests) {
		printf("{-} tests are disabled\n");
		return (ENOSYS);
	}

	error = sysctl_handle_long(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL) {
		return (error);
	}

	switch (val) {
	case	0:
		break;
	case	2:
		printf("{#} write user-space memory region from kernel\n");

		printf("{#} write \"%s\" from kernel to user-space buffer\n", TEST_STRING);
		stac();
		*us_addr = 0;
		strcpy(us_addr, TEST_STRING);
		clac();

		val = 0;
		break;
	default:
		val = 0;
		return (EINVAL);
		break;
	}

	return (error);
}
SYSCTL_PROC(_debug_smap, OID_AUTO, test_allowed_write,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, sysctl_debug_smap_allowed_write,
    "L", "allowed write to userspace buffer");



static int
smap_tester_vuln_kld_loader(struct module *m __unused, int what, void *arg __unused)
{
	int error = 0;

	switch (what) {
	case MOD_LOAD:
		buf = malloc(4096, M_SMAP_TEST, M_WAITOK | M_ZERO);
		printf("SMAP tester loaded.\n");
		printf("WARNING: vulnerable kernel module!\n");
		break;
	case MOD_UNLOAD:
		free(buf, M_SMAP_TEST);
		printf("SMAP tester unloaded.\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

DEV_MODULE(smap_tester_vuln_kld, smap_tester_vuln_kld_loader, NULL);
