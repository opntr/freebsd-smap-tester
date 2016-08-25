#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#define TEST_STR	"Ezt itt jo lenne nem kiolvasni..."

void test_prepare(void);
void test_allow(void);
void test_0(void);
void test_allowed_read(void);
void test_allowed_write(void);
void test_not_allowed_read(void);
void test_not_allowed_write(void);

void test_destroy(void);

const char *us_buf = NULL;

int
main(int argc, char **argv)
{
	test_prepare();
	test_allow();

	test_0();
	getchar();
#if 1
	test_allowed_read();
	getchar();
	test_allowed_write();
	getchar();
	test_destroy();

	test_prepare();
	test_allow();
	test_0();
	getchar();
#endif
	test_not_allowed_read();
	getchar();
	test_not_allowed_write();
	getchar();

	test_destroy();

	return (0);
}

void
test_prepare(void)
{
	void *us_addr=0;
	long *oldp;
	size_t oldps;
	int error=0;

	/* prepare the user-space memory region */
	us_buf = strdup(TEST_STR);
	if (us_buf == NULL) {
		printf("[-] failed to prepare SMAP test\n");
		exit(1);
	}

	/* take the user-space address */
	us_addr = (void *)us_buf;
	printf("[+] debug.smap.us_addr = %p\n", us_addr);

	/* read the old sysctl value */
	sysctlbyname("debug.smap.us_addr", NULL, &oldps, NULL, 0);
	oldp = calloc(oldps, sizeof(char));
	error = sysctlbyname("debug.smap.us_addr", oldp, &oldps, NULL, 0);
	if (error != 0) {
		printf("[-] sysctl error - unable to read debug.smap.us_addr\n");
		exit(2);
	}
	printf("[+] debug.smap.us_addr = %p [old value]\n", oldp);

	/* push to the kernel the current user-space memory region */
	error = sysctlbyname("debug.smap.us_addr", NULL, 0, &us_addr, sizeof(us_addr));
	if (error != 0) {
		printf("[-] sysctl error - unable to set debug.smap.us_addr\n");
		exit(3);
	}
	printf("[+] debug.smap.us_addr = %p [new value]\n", us_addr);
}

void
test_destroy(void)
{
	const char *s = "tests disabled";
	int error;

	if (us_buf != NULL) {
		free(us_buf);
		us_buf = NULL;
	}


	sysctlbyname("debug.smap.agreement_string", NULL, 0, s, strlen(s));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test agreement\n");
		exit(4);
	}
	printf("[+] debug.smap.agreement_string = %s\n", s);
}


void
test_allow(void)
{
	const char *s = "shoot my foot!!!11oneone!!";
	int error;

	sysctlbyname("debug.smap.agreement_string", NULL, 0, s, strlen(s));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test agreement\n");
		exit(4);
	}
	printf("[+] debug.smap.agreement_string = %s\n\n", s);
}


void
test_0(void)
{
	long val=1;
	int error;

	printf("\n[#] %s\n", __func__);

	sysctlbyname("debug.smap.test0", NULL, 0, &val, sizeof(val));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test0\n");
		exit(5);
	}
	printf("[+] debug.smap.test0 done\n\n");
}


void
test_not_allowed_read(void)
{
	long val=1;
	int error;

	printf("\n[#] %s\n", __func__);

	printf("[+] us_buf: %s\n", us_buf);

	sysctlbyname("debug.smap.test_not_allowed_read", NULL, 0, &val, sizeof(val));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test_not_allowed_read\n");
		exit(6);
	}
	printf("[+] debug.smap.test_not_allowed_read done\n\n");
}

void
test_not_allowed_write(void)
{
	long val=1;
	int error;

	printf("\n[#] %s\n", __func__);

	printf("[+] us_buf: %s\n", us_buf);

	sysctlbyname("debug.smap.test_not_allowed_write", NULL, 0, &val, sizeof(val));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test_not_allowed_write\n");
		exit(6);
	}
	printf("[+] us_buf: %s\n", us_buf);
	printf("[+] debug.smap.test_not_allowed_write done\n\n");
}

void
test_allowed_read(void)
{
	long val=2;
	int error;

	printf("\n[#] %s\n", __func__);

	printf("[+] us_buf: %s\n", us_buf);

	sysctlbyname("debug.smap.test_allowed_read", NULL, 0, &val, sizeof(val));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test_allowed_read\n");
		exit(6);
	}
	printf("[+] debug.smap.test_allowed_read done\n\n");
}

void
test_allowed_write(void)
{
	long val=2;
	int error;

	printf("\n[#] %s\n", __func__);

	printf("[+] us_buf: %s\n", us_buf);

	sysctlbyname("debug.smap.test_allowed_write", NULL, 0, &val, sizeof(val));
	if (error != 0) {
		printf("[-] sysctl error - unable to set test_allowed_write\n");
		exit(6);
	}
	printf("[+] us_buf: %s\n", us_buf);
	printf("[+] debug.smap.test_allowed_write done\n\n");
}
