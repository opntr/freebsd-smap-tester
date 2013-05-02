#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	char	buff[] = "hello...............";
	char	buff2[] = "XXXXXXXXXXXXXXXXXXXX";
	int	dev=-1;
	long	addr = (long)(long *)buff;
	int	kld_fileid;

	kld_fileid = kldload("./echo.ko");
       if (kld_fileid == -1 && errno != EEXIST) {
		printf("[-] failed to load echo.ko\n");
		return (1);
	}
	printf("[+] loaded echo.ko to kernel\n");

	dev=open("/dev/echo", O_RDWR);
	if (dev == -1) {
		printf("[-] failed to open echo device\n");
		return (1);
	}
	printf("[+] opened the echo device\n");

	if (write(dev, &addr, sizeof(long))==0) {
		printf("failed to write to echo device");
		return (1);
	}
	printf("[+] write &buff (%016lx) to the echo device\n", addr);

	if(read(dev, buff2, sizeof(buff2))==0) {
		printf("[-] failed to read from echo device\n");
	}
	printf("[+] this should never happen due SMAP...\n");


	return (0);
}
