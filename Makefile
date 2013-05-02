all:	kernel userspace
	(cd kernel; make)
	(cd userspace; make)
	cp kernel/echo.ko .
	cp userspace/tester .

clean:
	(cd kernel; make clean)
	(cd userspace; make clean)
	rm -f echo.ko
	rm -f tester
