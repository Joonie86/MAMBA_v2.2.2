clean:
	rm -f *.o *.elf stage2/*.map *.bin stage2/*.o lv2/src/*.o lv1/src/*.o debug/src/*.o 
all:
	make -f Makefile_4.80 clean --no-print-directory
	make -f Makefile_4.80 --no-print-directory
	make -f Makefile_4.80D clean --no-print-directory
	make -f Makefile_4.80D --no-print-directory
	make -f Makefile_4.80E clean --no-print-directory
	make -f Makefile_4.80E --no-print-directory
	rm -f *.o *.elf stage2/*.map stage2/*.o lv2/src/*.o lv1/src/*.o debug/src/*.o
