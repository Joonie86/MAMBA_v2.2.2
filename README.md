=====================================================================
MAMBA + PS3M_API
=====================================================================

Version of mamba who include ps3m_api_core by NzV.
	

----------------------------------------------------------------------
ORIGINAL README
----------------------------------------------------------------------

'Mamba' is the payload version of Cobra code (developed by Cobra Team) CFW for Iris Manager with some limitations.


Tested working in CFW 4.46 (Rogero v1.01) and CFW 4.53 Habib v1.01


Some differences with Cobra:



1) Mamba don´t support emulators: Iris Manager have your own method for PS1 ISOS



2) Mamba needs to reload Iris Manager self (iris_manager.self) 
because Cobra needs to get vsh process 
(reload causes vsh child process and i get it from here). 
Code is protected from vsh_process NULL condition.
[NZV 03/2015 This restriction is now removed, vsh_process is get
directly from the process list, no more need to reload a self to get it]


3) Some functions of cobralib are disabled: Iris Manager uses minimal cobralib named 'cobre'



4) Spoof functions are disabled from 4.53: iris Manager don´t support spoof method



5) Others functions for patches can be disabled



6) Multiman is blocked to avoid problems to the users (reboot the console to use it)
[NZV 03/2015 This restriction is now removed]


7) 'Mamba' is loaded AFTER of syscall8 Iris Manager payload and uses it for example, for HTAB method.
[NZV 03/2015 Mamba as now is own payload to load it)


8) 'Mamba' can be detected using the sys8_mamba() syscalls from Iris Manager: if it return 0x666 is 'Mamba' 
(and not Cobra)

To port to others CFW:

- This code is released under GPL v3. Please, release your changes!

- Surely it don´t work without some changes for CFW < 4.46 (untested)

- USE_LV1_PEEK_POKE must be disabled is you are using an the old LV1 access (CFW 3.55)

- lv2/symbols.h countain the symbols to be defined from LV2 for the payload. 'FIRMWARE_4_53' countain the basic offsets to works
and the code are adapted to it

- stage2/modulespatch.h countain patches to do in modules from the payload. 'FIRMWARE_4_53'  define this patches to 0 for disable it (as you can see).

NOTE: Surely some patches from Cobra cannot be done if you enable it: you are working after VSH.SELF is loaded.
Others patches can be done dinamically and it can work if you enable it, of course, pero some patches are done from other methods in the CFW
or from Iris Manager payload.

- I include a very old WIN32 compiler (with minimal environment) to compile the payload

- I include a zlib utility to compress the payloads (.lz.bin)

- IMPORTANT: You needs to alloc extra space to run the payload (or it hang, surely). I alloc 0x4000 bytes extra, fills to 0 
