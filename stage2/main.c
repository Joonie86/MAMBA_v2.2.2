/*
 'Mamba' is the payload version of Cobra code CFW (developed by Cobra Team) for Iris Manager
 LICENSED under GPL v3.0

*/

#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/memory.h>
#include <lv2/patch.h>
#include <lv2/syscall.h>
#include <lv2/usb.h>
#include <lv2/storage.h>
#include <lv2/thread.h>
#include <lv2/synchronization.h>
#include <lv2/modules.h>
#include <lv2/io.h>
#include <lv2/time.h>
#include <lv2/security.h>
#include <lv2/error.h>
#include <lv2/symbols.h>
#include <lv1/stor.h>
#include <lv1/patch.h>

#include "modulespatch.h"
#include "storage_ext.h"
#include "config.h"
#include "syscall8.h"
#include "region.h"

// Format of version:
// byte 0, 7 MS bits -> reserved
// byte 0, 1 LS bit -> 1 = CFW version, 0 = OFW/exploit version
// byte 1 and 2 -> ps3 fw version in BCD e.g 3.55 = 03 55. For legacy reasons, 00 00 means 3.41
// byte 3 is cobra firmware version,
// 1 = version 1.0-1.2,
// 2 = 2.0,
// 3 = 3.0
// 4 = 3.1
// 5 = 3.2
// 6 = 3.3
// 7 = 4.0
// 8 = 4.1
// 9 = 4.2
// A = 4.3
// B = 4.4
// C = 5.0
// D = 5.1
// E = 6.0
// F = 7.0

#define COBRA_VERSION		0x0F
#define COBRA_VERSION_BCD	0x0700

#if defined(FIRMWARE_3_41)
#define FIRMWARE_VERSION	0x0341
#elif defined(FIRMWARE_3_55)
#define FIRMWARE_VERSION	0x0355
#elif defined(FIRMWARE_3_55DEX)
#define FIRMWARE_VERSION	0x0355
#elif defined(FIRMWARE_4_21)
#define FIRMWARE_VERSION	0x0421
#elif defined(FIRMWARE_4_21DEX)
#define FIRMWARE_VERSION	0x0421
#elif defined(FIRMWARE_4_30)
#define FIRMWARE_VERSION	0x0430
#elif defined(FIRMWARE_4_31)
#define FIRMWARE_VERSION	0x0431
#elif defined(FIRMWARE_4_30DEX)
#define FIRMWARE_VERSION	0x0430
#elif defined(FIRMWARE_4_40)
#define FIRMWARE_VERSION	0x0440
#elif defined(FIRMWARE_4_41)
#define FIRMWARE_VERSION	0x0441
#elif defined(FIRMWARE_4_41DEX)
#define FIRMWARE_VERSION	0x0441
#elif defined(FIRMWARE_4_46)
#define FIRMWARE_VERSION	0x0446
#elif defined(FIRMWARE_4_46DEX)
#define FIRMWARE_VERSION	0x0446
#elif defined(FIRMWARE_4_50)
#define FIRMWARE_VERSION	0x0450
#elif defined(FIRMWARE_4_50DEX)
#define FIRMWARE_VERSION	0x0450
#elif defined(FIRMWARE_4_53)
#define FIRMWARE_VERSION	0x0453
#elif defined(FIRMWARE_4_53DEX)
#define FIRMWARE_VERSION	0x0453
#elif defined(FIRMWARE_4_55)
#define FIRMWARE_VERSION	0x0455
#elif defined(FIRMWARE_4_55DEX)
#define FIRMWARE_VERSION	0x0455
#elif defined(FIRMWARE_4_60)
#define FIRMWARE_VERSION	0x0460
#elif defined(FIRMWARE_4_65)
#define FIRMWARE_VERSION	0x0465
#endif

#define IS_CFW			1

process_t vsh_process = NULL;
uint8_t safe_mode = 0;

LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_8(int, load_process_hooked, (process_t process, int fd, char *path, int r6, uint64_t r7, uint64_t r8, uint64_t r9, uint64_t r10, uint64_t sp_70))
{

	////DPRINTF("PROCESS %s (%08X) loaded\n", path, process->pid);

	if (!vsh_process)
	{
        if(is_vsh_process(process->parent)) {
            vsh_process = process->parent;

           storage_ext_patches();
        }
        else

		if (strcmp(path, "/dev_flash/vsh/module/vsh.self") == 0)
		{
			vsh_process = process;
            storage_ext_patches();

		}
		else if (strcmp(path, "emer_init.self") == 0)
		{
			////DPRINTF("COBRA: Safe mode detected\n");
			safe_mode = 1;
		}
	}

	else if (strncmp(path, "/dev_hdd0/game/BLES80608", 24) == 0)
	{
		// Block multiman to avoid it use 'Mamba' as 'Cobra' causing problems...

        return 0x80010009;

	}
	/*
    else
	{
		block_peek = 0;
	}
    */

	return 0;
}
void _sys_cfw_poke(uint64_t *addr, uint64_t value);

LV2_HOOKED_FUNCTION(void, sys_cfw_new_poke, (uint64_t *addr, uint64_t value))
{
	//DPRINTF("New poke called\n");
	_sys_cfw_poke(addr, value);
	asm volatile("icbi 0,%0; isync" :: "r"(addr));
}

LV2_HOOKED_FUNCTION(void *, sys_cfw_memcpy, (void *dst, void *src, uint64_t len))
{
	//DPRINTF("sys_cfw_memcpy: %p %p 0x%lx\n", dst, src, len);

	if (len == 8)
	{
		_sys_cfw_poke(dst, *(uint64_t *)src);
		return dst;
	}

	return memcpy(dst, src, len);
}


#define MAKE_VERSION(cobra, fw, type) ((cobra&0xFF) | ((fw&0xffff)<<8) | ((type&0x1)<<24))

static INLINE int sys_get_version(uint32_t *version)
{
	uint32_t pv = MAKE_VERSION(COBRA_VERSION, FIRMWARE_VERSION, IS_CFW);
	return copy_to_user(&pv, get_secure_user_ptr(version), sizeof(uint32_t));
}

static INLINE int sys_get_version2(uint16_t *version)
{
	uint16_t cb = COBRA_VERSION_BCD;
	return copy_to_user(&cb, get_secure_user_ptr(version), sizeof(uint16_t));
}


int64_t syscall8(uint64_t function, uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4, uint64_t param5, uint64_t param6, uint64_t param7);
f_desc_t extended_syscall8;

static void *current_813;
LV2_SYSCALL2(void, sys_cfw_poke, (uint64_t *ptr, uint64_t value))
{
    uint64_t addr = (uint64_t)ptr;

    if (addr >= MKA(syscall_table_symbol))
	{
        uint64_t syscall_num = (addr-MKA(syscall_table_symbol)) / 8;

        if (syscall_num == 8 && (value & 0xFFFFFFFF00000000ULL) == MKA(0))
			{
				// Probably iris manager or similar
				// Lets extend our syscall 8 so that it can call this other syscall 8
				// First check if it is trying to restore our syscall8
				if (*(uint64_t *)syscall8 == value)
				{
					//DPRINTF("Removing syscall 8 extension\n");
					//extended_syscall8.addr = 0;
					return;
				}

				extended_syscall8.addr = (void *) *(uint64_t *)value;
				extended_syscall8.toc = (void *) *(uint64_t *)(MKA(0x3000));
				//DPRINTFF("Adding syscall 8 extension %p %p\n", extended_syscall8.addr, extended_syscall8.toc);
				return;
			}

			//DPRINTFF("HB has been blocked from rewritting syscall %ld\n", syscall_num);
			//return;

    }else
	{
		uint64_t sc813 = get_syscall_address(813);

		if (addr == sc813)
		{
			if (value == 0xF88300007C001FACULL)
			{
				f_desc_t f;

				// Assume app is trying to write the so called "new poke"
				//DPRINTF("Making sys_cfw_new_poke\n");
				if (current_813)
				{
					unhook_function(sc813, current_813);
				}

				hook_function(sc813, sys_cfw_new_poke, &f);
				current_813 = sys_cfw_new_poke;
				return;
			}
			else if (value == 0x4800000428250000ULL)
			{
				f_desc_t f;

				// Assume app is trying to write a memcpy
				//DPRINTF("Making sys_cfw_memcpy\n");
				if (current_813)
				{
					unhook_function(sc813, current_813);
				}

				hook_function(sc813, sys_cfw_memcpy, &f);
				current_813 = sys_cfw_memcpy;
				return;
			}
			else if (value == 0xF821FF017C0802A6ULL)
			{
				// Assume app is trying to restore sc 813
				if (current_813)
				{
					//DPRINTF("Restoring syscall 813\n");
					unhook_function(sc813, current_813);
					current_813 = NULL;
					return;
				}
			}
			else
			{
				//DPRINTF("Warning: syscall 813 being overwritten with unknown value (%016lx). *blocking it*\n", value);
				return;
			}
		}
		else if (addr > sc813 && addr < (sc813+0x20))
		{
			return;
		}
    }

    *ptr = value;
    return;
}


LV2_SYSCALL2(int64_t, syscall8, (uint64_t function, uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4, uint64_t param5, uint64_t param6, uint64_t param7))
{
	static uint32_t pid_blocked = 0;
	uint32_t pid;

	extend_kstack(0);

	//DPRINTF("Syscall 8 -> %lx\n", function);

	// Some processsing to avoid crashes with lv1 dumpers
	pid = get_current_process_critical()->pid;

	if (pid == pid_blocked)
	{
		if (function >= 0xA000 || (function & 3)) /* Keep all cobra opcodes below 0xA000 */
		{
			//DPRINTF("App was unblocked from using syscall8\n");
			pid_blocked = 0;
		}
		else
		{
			//DPRINTF("App was blocked from using syscall8\n");
			return ENOSYS;
		}
	}

	if (function == (SYSCALL8_OPCODE_GET_VERSION-8))
	{
		// 0x6FF8. On 0x7000 it *could* crash
		pid_blocked = pid;
		return ENOSYS;
	}
	else if (function == (SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART-8))
	{
		// 0x3000, On 0x3008 it *could* crash
		pid_blocked = pid;
		return ENOSYS;
	}

	switch (function)
	{
        case SYSCALL8_OPCODE_GET_MAMBA:
            return 0x666;
		break;

		case SYSCALL8_OPCODE_GET_VERSION:
			return sys_get_version((uint32_t *)param1);
		break;

		case SYSCALL8_OPCODE_GET_VERSION2:
			return sys_get_version2((uint16_t *)param1);
		break;
		#if 1
		case SYSCALL8_OPCODE_GET_DISC_TYPE:
			return sys_storage_ext_get_disc_type((unsigned int *)param1, (unsigned int *)param2, (unsigned int *)param3);
		break;

		case SYSCALL8_OPCODE_READ_PS3_DISC:
			return sys_storage_ext_read_ps3_disc((void *)param1, param2, (uint32_t)param3);
		break;

		case SYSCALL8_OPCODE_FAKE_STORAGE_EVENT:
			return sys_storage_ext_fake_storage_event(param1, param2, param3);
		break;

		case SYSCALL8_OPCODE_GET_EMU_STATE:
			return sys_storage_ext_get_emu_state((sys_emu_state_t *)param1);
		break;

		case SYSCALL8_OPCODE_MOUNT_PS3_DISCFILE:
			return sys_storage_ext_mount_ps3_discfile(param1, (char **)param2);
		break;

		case SYSCALL8_OPCODE_MOUNT_DVD_DISCFILE:
			return sys_storage_ext_mount_dvd_discfile(param1, (char **)param2);
		break;

		case SYSCALL8_OPCODE_MOUNT_BD_DISCFILE:
			return sys_storage_ext_mount_bd_discfile(param1, (char **)param2);
		break;

		case SYSCALL8_OPCODE_MOUNT_PSX_DISCFILE:
			return sys_storage_ext_mount_psx_discfile((char *)param1, param2, (ScsiTrackDescriptor *)param3);
		break;

		case SYSCALL8_OPCODE_MOUNT_PS2_DISCFILE:
			return sys_storage_ext_mount_ps2_discfile(param1, (char **)param2, param3, (ScsiTrackDescriptor *)param4);
		break;

		case SYSCALL8_OPCODE_MOUNT_DISCFILE_PROXY:
			return sys_storage_ext_mount_discfile_proxy(param1, param2, param3, param4, param5, param6, (ScsiTrackDescriptor *)param7);
		break;

		case SYSCALL8_OPCODE_UMOUNT_DISCFILE:
			return sys_storage_ext_umount_discfile();
		break;

		case SYSCALL8_OPCODE_MOUNT_ENCRYPTED_IMAGE:
			return sys_storage_ext_mount_encrypted_image((char *)param1, (char *)param2, (char *)param3, param4);

		case SYSCALL8_OPCODE_READ_COBRA_CONFIG:
			return sys_read_cobra_config((CobraConfig *)param1);
		break;

		case SYSCALL8_OPCODE_WRITE_COBRA_CONFIG:
			return sys_write_cobra_config((CobraConfig *)param1);
		break;

	    case SYSCALL8_OPCODE_GET_ACCESS:
        case SYSCALL8_OPCODE_REMOVE_ACCESS:
		case SYSCALL8_OPCODE_COBRA_USB_COMMAND:
		case SYSCALL8_OPCODE_SET_PSP_UMDFILE:
		case SYSCALL8_OPCODE_SET_PSP_DECRYPT_OPTIONS:
		case SYSCALL8_OPCODE_READ_PSP_HEADER:
		case SYSCALL8_OPCODE_READ_PSP_UMD:
		case SYSCALL8_OPCODE_PSP_PRX_PATCH:
		case SYSCALL8_OPCODE_PSP_CHANGE_EMU:
		case SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART:
		case SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART:
		case SYSCALL8_OPCODE_AIO_COPY_ROOT:
		case SYSCALL8_OPCODE_MAP_PATHS:
        case SYSCALL8_OPCODE_DRM_GET_DATA:
        case SYSCALL8_OPCODE_SEND_POWEROFF_EVENT:
			return ENOSYS;

		case SYSCALL8_OPCODE_VSH_SPOOF_VERSION:
			return sys_vsh_spoof_version((char *)param1);
		break;


		case SYSCALL8_OPCODE_LOAD_VSH_PLUGIN:
			return sys_prx_load_vsh_plugin(param1, (char *)param2, (void *)param3, param4);
		break;

		case SYSCALL8_OPCODE_UNLOAD_VSH_PLUGIN:
			return sys_prx_unload_vsh_plugin(param1);
		break;

       #endif
        default:
			if (extended_syscall8.addr)
			{
				// Lets handle a few hermes opcodes ourself, and let their payload handle the rest
				if (function == 2)
				{
					return (uint64_t)_sys_cfw_memcpy((void *)param1, (void *)param2, param3);
				}
				else if (function == 0xC)
				{
					//DPRINTF("Hermes copy inst: %lx %lx %lx\n", param1, param2, param3);
				}
				else if (function == 0xD)
				{
					//DPRINTF("Hermes poke inst: %lx %lx\n", param1, param2);
					_sys_cfw_new_poke((void *)param1, param2);
					return param1;
				}

				int64_t (* syscall8_hb)() = (void *)&extended_syscall8;

				//DPRINTF("Handling control to HB syscall 8 (opcode=0x%lx)\n", function);
				return syscall8_hb(function, param1, param2, param3, param4, param5, param6, param7);
			}
			else if (function >= 0xA000)
			{
				// Partial support for lv1_peek here
				return lv1_peekd(function);
			}


	}

	//DPRINTF("Unsupported syscall8 opcode: 0x%lx\n", function);

	return ENOSYS;
}


#if 0
typedef struct
{
	uint32_t address;
	uint32_t data;
} Patch;

#define N_KERNEL_PATCHES	(sizeof(kernel_patches) / sizeof(Patch))
static Patch kernel_patches[] =
{
	{ patch_data1_offset, 0x01000000 },
	{ patch_func8 + patch_func8_offset1, LI(R3, 0) }, // force lv2open return 0
	// disable calls in lv2open to lv1_send_event_locally which makes the system crash
	{ patch_func8 + patch_func8_offset2, NOP },
	{ patch_func9 + patch_func9_offset, NOP }, // 4.30 - watch: additional call after
	// psjailbreak, PL3, etc destroy this function to copy their code there.
	// We don't need that, but let's dummy the function just in case that patch is really necessary
	{ mem_base2, LI(R3, 1) },
	{ mem_base2 + 4, BLR },
	// sys_sm_shutdown, for ps2 let's pass to copy_from_user a fourth parameter
	//{ shutdown_patch_offset, MR(R6, R31) },
	//{ module_sdk_version_patch_offset, NOP },
	// User thread prio hack (needed for netiso)
	{ user_thread_prio_patch, NOP },
	{ user_thread_prio_patch2, NOP },
};
#endif

LV2_SYSCALL2(void, sys_cfw_lv1_poke, (uint64_t lv1_addr, uint64_t lv1_value))
{
	lv1_poked(lv1_addr, lv1_value);
}

LV2_SYSCALL2(int, sys_cfw_40, (uint64_t r3, uint64_t r4))
{
	return ENOSYS;
}

LV2_SYSCALL2(void, sys_cfw_lv1_call, (uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t num))
{
	/* DO NOT modify */
	asm("mflr 0\n");
	asm("std 0, 16(1)\n");
	asm("mr 11, 10\n");
	asm("sc 1\n");
	asm("ld 0, 16(1)\n");
	asm("mtlr 0\n");
	asm("blr\n");
}


#if 0
static INLINE void apply_kernel_patches(void)
{
/*	for (int i = 0; i < N_KERNEL_PATCHES; i++)
	{
		uint32_t *addr= (uint32_t *)MKA(kernel_patches[i].address);
		*addr = kernel_patches[i].data;
		clear_icache(addr, 4);
	}
    */
	//create_syscall2(9, sys_cfw_lv1_poke);
	//create_syscall2(10, sys_cfw_lv1_call);

}
#endif

static int one_time = 1;

int main(void)
{
    if(!one_time) return 0;

    one_time = 1;

    storage_ext_init();

    modules_patch_init();
    hook_function_on_precall_success(load_process_symbol, load_process_hooked, 9);
    //apply_kernel_patches();
    region_patches();


    extended_syscall8.addr = 0;

    uint64_t sys8_id = *((uint64_t *)MKA(0x4f0));
    if((sys8_id>>32) == 0x534B3145) {
        sys8_id&= 0xffffffffULL;


        extended_syscall8.addr = (void *) *((uint64_t *)MKA(0x8000000000000000ULL + (sys8_id + 0x20ULL)));
	    extended_syscall8.toc = (void *) *(uint64_t *)(MKA(0x3000));

    }


    create_syscall2(8, syscall8);
    create_syscall2(7, sys_cfw_poke);
    create_syscall2(40, sys_cfw_40);


    return 0;
}
