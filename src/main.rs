#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

// ================= PANIC =================

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// ================= HASH =================

fn hash(name: *const u8) -> u32 {
    let mut h = 0u32;
    let mut i = 0;

    unsafe {
        loop {
            let c = *name.add(i);
            if c == 0 {
                break;
            }

            h = h.rotate_right(13);
            h = h.wrapping_add(c as u32);

            i += 1;
        }
    }

    h
}

// ================= PEB =================

#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    _pad1: [u8; 0x30],
    dll_base: *mut c_void,
}

#[repr(C)]
struct PEB_LDR_DATA {
    _pad: [u8; 0x10],
    in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct PEB {
    _pad: [u8; 0x18],
    ldr: *mut PEB_LDR_DATA,
}

unsafe fn get_peb() -> *mut PEB {
    let peb;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

// ================= KERNEL32 =================

unsafe fn get_kernel32() -> *mut c_void {
    let peb = get_peb();
    let ldr = (*peb).ldr;

    let mut list = (*ldr).in_memory_order_module_list.flink;

    list = (*list).flink; // ntdll
    list = (*list).flink; // kernel32

    let entry = list as *mut LDR_DATA_TABLE_ENTRY;
    (*entry).dll_base
}

// ================= EXPORT =================

#[repr(C)]
struct IMAGE_DOS_HEADER {
    _pad: [u8; 60],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    _sig: u32,
    _file: [u8; 20],
    optional: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    _pad: [u8; 112],
    export: IMAGE_DATA_DIRECTORY,
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    _pad: [u8; 24],
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

unsafe fn get_proc_by_hash(base: *mut c_void, target_hash: u32) -> *mut c_void {
    let base = base as usize;

    let dos = base as *const IMAGE_DOS_HEADER;
    let nt = (base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

    let export_dir =
        (base + (*nt).optional.export.virtual_address as usize)
            as *const IMAGE_EXPORT_DIRECTORY;

    let names = (base + (*export_dir).address_of_names as usize) as *const u32;
    let funcs = (base + (*export_dir).address_of_functions as usize) as *const u32;
    let ords = (base + (*export_dir).address_of_name_ordinals as usize) as *const u16;

    for i in 0..(*export_dir).number_of_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = (base + name_rva as usize) as *const u8;

        if hash(name_ptr) == target_hash {
            let ord = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ord);

            return (base + func_rva as usize) as *mut c_void;
        }
    }

    core::ptr::null_mut()
}

// ================= ENTRY =================

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    unsafe {
        let k32 = get_kernel32();

        // hashes (pré-calculados)
        let loadlib_hash = 0xec0e4e8e; // LoadLibraryA
        let getproc_hash = 0x7c0dfcaa; // GetProcAddress

        let loadlib_addr = get_proc_by_hash(k32, loadlib_hash);
        let getproc_addr = get_proc_by_hash(k32, getproc_hash);

        type LoadLibraryA_t =
            unsafe extern "system" fn(*const u8) -> *mut c_void;

        type GetProcAddress_t =
            unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void;

        let load_library: LoadLibraryA_t = core::mem::transmute(loadlib_addr);
        let get_proc: GetProcAddress_t = core::mem::transmute(getproc_addr);

        // carregar user32.dll
        let user32 = load_library(b"user32.dll\0".as_ptr());

        // pegar MessageBoxA
        let msgbox_addr =
            get_proc(user32, b"MessageBoxA\0".as_ptr());

        type MessageBoxA_t = unsafe extern "system" fn(
            *mut c_void,
            *const u8,
            *const u8,
            u32,
        ) -> i32;

        let message_box: MessageBoxA_t = core::mem::transmute(msgbox_addr);

        let text = b"Funcionou!\0";
        let title = b"Rust no_std\0";

        message_box(
            core::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            0,
        );
    }

    0
}