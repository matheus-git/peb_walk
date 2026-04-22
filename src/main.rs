#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use core::arch::asm;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[repr(C)]
struct LIST_ENTRY {
    flink: *const LIST_ENTRY,
    blink: *const LIST_ENTRY,
}

#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    _pad1: [u8; 0x30],
    dll_base: *mut c_void,
    _pad2: [u8; 0x20],
    base_dll_name: UNICODE_STRING,
}

#[repr(C)]
struct PEB_LDR_DATA {
    _pad: [u8; 0x20],
    in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct PEB {
    _pad: [u8; 0x18],
    ldr: *const PEB_LDR_DATA,
}

fn get_peb() -> *const PEB {
    unsafe{ 
        let peb;
        asm!("mov {}, gs:[0x60]", out(reg) peb);
        peb
    }
}

const IN_MEMORY_ORDER_LINKS_OFFSET: usize = 0x10;

fn get_base_module(dll_name: &[u8]) -> Option<*const c_void> {
    unsafe {
        let peb = get_peb();
        let ldr = (*peb).ldr;

        if ldr.is_null() {
            return None;
        }

        let head = &(*ldr).in_memory_order_module_list as *const LIST_ENTRY;
        let mut current = (*head).flink;

        while current != head {
            let entry = (current as usize - IN_MEMORY_ORDER_LINKS_OFFSET) as *const LDR_DATA_TABLE_ENTRY;

            let base_name = &(*entry).base_dll_name;

            if cmp_utf16_ascii_case_insensitive(
                base_name.buffer,
                (base_name.length / 2) as usize,
                dll_name,
            ) {
                return Some((*entry).dll_base);
            }

            current = (*current).flink;
        }

        None
    }
}

fn cmp_utf16_ascii_case_insensitive(
    buf: *const u16,
    len: usize,
    ascii: &[u8],
) -> bool {
    if len != ascii.len() {
        return false;
    }

    let mut i = 0;

    while i < len {
        let c1 = unsafe { *buf.add(i) as u8 };
        let c2 = ascii[i];

        let c1 = if c1 >= b'a' && c1 <= b'z' {
            c1 - 32
        } else {
            c1
        };

        let c2 = if c2 >= b'a' && c2 <= b'z' {
            c2 - 32
        } else {
            c2
        };

        if c1 != c2 {
            return false;
        }

        i += 1;
    }

    true
}

#[repr(C)]
struct IMAGE_DOS_HEADER {
    _pad: [u8; 0x3c],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    _pad: [u8; 0x18],
    optional: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    _pad: [u8; 0x70],
    export: IMAGE_DATA_DIRECTORY,
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    _pad: [u8; 0x18],
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

fn get_proc_by_hash(base: *const c_void, target: &[u8]) -> *const c_void {
    unsafe{
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

            if strcmp(name_ptr, target.as_ptr()) {
                let ord = *ords.add(i as usize) as usize;
                let func_rva = *funcs.add(ord);

                return (base + func_rva as usize) as *const c_void;
            }
        }

        core::ptr::null_mut()
    }
}

fn strcmp(a: *const u8, b: *const u8) -> bool {
    unsafe{
        let mut i = 0;

        loop {
            let c1 = *a.add(i);
            let c2 = *b.add(i);

            if c1 != c2 {
                return false;
            }

            if c1 == 0 {
                return true;
            }

            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    unsafe {
        let k32 = match get_base_module(b"KERNEL32.DLL") {
            Some(addr) => addr,
            None => return 1
        };

        let loadlib_addr = get_proc_by_hash(k32, b"LoadLibraryA\0");
        let getproc_addr = get_proc_by_hash(k32, b"GetProcAddress\0");

        type LoadLibraryAT =
            unsafe extern "system" fn(*const u8) -> *mut c_void;

        type GetProcAddressT =
            unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void;

        let load_library: LoadLibraryAT = core::mem::transmute(loadlib_addr);
        let get_proc: GetProcAddressT = core::mem::transmute(getproc_addr);

        let user32 = load_library(b"user32.dll\0".as_ptr());

        let msgbox_addr =
            get_proc(user32, b"MessageBoxA\0".as_ptr());

        type MessageBoxAT = unsafe extern "system" fn(
            *mut c_void,
            *const u8,
            *const u8,
            u32,
        ) -> i32;

        let message_box: MessageBoxAT = core::mem::transmute(msgbox_addr);

        let text = b"text!\0";
        let title = b"title\0";

        message_box(
            core::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            0,
        );
    }

    0
}