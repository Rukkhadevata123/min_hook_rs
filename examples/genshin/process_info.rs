//! Process Information Tool - Dynamic process base address and module information
//!
//! Usage: cargo run --example process_info -- <process_name.exe>
//! Example: cargo run --example process_info -- GenshinImpact.exe

use std::env;
use std::mem;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;

#[derive(Debug)]
struct ProcessInfo {
    pid: u32,
    name: String,
    base_address: usize,
    image_size: u32,
    entry_point: usize,
}

#[derive(Debug)]
struct ModuleInfo {
    name: String,
    base_address: usize,
    size: u32,
}

// C-style GetPID function
fn get_pid_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return None;
        }

        loop {
            let exe_name = String::from_utf16_lossy(&entry.szExeFile);
            let exe_name = exe_name.trim_end_matches('\0');

            if exe_name.eq_ignore_ascii_case(process_name) {
                CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        None
    }
}

// C-style GetModule function
fn get_module_info(pid: u32, module_name: &str) -> Option<(usize, u32)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let current_module_name = String::from_utf16_lossy(&entry.szModule);
                let current_module_name = current_module_name.trim_end_matches('\0');

                if current_module_name.eq_ignore_ascii_case(module_name) {
                    CloseHandle(snapshot);
                    return Some((entry.modBaseAddr as usize, entry.modBaseSize));
                }

                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

fn get_process_by_name(process_name: &str) -> Result<ProcessInfo, String> {
    // Process lookup using CreateToolhelp32Snapshot + Process32First/Next
    let pid = get_pid_by_name(process_name)
        .ok_or_else(|| format!("Process '{}' not found", process_name))?;

    // Request high privilege PROCESS_ALL_ACCESS
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "OpenProcess failed: {} (requires admin privileges)",
            unsafe { GetLastError() }
        ));
    }

    // Get main module base address via GetModule function
    let (base_address, image_size) = get_module_info(pid, process_name)
        .ok_or_else(|| "Failed to get module information".to_string())?;

    // Read PE header to get entry point
    let entry_point = unsafe {
        let mut dos_header: IMAGE_DOS_HEADER = mem::zeroed();
        let mut bytes_read = 0;
        if ReadProcessMemory(
            process,
            base_address as *const _,
            &mut dos_header as *mut _ as *mut _,
            size_of::<IMAGE_DOS_HEADER>(),
            &mut bytes_read,
        ) == 0
        {
            CloseHandle(process);
            return Err(format!("Failed to read DOS header: {}", GetLastError()));
        }

        let mut nt_headers: IMAGE_NT_HEADERS64 = mem::zeroed();
        if ReadProcessMemory(
            process,
            (base_address + dos_header.e_lfanew as usize) as *const _,
            &mut nt_headers as *mut _ as *mut _,
            size_of::<IMAGE_NT_HEADERS64>(),
            &mut bytes_read,
        ) == 0
        {
            CloseHandle(process);
            return Err(format!("Failed to read NT headers: {}", GetLastError()));
        }

        base_address + nt_headers.OptionalHeader.AddressOfEntryPoint as usize
    };

    unsafe {
        CloseHandle(process);
    }

    Ok(ProcessInfo {
        pid,
        name: process_name.to_string(),
        base_address,
        image_size,
        entry_point,
    })
}

fn get_process_modules(pid: u32) -> Result<Vec<ModuleInfo>, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "CreateToolhelp32Snapshot for modules failed: {} (requires admin privileges)",
                GetLastError()
            ));
        }

        let mut modules = Vec::new();
        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let module_name = String::from_utf16_lossy(&entry.szModule);
                let module_name = module_name.trim_end_matches('\0');

                modules.push(ModuleInfo {
                    name: module_name.to_string(),
                    base_address: entry.modBaseAddr as usize,
                    size: entry.modBaseSize,
                });

                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        Ok(modules)
    }
}

fn analyze_pe_sections(process: HANDLE, base_address: usize) -> Result<(), String> {
    unsafe {
        // Read DOS header
        let mut dos_header: IMAGE_DOS_HEADER = mem::zeroed();
        let mut bytes_read = 0;
        if ReadProcessMemory(
            process,
            base_address as *const _,
            &mut dos_header as *mut _ as *mut _,
            size_of::<IMAGE_DOS_HEADER>(),
            &mut bytes_read,
        ) == 0
        {
            return Err(format!("Failed to read DOS header: {}", GetLastError()));
        }

        // Read NT headers
        let mut nt_headers: IMAGE_NT_HEADERS64 = mem::zeroed();
        if ReadProcessMemory(
            process,
            (base_address + dos_header.e_lfanew as usize) as *const _,
            &mut nt_headers as *mut _ as *mut _,
            size_of::<IMAGE_NT_HEADERS64>(),
            &mut bytes_read,
        ) == 0
        {
            return Err(format!("Failed to read NT headers: {}", GetLastError()));
        }

        // Copy fields to local variables to avoid references to packed fields
        let machine = nt_headers.FileHeader.Machine;
        let num_sections = nt_headers.FileHeader.NumberOfSections;
        let image_base = nt_headers.OptionalHeader.ImageBase;
        let entry_point_rva = nt_headers.OptionalHeader.AddressOfEntryPoint;
        let size_of_image = nt_headers.OptionalHeader.SizeOfImage;

        println!("PE Information:");
        println!("  Machine: 0x{:X}", machine);
        println!("  Number of sections: {}", num_sections);
        println!("  Image base: 0x{:X}", image_base);
        println!(
            "  Entry point: 0x{:X}",
            base_address + entry_point_rva as usize
        );
        println!("  Size of image: 0x{:X}", size_of_image);

        // Read section table
        let sections_offset = dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS64>();
        let mut sections_data =
            vec![0u8; num_sections as usize * size_of::<IMAGE_SECTION_HEADER>()];

        if ReadProcessMemory(
            process,
            (base_address + sections_offset) as *const _,
            sections_data.as_mut_ptr() as *mut _,
            sections_data.len(),
            &mut bytes_read,
        ) == 0
        {
            return Err(format!(
                "Failed to read section headers: {}",
                GetLastError()
            ));
        }

        println!("\nSections:");
        for i in 0..num_sections {
            let section = &*(sections_data
                .as_ptr()
                .add(i as usize * size_of::<IMAGE_SECTION_HEADER>())
                as *const IMAGE_SECTION_HEADER);

            let name =
                std::ffi::CStr::from_ptr(section.Name.as_ptr() as *const i8).to_string_lossy();

            // Copy fields to local variables
            let virtual_address = section.VirtualAddress;
            let size_of_raw_data = section.SizeOfRawData;
            let characteristics = section.Characteristics;

            println!(
                "  {} - VA: 0x{:X}, Size: 0x{:X}, Characteristics: 0x{:X}",
                name,
                base_address + virtual_address as usize,
                size_of_raw_data,
                characteristics
            );

            // Mark important sections
            if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                println!("    ^ Executable section");
            }
            if characteristics & IMAGE_SCN_MEM_READ != 0
                && characteristics & IMAGE_SCN_MEM_WRITE != 0
            {
                println!("    ^ Read/Write section");
            }
        }

        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <process_name.exe>", args[0]);
        eprintln!("Example: {} GenshinImpact.exe", args[0]);
        eprintln!("Note: Requires administrator privileges");
        eprintln!();
        eprintln!("Implementation details:");
        eprintln!("  - Process lookup: CreateToolhelp32Snapshot + Process32First/Next");
        eprintln!("  - Privilege handling: Direct use of high privilege PROCESS_ALL_ACCESS");
        eprintln!("  - Base address retrieval: GetModule function for main module base");
        return;
    }

    let process_name = &args[1];

    match get_process_by_name(process_name) {
        Ok(process_info) => {
            println!("Process Information (C-style implementation):");
            println!("  Name: {}", process_info.name);
            println!("  PID: {}", process_info.pid);
            println!("  Base Address: 0x{:X}", process_info.base_address);
            println!(
                "  Image Size: 0x{:X} ({} bytes)",
                process_info.image_size, process_info.image_size
            );
            println!("  Entry Point: 0x{:X}", process_info.entry_point);
            println!();

            // Get module list
            match get_process_modules(process_info.pid) {
                Ok(modules) => {
                    println!("Loaded Modules ({} total):", modules.len());
                    for (i, module) in modules.iter().enumerate() {
                        if i < 10 {
                            // Show only first 10 modules
                            println!(
                                "  {} - Base: 0x{:X}, Size: 0x{:X}",
                                module.name, module.base_address, module.size
                            );
                        }
                    }
                    if modules.len() > 10 {
                        println!("  ... and {} more modules", modules.len() - 10);
                    }
                    println!();
                }
                Err(e) => {
                    eprintln!("Failed to get modules: {}", e);
                }
            }

            // Analyze PE structure
            unsafe {
                let process = OpenProcess(PROCESS_ALL_ACCESS, 0, process_info.pid);

                if !process.is_null() {
                    if let Err(e) = analyze_pe_sections(process, process_info.base_address) {
                        eprintln!("Failed to analyze PE sections: {}", e);
                    }
                    CloseHandle(process);
                } else {
                    eprintln!(
                        "Failed to open process for PE analysis: {} (requires admin privileges)",
                        GetLastError()
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Tip: Please run this program as administrator");
        }
    }
}
