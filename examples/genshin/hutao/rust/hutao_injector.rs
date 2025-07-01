use std::ffi::CString;
use std::io::{self, Write};
use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::ProcessStatus::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// Shared memory structure matching the DLL
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FunctionOffsets {
    find_string: u32,
    set_field_of_view: u32,
    set_enable_fog_rendering: u32,
    set_target_frame_rate: u32,
    open_team: u32,
    open_team_page_accordingly: u32,
    check_can_enter: u32,
    setup_quest_banner: u32,
    find_game_object: u32,
    set_active: u32,
    event_camera_move: u32,
    show_one_damage_text_ex: u32,
    switch_input_device_to_touch_screen: u32,
    craft_entry: u32,
    craft_entry_partner: u32,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum IslandState {
    None = 0,
    Error = 1,
    Started = 2,
    Stopped = 3,
}

#[repr(C)]
#[derive(Debug)]
struct IslandEnvironment {
    state: IslandState,
    last_error: u32,
    function_offsets: FunctionOffsets,
    field_of_view: f32,
    fix_low_fov_scene: i32, // BOOL
    disable_fog: i32,       // BOOL
    target_frame_rate: i32,
    remove_open_team_progress: i32, // BOOL
    hide_quest_banner: i32,         // BOOL
    disable_event_camera_move: i32, // BOOL
    disable_show_damage_text: i32,  // BOOL
    using_touch_screen: i32,        // BOOL
    redirect_craft_entry: i32,      // BOOL
}

// Configuration structure for initial settings
#[derive(Debug, Clone)]
struct GameConfig {
    fov: f32,
    fps: i32,
    disable_fog: bool,
    fix_low_fov: bool,
    hide_banner: bool,
    remove_team_anim: bool,
    disable_event_camera: bool,
    hide_damage: bool,
    touch_screen: bool,
    redirect_craft: bool,
}

impl Default for GameConfig {
    fn default() -> Self {
        Self {
            fov: 45.0,
            fps: 60,
            disable_fog: false,
            fix_low_fov: true,
            hide_banner: false,
            remove_team_anim: false,
            disable_event_camera: false,
            hide_damage: false,
            touch_screen: false,
            redirect_craft: false,
        }
    }
}

struct HutaoInjector {
    shared_memory_name: &'static str,
    chinese_offsets: FunctionOffsets,
    h_memory_mapped_file: HANDLE,
    p_shared_memory: MEMORY_MAPPED_VIEW_ADDRESS,
    h_process: HANDLE,
    process_id: u32,
}

impl HutaoInjector {
    const SHARED_MEMORY_NAME: &'static str = "4F3E8543-40F7-4808-82DC-21E48A6037A7";

    // Chinese version offsets
    const CHINESE_OFFSETS: FunctionOffsets = FunctionOffsets {
        find_string: 4830752,
        set_field_of_view: 17204528,
        set_enable_fog_rendering: 277807600,
        set_target_frame_rate: 277729120,
        open_team: 118414576,
        open_team_page_accordingly: 118384496,
        check_can_enter: 156982512,
        setup_quest_banner: 124927536,
        find_game_object: 277741040,
        set_active: 277740368,
        event_camera_move: 186643424,
        show_one_damage_text_ex: 204578400,
        switch_input_device_to_touch_screen: 144617776,
        craft_entry: 127845632,
        craft_entry_partner: 201143472,
    };

    fn new() -> Self {
        Self {
            shared_memory_name: Self::SHARED_MEMORY_NAME,
            chinese_offsets: Self::CHINESE_OFFSETS,
            h_memory_mapped_file: INVALID_HANDLE_VALUE,
            p_shared_memory: MEMORY_MAPPED_VIEW_ADDRESS {
                Value: ptr::null_mut(),
            },
            h_process: INVALID_HANDLE_VALUE,
            process_id: 0,
        }
    }

    fn initialize(&mut self) -> Result<(), String> {
        self.create_persistent_shared_memory()
    }

    fn launch_and_inject(
        &mut self,
        game_path: &str,
        dll_path: &str,
        config: &GameConfig,
    ) -> Result<(), String> {
        // Configure initial environment
        self.configure_initial_environment(config)?;

        // Launch game
        self.launch_game(game_path)?;

        // Inject DLL
        self.inject_dll_with_hook(dll_path)?;

        Ok(())
    }

    fn run_config_loop(&mut self) {
        println!("\n=== Hutao Injector & Configuration Tool ===");
        println!("Type 'help' for commands, 'status' for current config, or 'quit' to exit.");
        println!("Game launched with PID: {}", self.process_id);
        println!("\n[NOTE] Remember to use 'quit' command to restore defaults before closing!");

        loop {
            print!("hutao> ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            match io::stdin().read_line(&mut input) {
                Ok(_) => {
                    let input = input.trim();
                    if input.is_empty() {
                        continue;
                    }

                    if input == "quit" || input == "exit" {
                        println!("Restoring defaults and preparing to exit...");
                        self.process_command("reset");
                        break;
                    }

                    self.process_command(input);
                }
                Err(_) => break,
            }
        }

        println!("\nExiting configuration loop...");
    }

    fn create_persistent_shared_memory(&mut self) -> Result<(), String> {
        unsafe {
            let mut sa = SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: ptr::null_mut(),
                bInheritHandle: TRUE,
            };

            let name = CString::new(self.shared_memory_name).unwrap();
            self.h_memory_mapped_file = CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                &mut sa,
                PAGE_READWRITE,
                0,
                mem::size_of::<IslandEnvironment>() as u32,
                name.as_ptr() as *const u8,
            );

            if self.h_memory_mapped_file.is_null() {
                return Err(format!(
                    "Failed to create memory mapped file: {}",
                    GetLastError()
                ));
            }

            self.p_shared_memory = MapViewOfFile(
                self.h_memory_mapped_file,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                mem::size_of::<IslandEnvironment>(),
            );

            if self.p_shared_memory.Value.is_null() {
                return Err(format!("Failed to map view of file: {}", GetLastError()));
            }

            println!("[OK] Persistent shared memory created");
            Ok(())
        }
    }

    fn configure_initial_environment(&self, config: &GameConfig) -> Result<(), String> {
        if self.p_shared_memory.Value.is_null() {
            return Err("Shared memory not initialized".to_string());
        }

        unsafe {
            let p_env = self.p_shared_memory.Value as *mut IslandEnvironment;
            ptr::write_bytes(p_env, 0, 1); // ZeroMemory equivalent

            (*p_env).function_offsets = self.chinese_offsets;
            (*p_env).field_of_view = config.fov;
            (*p_env).fix_low_fov_scene = if config.fix_low_fov { 1 } else { 0 };
            (*p_env).disable_fog = if config.disable_fog { 1 } else { 0 };
            (*p_env).target_frame_rate = config.fps;
            (*p_env).remove_open_team_progress = if config.remove_team_anim { 1 } else { 0 };
            (*p_env).hide_quest_banner = if config.hide_banner { 1 } else { 0 };
            (*p_env).disable_event_camera_move = if config.disable_event_camera { 1 } else { 0 };
            (*p_env).disable_show_damage_text = if config.hide_damage { 1 } else { 0 };
            (*p_env).using_touch_screen = if config.touch_screen { 1 } else { 0 };
            (*p_env).redirect_craft_entry = if config.redirect_craft { 1 } else { 0 };
            (*p_env).state = IslandState::Started;
        }

        println!("\n[OK] Initial configuration applied:");
        println!("  - FPS: {} (always enabled)", config.fps);
        println!("  - FOV: {} (always enabled)", config.fov);
        println!(
            "  - Fix low FOV scenes: {}",
            if config.fix_low_fov {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!("  - Other settings configured");

        Ok(())
    }

    fn launch_game(&mut self, game_path: &str) -> Result<(), String> {
        let game_dir = if let Some(pos) = game_path.rfind('\\') {
            &game_path[..pos]
        } else if let Some(pos) = game_path.rfind('/') {
            &game_path[..pos]
        } else {
            "."
        };

        println!("Launching game: {}", game_path);
        println!("Working directory: {}", game_dir);

        unsafe {
            let mut si = STARTUPINFOA {
                cb: mem::size_of::<STARTUPINFOA>() as u32,
                ..mem::zeroed()
            };
            let mut pi = mem::zeroed::<PROCESS_INFORMATION>();

            let game_path_c = CString::new(game_path).unwrap();
            let game_dir_c = CString::new(game_dir).unwrap();

            let success = CreateProcessA(
                game_path_c.as_ptr() as *const u8,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                FALSE,
                0,
                ptr::null_mut(),
                game_dir_c.as_ptr() as *const u8,
                &mut si,
                &mut pi,
            );

            if success == 0 {
                return Err(format!("Failed to launch game. Error: {}", GetLastError()));
            }

            CloseHandle(pi.hThread);
            self.h_process = pi.hProcess;
            self.process_id = pi.dwProcessId;

            println!("Game launched successfully (PID: {})", self.process_id);
            SetPriorityClass(self.h_process, HIGH_PRIORITY_CLASS);

            println!("Waiting for game initialization...");
            thread::sleep(Duration::from_secs(10));

            self.wait_for_main_module("YuanShen.exe")
        }
    }

    fn inject_dll_with_hook(&self, dll_path: &str) -> Result<(), String> {
        if self.process_id == 0 {
            return Err("No target process identified".to_string());
        }

        println!("Injecting DLL via SetWindowsHookEx: {}", dll_path);

        unsafe {
            let dll_path_c = CString::new(dll_path).unwrap();
            let h_dll = LoadLibraryA(dll_path_c.as_ptr() as *const u8);
            if h_dll.is_null() {
                return Err(format!("Failed to load DLL locally: {}", GetLastError()));
            }

            // Try to get hook function from DLL
            let mut hook_proc: HOOKPROC = None;

            let proc_name1 = CString::new("DllGetWindowsHookForHutao").unwrap();
            let p_get_hook = GetProcAddress(h_dll, proc_name1.as_ptr() as *const u8);

            let p_get_hook = if p_get_hook.is_some() {
                p_get_hook
            } else {
                let proc_name2 = CString::new("IslandGetWindowHook").unwrap();
                GetProcAddress(h_dll, proc_name2.as_ptr() as *const u8)
            };

            if let Some(get_hook_fn) = p_get_hook {
                // Call the function to get hook procedure
                type GetHookFn = unsafe extern "system" fn(*mut HOOKPROC) -> i32;
                let get_hook: GetHookFn = mem::transmute(get_hook_fn);

                let result = get_hook(&mut hook_proc as *mut HOOKPROC);
                if result != 0 || hook_proc.is_none() {
                    FreeLibrary(h_dll);
                    return Err("Failed to get hook function from DLL".to_string());
                }

                println!("Hook function retrieved from DLL");
            } else {
                FreeLibrary(h_dll);
                return Err("Failed to get hook function from DLL".to_string());
            }

            let thread_id = self.get_main_thread_id(self.process_id);
            if thread_id == 0 {
                FreeLibrary(h_dll);
                return Err("Failed to get main thread ID".to_string());
            }

            let h_hook = SetWindowsHookExA(WH_GETMESSAGE, hook_proc, h_dll, thread_id);
            if h_hook.is_null() {
                let error = GetLastError();
                FreeLibrary(h_dll);
                return Err(format!("SetWindowsHookEx failed: {}", error));
            }

            PostThreadMessageA(thread_id, WM_NULL, 0, 0);
            thread::sleep(Duration::from_millis(500));

            println!("[OK] DLL injected successfully");

            UnhookWindowsHookEx(h_hook);
            FreeLibrary(h_dll);

            Ok(())
        }
    }

    fn process_command(&self, command: &str) {
        if self.p_shared_memory.Value.is_null() {
            return;
        }

        unsafe {
            let p_env = self.p_shared_memory.Value as *mut IslandEnvironment;
            let parts: Vec<&str> = command.split_whitespace().collect();

            if parts.is_empty() {
                return;
            }

            match parts[0] {
                "fps" => {
                    if parts.len() > 1 {
                        if let Ok(value) = parts[1].parse::<i32>() {
                            if value < 30 {
                                println!(
                                    "Error: FPS must be at least 30. Current value: {}",
                                    value
                                );
                                return;
                            }
                            (*p_env).target_frame_rate = value;
                            println!("FPS set to: {} (enabled)", value);
                        } else {
                            println!("Invalid FPS value");
                        }
                    } else {
                        println!(
                            "Usage: fps <value> - Set target frame rate (minimum 30, e.g., fps 120)"
                        );
                    }
                }
                "fov" => {
                    if parts.len() > 1 {
                        if let Ok(value) = parts[1].parse::<f32>() {
                            if value < 1.0 {
                                println!(
                                    "Error: FOV must be at least 1.0. Current value: {}",
                                    value
                                );
                                return;
                            }
                            (*p_env).field_of_view = value;
                            println!("FOV set to: {} (enabled)", value);
                        } else {
                            println!("Invalid FOV value");
                        }
                    } else {
                        println!(
                            "Usage: fov <value> - Set field of view (minimum 1.0, e.g., fov 60.0)"
                        );
                    }
                }
                "fixfov" => {
                    if parts.len() > 1 {
                        let enabled = matches!(parts[1], "on" | "enable");
                        (*p_env).fix_low_fov_scene = if enabled { 1 } else { 0 };
                        println!(
                            "Fix low FOV scenes: {}",
                            if enabled { "enabled" } else { "disabled" }
                        );
                    } else {
                        println!("Usage: fixfov <on|off> - Fix low FOV scenes (fov <= 30)");
                    }
                }
                "fog" => {
                    if parts.len() > 1 {
                        let disabled = matches!(parts[1], "off" | "disable");
                        (*p_env).disable_fog = if disabled { 1 } else { 0 };
                        println!(
                            "Fog rendering: {}",
                            if disabled { "disabled" } else { "enabled" }
                        );
                    } else {
                        println!("Usage: fog <on|off>");
                    }
                }
                "banner" => {
                    if parts.len() > 1 {
                        let hidden = parts[1] == "hide";
                        (*p_env).hide_quest_banner = if hidden { 1 } else { 0 };
                        println!(
                            "Quest banner: {}",
                            if hidden { "hidden" } else { "visible" }
                        );
                    } else {
                        println!("Usage: banner <show|hide>");
                    }
                }
                "team" => {
                    if parts.len() > 1 {
                        let removed = parts[1] == "remove";
                        (*p_env).remove_open_team_progress = if removed { 1 } else { 0 };
                        println!(
                            "Team animation: {}",
                            if removed { "removed" } else { "normal" }
                        );
                    } else {
                        println!("Usage: team <normal|remove>");
                    }
                }
                "camera" => {
                    if parts.len() > 1 {
                        let disabled = parts[1] == "disable";
                        (*p_env).disable_event_camera_move = if disabled { 1 } else { 0 };
                        println!(
                            "Event camera: {}",
                            if disabled { "disabled" } else { "enabled" }
                        );
                    } else {
                        println!("Usage: camera <enable|disable>");
                    }
                }
                "damage" => {
                    if parts.len() > 1 {
                        let hidden = parts[1] == "hide";
                        (*p_env).disable_show_damage_text = if hidden { 1 } else { 0 };
                        println!(
                            "Damage numbers: {}",
                            if hidden { "hidden" } else { "visible" }
                        );
                    } else {
                        println!("Usage: damage <show|hide>");
                    }
                }
                "craft" => {
                    if parts.len() > 1 {
                        let redirected = parts[1] == "redirect";
                        (*p_env).redirect_craft_entry = if redirected { 1 } else { 0 };
                        println!(
                            "Crafting table: {}",
                            if redirected { "redirected" } else { "normal" }
                        );
                    } else {
                        println!("Usage: craft <normal|redirect>");
                    }
                }
                "status" => {
                    self.show_status(p_env);
                }
                "reset" => {
                    println!("Resetting all settings to default values...");
                    // Restore default values
                    (*p_env).target_frame_rate = 60;
                    (*p_env).field_of_view = 45.0;
                    (*p_env).fix_low_fov_scene = 1;
                    (*p_env).disable_fog = 0;
                    (*p_env).hide_quest_banner = 0;
                    (*p_env).remove_open_team_progress = 0;
                    (*p_env).disable_event_camera_move = 0;
                    (*p_env).disable_show_damage_text = 0;
                    (*p_env).using_touch_screen = 0;
                    (*p_env).redirect_craft_entry = 0;
                    println!("[OK] All settings have been reset to defaults");
                }
                "help" | "?" => {
                    self.show_help();
                }
                _ => {
                    println!(
                        "Unknown command: '{}'. Type 'help' for available commands.",
                        parts[0]
                    );
                }
            }
        }
    }

    fn show_status(&self, p_env: *const IslandEnvironment) {
        unsafe {
            println!("\n=== Current Configuration ===");
            println!("FPS: {} (always enabled)", (*p_env).target_frame_rate);
            println!("FOV: {} (always enabled)", (*p_env).field_of_view);
            println!(
                "Fix low FOV scenes: {}",
                if (*p_env).fix_low_fov_scene != 0 {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "Fog: {}",
                if (*p_env).disable_fog != 0 {
                    "disabled"
                } else {
                    "enabled"
                }
            );
            println!(
                "Banner: {}",
                if (*p_env).hide_quest_banner != 0 {
                    "hidden"
                } else {
                    "visible"
                }
            );
            println!(
                "Team animation: {}",
                if (*p_env).remove_open_team_progress != 0 {
                    "removed"
                } else {
                    "normal"
                }
            );
            println!(
                "Event camera: {}",
                if (*p_env).disable_event_camera_move != 0 {
                    "disabled"
                } else {
                    "enabled"
                }
            );
            println!(
                "Damage numbers: {}",
                if (*p_env).disable_show_damage_text != 0 {
                    "hidden"
                } else {
                    "visible"
                }
            );
            println!(
                "Touch screen: {}",
                if (*p_env).using_touch_screen != 0 {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "Crafting table: {}",
                if (*p_env).redirect_craft_entry != 0 {
                    "redirected"
                } else {
                    "normal"
                }
            );
            println!("State: {:?}", (*p_env).state);
            println!("Game PID: {}", self.process_id);
        }
    }

    fn show_help(&self) {
        println!("\n=== Available Commands ===");
        println!("fps <value>          - Set target FPS (e.g., fps 120)");
        println!("fov <value>          - Set field of view (e.g., fov 60.0)");
        println!("fixfov <on|off>      - Fix low FOV scenes (fov <= 30)");
        println!("fog <on|off>         - Enable/disable fog rendering");
        println!("banner <show|hide>   - Show/hide quest banner");
        println!("team <normal|remove> - Control team opening animation");
        println!("camera <enable|disable> - Control event camera movement");
        println!("damage <show|hide>   - Control damage number display");
        println!("craft <normal|redirect> - Control crafting table redirect");
        println!("status               - Show current configuration");
        println!("reset                - Reset all settings to defaults");
        println!("help, ?              - Show this help message");
        println!("quit, exit           - Restore defaults and exit");
        println!("\n[IMPORTANT] Always use 'quit' to properly restore defaults!");
        println!("===========================");
    }

    fn wait_for_main_module(&self, exe_name: &str) -> Result<(), String> {
        println!("Waiting for main module: {}", exe_name);

        for _ in 0..300 {
            if self.get_main_module_info(exe_name) {
                println!("Main module loaded successfully");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }

        Err("Timeout waiting for main module!".to_string())
    }

    fn get_main_module_info(&self, exe_name: &str) -> bool {
        unsafe {
            let mut h_mods: [HMODULE; 1024] = [ptr::null_mut(); 1024];
            let mut cb_needed = 0u32;

            if EnumProcessModules(
                self.h_process,
                h_mods.as_mut_ptr(),
                (h_mods.len() * mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
            ) == 0
            {
                return false;
            }

            let module_count = cb_needed as usize / mem::size_of::<HMODULE>();

            for &h_mod in h_mods.iter().take(module_count.min(h_mods.len())) {
                let mut module_name = [0u8; 260]; // MAX_PATH
                if GetModuleFileNameExA(
                    self.h_process,
                    h_mod,
                    module_name.as_mut_ptr(),
                    module_name.len() as u32,
                ) != 0
                {
                    let name_str = String::from_utf8_lossy(&module_name);
                    let name_str = name_str.trim_end_matches('\0');

                    if let Some(filename) = name_str.split('\\').next_back() {
                        if filename == exe_name {
                            return true;
                        }
                    }
                }
            }

            false
        }
    }

    fn get_main_thread_id(&self, process_id: u32) -> u32 {
        unsafe {
            let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if h_snapshot == INVALID_HANDLE_VALUE {
                return 0;
            }

            let mut te32 = THREADENTRY32 {
                dwSize: mem::size_of::<THREADENTRY32>() as u32,
                ..mem::zeroed()
            };

            let mut thread_id = 0u32;
            let mut earliest_time = FILETIME {
                dwLowDateTime: u32::MAX,
                dwHighDateTime: u32::MAX,
            };

            if Thread32First(h_snapshot, &mut te32) != 0 {
                loop {
                    if te32.th32OwnerProcessID == process_id {
                        let h_thread =
                            OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if !h_thread.is_null() {
                            let mut creation_time = mem::zeroed();
                            let mut exit_time = mem::zeroed();
                            let mut kernel_time = mem::zeroed();
                            let mut user_time = mem::zeroed();

                            if GetThreadTimes(
                                h_thread,
                                &mut creation_time,
                                &mut exit_time,
                                &mut kernel_time,
                                &mut user_time,
                            ) != 0
                            {
                                // Compare file times manually since CompareFileTime isn't available
                                let creation_u64 = ((creation_time.dwHighDateTime as u64) << 32)
                                    | (creation_time.dwLowDateTime as u64);
                                let earliest_u64 = ((earliest_time.dwHighDateTime as u64) << 32)
                                    | (earliest_time.dwLowDateTime as u64);

                                if creation_u64 < earliest_u64 {
                                    earliest_time = creation_time;
                                    thread_id = te32.th32ThreadID;
                                }
                            }
                            CloseHandle(h_thread);
                        }
                    }

                    if Thread32Next(h_snapshot, &mut te32) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(h_snapshot);
            thread_id
        }
    }
}

impl Drop for HutaoInjector {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl HutaoInjector {
    fn cleanup(&mut self) {
        println!("[Cleanup] Starting cleanup process...");

        unsafe {
            if !self.p_shared_memory.Value.is_null() {
                println!("[Cleanup] Setting DLL state to stopped...");
                let p_env = self.p_shared_memory.Value as *mut IslandEnvironment;
                (*p_env).state = IslandState::Stopped;

                UnmapViewOfFile(self.p_shared_memory);
                self.p_shared_memory.Value = ptr::null_mut();
                println!("[Cleanup] SharedMemory unmapped");
            }

            if self.h_memory_mapped_file != INVALID_HANDLE_VALUE {
                CloseHandle(self.h_memory_mapped_file);
                self.h_memory_mapped_file = INVALID_HANDLE_VALUE;
                println!("[Cleanup] Memory mapped file closed");
            }

            if self.h_process != INVALID_HANDLE_VALUE {
                CloseHandle(self.h_process);
                self.h_process = INVALID_HANDLE_VALUE;
                println!("[Cleanup] Game process handle closed");
            }
        }

        println!("[Cleanup] All resources cleaned up successfully");
    }
}

// Helper functions for input
fn get_input(prompt: &str, default_value: &str) -> String {
    print!("{} [default: {}]: ", prompt, default_value);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        default_value.to_string()
    } else {
        input.to_string()
    }
}

fn get_int_input(prompt: &str, default_value: i32) -> i32 {
    let input = get_input(prompt, &default_value.to_string());
    input.parse().unwrap_or(default_value)
}

fn get_float_input(prompt: &str, default_value: f32) -> f32 {
    let input = get_input(prompt, &default_value.to_string());
    input.parse().unwrap_or(default_value)
}

fn get_bool_input(prompt: &str, default_value: bool) -> bool {
    let prompt_text = format!("{} [{}]", prompt, if default_value { "Y/n" } else { "y/N" });
    print!("{}: ", prompt_text);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        default_value
    } else {
        matches!(input.chars().next(), Some('y'))
    }
}

fn main() {
    println!("=== Hutao Injector & Configuration Tool ===");

    let args: Vec<String> = std::env::args().collect();

    let (game_path, dll_path) = if args.len() >= 3 {
        (args[1].clone(), args[2].clone())
    } else {
        println!("Usage: hutao_injector.exe <game_path> <dll_path>");
        println!("Or run without arguments for interactive mode");

        let game_path = get_input(
            "Game path",
            "D:\\Program Files\\Genshin Impact\\Genshin Impact Game\\YuanShen.exe",
        );
        let dll_path = get_input("DLL path", "hutao_minhook.dll");
        (game_path, dll_path)
    };

    // Configuration setup with validation
    let target_fps = loop {
        let fps = get_int_input("Target FPS (minimum 30)", 60);
        if fps >= 30 {
            break fps;
        }
        println!("Error: FPS must be at least 30. Please try again.");
    };

    let field_of_view = loop {
        let fov = get_float_input("Field of View (minimum 1.0)", 45.0);
        if fov >= 1.0 {
            break fov;
        }
        println!("Error: FOV must be at least 1.0. Please try again.");
    };

    let config = GameConfig {
        fov: field_of_view,
        fps: target_fps,
        disable_fog: get_bool_input("Disable fog rendering?", false),
        fix_low_fov: get_bool_input("Fix low FOV scenes (fov <= 30)?", true),
        hide_banner: get_bool_input("Hide quest banner?", false),
        remove_team_anim: get_bool_input("Remove team open animation?", false),
        disable_event_camera: get_bool_input("Disable event camera movement?", false),
        hide_damage: get_bool_input("Hide damage numbers?", false),
        touch_screen: get_bool_input("Enable touch screen mode?", false),
        redirect_craft: get_bool_input("Redirect crafting table?", false),
    };

    // Check if DLL exists
    if !std::path::Path::new(&dll_path).exists() {
        eprintln!("DLL not found: {}", dll_path);
        std::process::exit(1);
    }

    let mut injector = HutaoInjector::new();

    if let Err(e) = injector.initialize() {
        eprintln!("Failed to initialize injector: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = injector.launch_and_inject(&game_path, &dll_path, &config) {
        eprintln!("Failed to launch and inject: {}", e);
        std::process::exit(1);
    }

    println!("\n[OK] Launch and injection completed!");
    println!("Game is running with initial configuration.");
    println!("You can now modify settings using commands below.");

    // Run configuration loop
    injector.run_config_loop();
}
