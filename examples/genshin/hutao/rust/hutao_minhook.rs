use microseh;
use min_hook_rs::*;
use std::ffi::{CString, c_void};
use std::mem;
use std::ptr;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::*;

// IL2CPP structures
#[repr(C)]
struct Il2CppObject {
    klass: *mut c_void,
    monitor: *mut c_void,
}

#[repr(C)]
struct Il2CppArraySize {
    object: Il2CppObject,
    bounds: *mut c_void,
    max_length: usize,
    vector: [u8; 32],
}

#[repr(C)]
struct Il2CppString {
    object: Il2CppObject,
    length: i32,
    chars: [u16; 32],
}

// Function types - using correct calling convention
type MickeyWonderMethod = unsafe extern "system" fn(i32) -> *mut Il2CppArraySize;
type MickeyWonderMethodPartner = unsafe extern "system" fn(*const i8) -> *mut Il2CppString;
type MickeyWonderMethodPartner2 = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void);
type SetFieldOfViewMethod = unsafe extern "system" fn(*mut c_void, f32);
type SetEnableFogRenderingMethod = unsafe extern "system" fn(bool);
type SetTargetFrameRateMethod = unsafe extern "system" fn(i32);
type OpenTeamMethod = unsafe extern "system" fn();
type OpenTeamPageAccordinglyMethod = unsafe extern "system" fn(bool);
type CheckCanEnterMethod = unsafe extern "system" fn() -> bool;
type SetupQuestBannerMethod = unsafe extern "system" fn(*mut c_void);
type FindGameObjectMethod = unsafe extern "system" fn(*mut Il2CppString) -> *mut c_void;
type SetActiveMethod = unsafe extern "system" fn(*mut c_void, bool);
type EventCameraMoveMethod = unsafe extern "system" fn(*mut c_void, *mut c_void) -> bool;
type ShowOneDamageTextExMethod = unsafe extern "system" fn(
    *mut c_void,
    i32,
    i32,
    i32,
    f32,
    *mut Il2CppString,
    *mut c_void,
    *mut c_void,
    i32,
);
type SwitchInputDeviceToTouchScreenMethod = unsafe extern "system" fn(*mut c_void);
type MickeyWonderCombineEntryMethod = unsafe extern "system" fn(*mut c_void);
type MickeyWonderCombineEntryMethodPartner = unsafe extern "system" fn(
    *mut Il2CppString,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
) -> bool;

// Environment structure
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum IslandState {
    None = 0,
    Error = 1,
    Started = 2,
    Stopped = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FunctionOffsets {
    mickey_wonder: u32,
    mickey_wonder_partner: u32,
    mickey_wonder_partner2: u32,
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
    mickey_wonder_combine_entry: u32,
    mickey_wonder_combine_entry_partner: u32,
}

#[repr(C)]
#[derive(Debug)]
struct IslandEnvironment {
    state: IslandState,
    last_error: u32,
    function_offsets: FunctionOffsets,
    enable_set_field_of_view: i32, // BOOL
    field_of_view: f32,
    fix_low_fov_scene: i32,            // BOOL
    disable_fog: i32,                  // BOOL
    enable_set_target_frame_rate: i32, // BOOL
    target_frame_rate: i32,
    remove_open_team_progress: i32, // BOOL
    hide_quest_banner: i32,         // BOOL
    disable_event_camera_move: i32, // BOOL
    disable_show_damage_text: i32,  // BOOL
    using_touch_screen: i32,        // BOOL
    redirect_combine_entry: i32,    // BOOL
}

// Original function pointers
#[derive(Default)]
struct OriginalFunctions {
    mickey_wonder: Option<MickeyWonderMethod>,
    mickey_wonder_partner: Option<MickeyWonderMethodPartner>,
    mickey_wonder_partner2: Option<MickeyWonderMethodPartner2>,
    set_field_of_view: Option<SetFieldOfViewMethod>,
    set_enable_fog_rendering: Option<SetEnableFogRenderingMethod>,
    set_target_frame_rate: Option<SetTargetFrameRateMethod>,
    open_team: Option<OpenTeamMethod>,
    open_team_page_accordingly: Option<OpenTeamPageAccordinglyMethod>,
    check_can_enter: Option<CheckCanEnterMethod>,
    setup_quest_banner: Option<SetupQuestBannerMethod>,
    find_game_object: Option<FindGameObjectMethod>,
    set_active: Option<SetActiveMethod>,
    event_camera_move: Option<EventCameraMoveMethod>,
    show_one_damage_text_ex: Option<ShowOneDamageTextExMethod>,
    switch_input_device_to_touch_screen: Option<SwitchInputDeviceToTouchScreenMethod>,
    mickey_wonder_combine_entry: Option<MickeyWonderCombineEntryMethod>,
    mickey_wonder_combine_entry_partner: Option<MickeyWonderCombineEntryMethodPartner>,
}

// Global state
static ISLAND_ENVIRONMENT_NAME: &str = "4F3E8543-40F7-4808-82DC-21E48A6037A7";
static mut P_ENVIRONMENT: *mut IslandEnvironment = ptr::null_mut();
static ORIGINALS: Mutex<OriginalFunctions> = Mutex::new(OriginalFunctions {
    mickey_wonder: None,
    mickey_wonder_partner: None,
    mickey_wonder_partner2: None,
    set_field_of_view: None,
    set_enable_fog_rendering: None,
    set_target_frame_rate: None,
    open_team: None,
    open_team_page_accordingly: None,
    check_can_enter: None,
    setup_quest_banner: None,
    find_game_object: None,
    set_active: None,
    event_camera_move: None,
    show_one_damage_text_ex: None,
    switch_input_device_to_touch_screen: None,
    mickey_wonder_combine_entry: None,
    mickey_wonder_combine_entry_partner: None,
});
static mut MINNIE_BUFFER: [i8; 1024] = [0; 1024];
static mut MINNIE_LENGTH: usize = 0;
static mut TOUCH_SCREEN_INITIALIZED: bool = false;

// Memory protection disabling
unsafe extern "system" {
    unsafe fn LdrAddRefDll(flags: u32, dll_handle: *mut c_void) -> i32;
}

const LDR_ADDREF_DLL_PIN: u32 = 0x00000001;

fn disable_protect_virtual_memory() {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return;
        }

        let p_nt_protect_virtual_memory =
            GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr());
        let p_nt_query_section = GetProcAddress(ntdll, b"NtQuerySection\0".as_ptr());

        if let (Some(protect_fn), Some(query_fn)) =
            (p_nt_protect_virtual_memory, p_nt_query_section)
        {
            let mut old = 0u32;
            VirtualProtect(
                protect_fn as *mut c_void,
                1,
                PAGE_EXECUTE_READWRITE,
                &mut old,
            );

            let protect_ptr = protect_fn as *mut u64;
            let query_ptr = query_fn as *const u64;
            let query_offset_ptr = (query_fn as usize + 4) as *const u32;

            *protect_ptr = (*query_ptr & !(0xFFu64 << 32)) | ((*query_offset_ptr as u64 - 1) << 32);

            VirtualProtect(protect_fn as *mut c_void, 1, old, &mut old);
        }
    }
}

// Utility functions
fn is_valid_read_ptr(ptr: *mut c_void, _size: usize) -> bool {
    unsafe {
        let mut mbi = mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        if VirtualQuery(ptr, &mut mbi, mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0 {
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) != 0
        } else {
            false
        }
    }
}

// Hook endpoints - corrected logic to match C++ exactly
unsafe extern "system" fn mickey_wonder_partner2_endpoint(
    mickey: *mut c_void,
    house: *mut c_void,
    spell: *mut c_void,
) {
    unsafe {
        let (partner_fn, partner2_fn) = {
            let originals = ORIGINALS.lock().unwrap();
            (
                originals.mickey_wonder_partner,
                originals.mickey_wonder_partner2,
            )
        };

        let mut b_found = false;

        if let Some(partner_fn) = partner_fn {
            let buffer_ptr = ptr::addr_of!(MINNIE_BUFFER) as *const i8;
            let p_string = partner_fn(buffer_ptr);
            let mut pp_current: *mut *mut Il2CppString = ptr::null_mut();

            // Find loop
            for offset in (0x10..0x233).step_by(0x8) {
                pp_current = (house as *mut u8).add(offset) as *mut *mut Il2CppString;
                if (*pp_current).is_null()
                    || !is_valid_read_ptr(
                        *pp_current as *mut c_void,
                        mem::size_of::<Il2CppString>(),
                    )
                {
                    continue;
                }
                if (**pp_current).length != 66 {
                    continue;
                }
                b_found = true;
                break;
            }

            // Simple logic like C++
            if !b_found {
                if let Some(partner2_fn) = partner2_fn {
                    partner2_fn(mickey, house, spell);
                }
                return;
            }

            if !pp_current.is_null() {
                *pp_current = p_string;
            }
        }

        if let Some(partner2_fn) = partner2_fn {
            partner2_fn(mickey, house, spell);
        }
    }
}

unsafe extern "system" fn set_field_of_view_endpoint(p_this: *mut c_void, value: f32) {
    unsafe {
        if P_ENVIRONMENT.is_null() {
            return;
        }

        let env = &*P_ENVIRONMENT;

        let (touch_fn, frame_rate_fn, fov_fn, fog_fn) = {
            let originals = ORIGINALS.lock().unwrap();
            (
                originals.switch_input_device_to_touch_screen,
                originals.set_target_frame_rate,
                originals.set_field_of_view,
                originals.set_enable_fog_rendering,
            )
        };

        // Touch screen initialization (this should happen regardless)
        if !TOUCH_SCREEN_INITIALIZED && env.using_touch_screen != 0 {
            TOUCH_SCREEN_INITIALIZED = true;
            if let Some(touch_fn) = touch_fn {
                touch_fn(ptr::null_mut());
            }
        }

        // Target frame rate (this should happen regardless)
        if env.enable_set_target_frame_rate != 0 {
            if let Some(frame_rate_fn) = frame_rate_fn {
                frame_rate_fn(env.target_frame_rate);
            }
        }

        // CORRECTED: Match C++ logic exactly - early return
        if env.enable_set_field_of_view == 0 {
            if let Some(fov_fn) = fov_fn {
                fov_fn(p_this, value);
            }
            return;
        }

        // Only reach here if EnableSetFieldOfView is true
        if value.floor() <= 30.0 {
            if let Some(fog_fn) = fog_fn {
                fog_fn(false);
            }
            if let Some(fov_fn) = fov_fn {
                let fov_value = if env.fix_low_fov_scene != 0 {
                    value
                } else {
                    env.field_of_view
                };
                fov_fn(p_this, fov_value);
            }
        } else {
            if let Some(fog_fn) = fog_fn {
                fog_fn(env.disable_fog == 0);
            }
            if let Some(fov_fn) = fov_fn {
                fov_fn(p_this, env.field_of_view);
            }
        }
    }
}

unsafe extern "system" fn open_team_endpoint() {
    unsafe {
        if P_ENVIRONMENT.is_null() {
            return;
        }

        let env = &*P_ENVIRONMENT;

        // Get function pointers
        let (check_fn, page_fn, team_fn) = {
            let originals = ORIGINALS.lock().unwrap();
            (
                originals.check_can_enter,
                originals.open_team_page_accordingly,
                originals.open_team,
            )
        };

        // CORRECTED: Exact C++ logic translation
        let should_use_page_fn =
            env.remove_open_team_progress != 0 && check_fn.map_or(false, |f| f());

        if should_use_page_fn {
            if let Some(page_fn) = page_fn {
                page_fn(false);
            }
        } else {
            if let Some(team_fn) = team_fn {
                team_fn();
            }
        }
    }
}

unsafe extern "system" fn setup_quest_banner_endpoint(p_this: *mut c_void) {
    unsafe {
        if P_ENVIRONMENT.is_null() {
            return;
        }

        let env = &*P_ENVIRONMENT;

        let (banner_fn, partner_fn, find_fn, active_fn) = {
            let originals = ORIGINALS.lock().unwrap();
            (
                originals.setup_quest_banner,
                originals.mickey_wonder_partner,
                originals.find_game_object,
                originals.set_active,
            )
        };

        if env.hide_quest_banner == 0 {
            if let Some(banner_fn) = banner_fn {
                banner_fn(p_this);
            }
        } else {
            if let Some(partner_fn) = partner_fn {
                let banner_path = CString::new(
                    "Canvas/Pages/InLevelMapPage/GrpMap/GrpPointTips/Layout/QuestBanner",
                )
                .unwrap();
                let banner_string = partner_fn(banner_path.as_ptr());

                if let Some(find_fn) = find_fn {
                    let banner = find_fn(banner_string);
                    if !banner.is_null() {
                        if let Some(active_fn) = active_fn {
                            active_fn(banner, false);
                        }
                    }
                }
            }
        }
    }
}

unsafe extern "system" fn event_camera_move_endpoint(
    p_this: *mut c_void,
    event: *mut c_void,
) -> bool {
    unsafe {
        if P_ENVIRONMENT.is_null() {
            return true;
        }

        let env = &*P_ENVIRONMENT;

        if env.disable_event_camera_move != 0 {
            true
        } else {
            // Get lock and immediately get required function pointer
            let camera_fn = {
                let originals = ORIGINALS.lock().unwrap();
                originals.event_camera_move
            };

            if let Some(camera_fn) = camera_fn {
                camera_fn(p_this, event)
            } else {
                true
            }
        }
    }
}

unsafe extern "system" fn show_one_damage_text_ex_endpoint(
    p_this: *mut c_void,
    r#type: i32,
    damage_type: i32,
    show_type: i32,
    damage: f32,
    show_text: *mut Il2CppString,
    world_pos: *mut c_void,
    attackee: *mut c_void,
    element_reaction_type: i32,
) {
    unsafe {
        if P_ENVIRONMENT.is_null() {
            return;
        }

        let env = &*P_ENVIRONMENT;

        if env.disable_show_damage_text != 0 {
            return;
        }

        // Get lock and immediately get required function pointer
        let damage_fn = {
            let originals = ORIGINALS.lock().unwrap();
            originals.show_one_damage_text_ex
        };

        if let Some(damage_fn) = damage_fn {
            damage_fn(
                p_this,
                r#type,
                damage_type,
                show_type,
                damage,
                show_text,
                world_pos,
                attackee,
                element_reaction_type,
            );
        }
    }
}

unsafe extern "system" fn mickey_wonder_combine_entry_endpoint(p_this: *mut c_void) {
    unsafe {
        if P_ENVIRONMENT.is_null() {
            return;
        }

        let env = &*P_ENVIRONMENT;

        let (partner_fn, combine_partner_fn, combine_fn) = {
            let originals = ORIGINALS.lock().unwrap();
            (
                originals.mickey_wonder_partner,
                originals.mickey_wonder_combine_entry_partner,
                originals.mickey_wonder_combine_entry,
            )
        };

        if env.redirect_combine_entry != 0 {
            if let (Some(partner_fn), Some(combine_partner_fn)) = (partner_fn, combine_partner_fn) {
                let synthesis_page = CString::new("SynthesisPage").unwrap();
                let page_string = partner_fn(synthesis_page.as_ptr());
                combine_partner_fn(
                    page_string,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                return;
            }
        }

        if let Some(combine_fn) = combine_fn {
            combine_fn(p_this);
        }
    }
}

// Install MinHooks
fn install_min_hooks(base: u64, env: &IslandEnvironment) -> Result<()> {
    unsafe {
        initialize()?;

        let mut originals = ORIGINALS.lock().unwrap();

        originals.mickey_wonder = Some(mem::transmute(
            (base + env.function_offsets.mickey_wonder as u64) as *mut c_void,
        ));
        originals.mickey_wonder_partner = Some(mem::transmute(
            (base + env.function_offsets.mickey_wonder_partner as u64) as *mut c_void,
        ));
        originals.set_enable_fog_rendering = Some(mem::transmute(
            (base + env.function_offsets.set_enable_fog_rendering as u64) as *mut c_void,
        ));
        originals.set_target_frame_rate = Some(mem::transmute(
            (base + env.function_offsets.set_target_frame_rate as u64) as *mut c_void,
        ));
        originals.open_team_page_accordingly = Some(mem::transmute(
            (base + env.function_offsets.open_team_page_accordingly as u64) as *mut c_void,
        ));
        originals.check_can_enter = Some(mem::transmute(
            (base + env.function_offsets.check_can_enter as u64) as *mut c_void,
        ));
        originals.find_game_object = Some(mem::transmute(
            (base + env.function_offsets.find_game_object as u64) as *mut c_void,
        ));
        originals.set_active = Some(mem::transmute(
            (base + env.function_offsets.set_active as u64) as *mut c_void,
        ));
        originals.switch_input_device_to_touch_screen = Some(mem::transmute(
            (base + env.function_offsets.switch_input_device_to_touch_screen as u64) as *mut c_void,
        ));
        originals.mickey_wonder_combine_entry_partner = Some(mem::transmute(
            (base + env.function_offsets.mickey_wonder_combine_entry_partner as u64) as *mut c_void,
        ));

        let target = (base + env.function_offsets.mickey_wonder_partner2 as u64) as *mut c_void;
        let trampoline = create_hook(target, mickey_wonder_partner2_endpoint as *mut c_void)?;
        originals.mickey_wonder_partner2 = Some(mem::transmute(trampoline));

        let target = (base + env.function_offsets.set_field_of_view as u64) as *mut c_void;
        let trampoline = create_hook(target, set_field_of_view_endpoint as *mut c_void)?;
        originals.set_field_of_view = Some(mem::transmute(trampoline));

        let target = (base + env.function_offsets.open_team as u64) as *mut c_void;
        let trampoline = create_hook(target, open_team_endpoint as *mut c_void)?;
        originals.open_team = Some(mem::transmute(trampoline));

        let target = (base + env.function_offsets.setup_quest_banner as u64) as *mut c_void;
        let trampoline = create_hook(target, setup_quest_banner_endpoint as *mut c_void)?;
        originals.setup_quest_banner = Some(mem::transmute(trampoline));

        let target = (base + env.function_offsets.event_camera_move as u64) as *mut c_void;
        let trampoline = create_hook(target, event_camera_move_endpoint as *mut c_void)?;
        originals.event_camera_move = Some(mem::transmute(trampoline));

        let target = (base + env.function_offsets.show_one_damage_text_ex as u64) as *mut c_void;
        let trampoline = create_hook(target, show_one_damage_text_ex_endpoint as *mut c_void)?;
        originals.show_one_damage_text_ex = Some(mem::transmute(trampoline));

        let target =
            (base + env.function_offsets.mickey_wonder_combine_entry as u64) as *mut c_void;
        let trampoline = create_hook(target, mickey_wonder_combine_entry_endpoint as *mut c_void)?;
        originals.mickey_wonder_combine_entry = Some(mem::transmute(trampoline));

        // Enable all hooks
        enable_hook(ALL_HOOKS)?;

        Ok(())
    }
}

// Main DLL thread
extern "system" fn island_thread(lp_param: *mut c_void) -> u32 {
    unsafe {
        let env_name_c = CString::new(ISLAND_ENVIRONMENT_NAME).unwrap();

        let h_file = OpenFileMappingA(
            FILE_MAP_READ | FILE_MAP_WRITE,
            FALSE.into(),
            env_name_c.as_ptr() as *const u8,
        );
        if h_file.is_null() || h_file == INVALID_HANDLE_VALUE {
            return GetLastError();
        }

        let lp_view = MapViewOfFile(h_file, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if lp_view.Value.is_null() {
            CloseHandle(h_file);
            return GetLastError();
        }

        P_ENVIRONMENT = lp_view.Value as *mut IslandEnvironment;
        (*P_ENVIRONMENT).state = IslandState::Started;

        let base = GetModuleHandleA(ptr::null()) as u64;

        // Build minnie string using microseh for exception handling
        MINNIE_LENGTH = 0;

        for n in 0..3 {
            let mickey_wonder_addr = base + (*P_ENVIRONMENT).function_offsets.mickey_wonder as u64;
            let mickey_wonder: MickeyWonderMethod =
                mem::transmute(mickey_wonder_addr as *mut c_void);

            // Use microseh to handle exceptions like C++ __try/__except
            match microseh::try_seh(|| {
                let result = mickey_wonder(n);
                if !result.is_null() {
                    let array = &*result;
                    let buffer_len = ptr::addr_of!(MINNIE_BUFFER)
                        .cast::<[i8; 1024]>()
                        .as_ref()
                        .unwrap()
                        .len();
                    if MINNIE_LENGTH + array.max_length < buffer_len {
                        let src_ptr = array.vector.as_ptr() as *const i8;
                        let dst_ptr = ptr::addr_of_mut!(MINNIE_BUFFER)
                            .cast::<i8>()
                            .add(MINNIE_LENGTH);
                        ptr::copy_nonoverlapping(src_ptr, dst_ptr, array.max_length);
                        MINNIE_LENGTH += array.max_length;
                    }
                }
            }) {
                Ok(_) => {}
                Err(_) => {
                    // Exception occurred, continue with next iteration like C++ version
                }
            }
        }

        // Install hooks
        if let Err(_) = install_min_hooks(base, &(*P_ENVIRONMENT)) {
            (*P_ENVIRONMENT).state = IslandState::Error;
            (*P_ENVIRONMENT).last_error = GetLastError();
            UnmapViewOfFile(lp_view);
            CloseHandle(h_file);
            return GetLastError();
        }

        // Wait indefinitely like C++ version
        WaitForSingleObject(GetCurrentThread(), u32::MAX);

        // Cleanup
        let _ = disable_hook(ALL_HOOKS);
        let _ = uninitialize();

        (*P_ENVIRONMENT).state = IslandState::Stopped;
        UnmapViewOfFile(lp_view);
        CloseHandle(h_file);

        FreeLibraryAndExitThread(lp_param as HMODULE, 0);
    }
}

// Hook procedure for exports
extern "system" fn island_get_window_hook_impl(
    code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    unsafe { CallNextHookEx(ptr::null_mut(), code, w_param, l_param) }
}

// Export functions - Updated following upstream changes
#[unsafe(no_mangle)]
pub extern "system" fn DllGetWindowsHookForHutao(p_hook_proc: *mut *mut c_void) -> HRESULT {
    // We don't handle package family checks - keep it simple
    unsafe {
        *p_hook_proc = island_get_window_hook_impl as *mut c_void;
        0 // S_OK
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn IslandGetFunctionOffsetsSize(p_count: *mut u64) -> HRESULT {
    unsafe {
        *p_count = mem::size_of::<FunctionOffsets>() as u64;
        0 // S_OK
    }
}

// DLL entry point
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    h_module: HINSTANCE,
    ul_reason_for_call: u32,
    _lp_reserved: *mut c_void,
) -> BOOL {
    unsafe {
        match ul_reason_for_call {
            DLL_PROCESS_ATTACH => {
                DisableThreadLibraryCalls(h_module);
                LdrAddRefDll(LDR_ADDREF_DLL_PIN, h_module as *mut c_void);
                disable_protect_virtual_memory();
                CreateThread(
                    ptr::null_mut(),
                    0,
                    Some(island_thread),
                    h_module as *mut c_void,
                    0,
                    ptr::null_mut(),
                );
            }
            DLL_PROCESS_DETACH => {
                let _ = disable_hook(ALL_HOOKS);
                let _ = uninitialize();
                Sleep(500);
            }
            _ => {}
        }
        TRUE.into()
    }
}
