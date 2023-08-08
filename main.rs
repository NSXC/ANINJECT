use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use std::ptr;
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::EnumProcessModules;
use winapi::um::psapi::GetModuleFileNameExW;

const TARGET_PROCESS_NAME: &str = "TARGETAPP"; 

fn get_process_id(process_name: &str) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot != ptr::null_mut() {
        let mut process_entry: PROCESSENTRY32W = Default::default();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if unsafe { Process32FirstW(snapshot, &mut process_entry) } != 0 {
            while unsafe { Process32NextW(snapshot, &mut process_entry) } != 0 {
                let process_name_str = String::from_utf16_lossy(&process_entry.szExeFile);
                if process_name_str.to_lowercase() == process_name.to_lowercase() {
                    unsafe { CloseHandle(snapshot) };
                    return Some(process_entry.th32ProcessID);
                }
            }
        }
        
        unsafe { CloseHandle(snapshot) };
    }
    None
}

fn get_loaded_dlls(process_id: u32) -> HashSet<String> {
    let mut loaded_dlls = HashSet::new();

    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id) };
    if process_handle != ptr::null_mut() {
        let mut module_handles: [HMODULE; 1024] = [ptr::null_mut(); 1024];
        let mut module_count: u32 = 0;

        if unsafe {
            EnumProcessModules(
                process_handle,
                module_handles.as_mut_ptr(),
                std::mem::size_of_val(&module_handles) as u32,
                &mut module_count,
            )
        } != 0
        {
            for i in 0..module_count as usize {
                let mut module_file_name: [u16; 512] = [0; 512];
                if unsafe {
                    GetModuleFileNameExW(
                        process_handle,
                        module_handles[i],
                        module_file_name.as_mut_ptr(),
                        module_file_name.len() as u32,
                    )
                } != 0
                {
                    let module_name = String::from_utf16_lossy(&module_file_name)
                        .split('\\')
                        .last()
                        .unwrap_or_default()
                        .to_string();
                    loaded_dlls.insert(module_name);
                }
            }
        }

        unsafe { CloseHandle(process_handle) };
    }

    loaded_dlls
}

fn main() {
    let target_process_id = loop {
        if let Some(process_id) = get_process_id(TARGET_PROCESS_NAME) {
            break process_id;
        }
        thread::sleep(Duration::from_secs(1));
    };

    let mut initial_dlls = get_loaded_dlls(target_process_id);

    loop {
        let current_dlls = get_loaded_dlls(target_process_id);

        for dll in &current_dlls {
            if !initial_dlls.contains(dll) {
                println!("New DLL injected into process {}: {}", TARGET_PROCESS_NAME, dll);
            }
        }

        initial_dlls = current_dlls;

        thread::sleep(Duration::from_secs(1));
    }
}
