#[cfg(windows)]
pub(crate) fn terminate_local_process(process_id: i32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    let Ok(process_id) = u32::try_from(process_id) else {
        return;
    };
    // SAFETY: OpenProcess returns an owned handle or null. TerminateProcess
    // and CloseHandle receive that same live handle and retain no pointers.
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, 0, process_id);
        if !process.is_null() {
            let _ = TerminateProcess(process, 1);
            let _ = CloseHandle(process);
        }
    }
}
