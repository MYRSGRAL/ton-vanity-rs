use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const STOP: usize = 1 << (usize::BITS - 1);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Initializing,
    SelfTesting,
    Searching,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InterruptAction {
    ExitBeforeSearch,
    Drain,
    ForceExit,
}

#[derive(Default)]
pub struct SearchControl {
    gate: AtomicUsize,
    phase: AtomicU8,
}

impl SearchControl {
    /// Возвращает true при повторном запросе остановки.
    pub fn request_stop(&self) -> bool {
        self.gate.fetch_or(STOP, Ordering::SeqCst) & STOP != 0
    }
    pub fn interrupt_action(&self) -> InterruptAction {
        if self.request_stop() {
            InterruptAction::ForceExit
        } else if self.phase() != Phase::Searching {
            InterruptAction::ExitBeforeSearch
        } else {
            InterruptAction::Drain
        }
    }
    pub fn is_stopping(&self) -> bool {
        self.gate.load(Ordering::SeqCst) & STOP != 0
    }
    pub fn set_phase(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::SeqCst);
    }
    pub fn phase(&self) -> Phase {
        match self.phase.load(Ordering::SeqCst) {
            0 => Phase::Initializing,
            1 => Phase::SelfTesting,
            _ => Phase::Searching,
        }
    }
    /// Admission линеаризован с отменой; драйвер вызывается без удержания lock.
    pub fn try_admit(&self) -> bool {
        self.gate
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| {
                (state & STOP == 0 && state < 2).then_some(state + 1)
            })
            .is_ok()
    }
    pub fn complete(&self) {
        self.gate.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Обходит atexit/DLL detach: драйвер может зависнуть даже внутри process::exit.
/// Используется только до поисковых пачек либо по повторному Ctrl+C.
pub fn force_exit(code: i32) -> ! {
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn _exit(code: i32) -> !;
        }
        _exit(code)
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn TerminateProcess(process: *mut std::ffi::c_void, code: u32) -> i32;
        }
        // Свой process handle не требует дополнительных прав. TerminateProcess
        // обходит потенциально зависший DLL detach, вызываемый ExitProcess.
        unsafe {
            TerminateProcess(GetCurrentProcess(), code as u32);
        }
        std::process::abort()
    }
    #[cfg(not(any(unix, windows)))]
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_blocks_new_admissions_and_keeps_accepted_batches() {
        let control = SearchControl::default();
        assert!(control.try_admit());
        assert!(control.try_admit());
        assert!(!control.try_admit());
        assert!(!control.request_stop());
        assert!(!control.try_admit());
        control.complete();
        assert!(!control.try_admit());
        control.complete();
        assert!(control.request_stop());
    }

    #[test]
    fn initialization_cancel_exits_without_waiting_for_backend() {
        for phase in [super::Phase::Initializing, super::Phase::SelfTesting] {
            let control = SearchControl::default();
            control.set_phase(phase);
            assert_eq!(
                control.interrupt_action(),
                super::InterruptAction::ExitBeforeSearch
            );
            assert!(!control.try_admit());
        }
    }

    #[test]
    fn cancellation_during_entropy_preparation_prevents_submit() {
        use std::sync::{Arc, Barrier};
        let control = Arc::new(SearchControl::default());
        control.set_phase(super::Phase::Searching);
        let barrier = Arc::new(Barrier::new(2));
        let worker_control = Arc::clone(&control);
        let worker_barrier = Arc::clone(&barrier);
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            worker_barrier.wait();
            worker_control.try_admit()
        });
        barrier.wait();
        assert_eq!(control.interrupt_action(), super::InterruptAction::Drain);
        barrier.wait();
        assert!(!worker.join().unwrap());
        assert_eq!(
            control.interrupt_action(),
            super::InterruptAction::ForceExit
        );
    }
}
