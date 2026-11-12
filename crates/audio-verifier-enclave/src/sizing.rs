//! How many `/v1/measure` jobs run at once, derived at boot from the enclave's own vCPUs and
//! memory. The parent sets both with `nitro-cli run-enclave --cpu-count --memory`; neither is
//! part of the PCRs, so resizing an enclave needs no new image or registration.

use std::{fs, num::NonZeroUsize, thread};

const MIB: u64 = 1 << 20;

/// Worst-case memory of one `/v1/measure` job, rounded up from its parts:
///
/// - the decoder's window: at most 16 MiB + 128 KiB past the last complete frame, one more
///   8 KiB read and 1 MiB of finished frames, in one allocation that is never copied, 17.2 MiB;
/// - the PCM pipeline: four buffers of a 65,535-sample, 8-channel, 24-bit frame, 6 MiB;
/// - libFLAC's decoder: output and residual buffers for 8 channels of 65,536 samples, the side
///   channel and the Rice partition tables, about 7 MiB;
/// - the body queue: 16 queued chunks, the one being read and the one being sent, each at most
///   hyper's ~408 KiB read buffer, about 7.3 MiB;
/// - the metadata (64 KiB), two thread stacks and the response.
pub const MEASURE_JOB_BYTES: u64 = 48 * MIB;

/// Memory kept for everything but the jobs: the kernel's own allocations, the root file system
/// the image unpacks into memory, the runtime, and up to 256 connections, each with at most a
/// 4 KiB `/attestation` body.
pub const PROCESS_RESERVE_BYTES: u64 = 128 * MIB;

/// The enclave's vCPUs and memory, as its kernel reports them; either may be unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    /// vCPUs this process may run on.
    pub cpus: Option<usize>,
    /// `MemTotal` from `/proc/meminfo`, in bytes.
    pub memory_bytes: Option<u64>,
}

impl Resources {
    /// Reads the vCPUs from `std::thread::available_parallelism` and `MemTotal` from
    /// `/proc/meminfo`.
    pub fn detect() -> Self {
        Self {
            cpus: thread::available_parallelism().ok().map(NonZeroUsize::get),
            memory_bytes: fs::read_to_string("/proc/meminfo")
                .ok()
                .as_deref()
                .and_then(mem_total),
        }
    }
}

/// `MemTotal` from the text of `/proc/meminfo`, in bytes.
pub fn mem_total(meminfo: &str) -> Option<u64> {
    let value = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?;
    let kib = value
        .trim()
        .strip_suffix("kB")?
        .trim_end()
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

/// Concurrent `/v1/measure` jobs for an enclave with `resources`: one per vCPU, and no more than
/// fit in `MemTotal` after [`PROCESS_RESERVE_BYTES`] at [`MEASURE_JOB_BYTES`] each, but at least
/// one. An unknown vCPU count or memory size counts as room for one.
pub fn measure_concurrency(resources: Resources) -> usize {
    let cpus = resources.cpus.unwrap_or(1);
    let by_memory = resources.memory_bytes.map_or(1, |memory| {
        memory.saturating_sub(PROCESS_RESERVE_BYTES) / MEASURE_JOB_BYTES
    });
    cpus.min(usize::try_from(by_memory).unwrap_or(usize::MAX))
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enclave(cpus: usize, memory_mib: u64) -> Resources {
        Resources {
            cpus: Some(cpus),
            memory_bytes: Some(memory_mib * MIB),
        }
    }

    #[test]
    fn typical_enclaves_run_one_job_per_vcpu() {
        assert_eq!(measure_concurrency(enclave(2, 2048)), 2);
        assert_eq!(measure_concurrency(enclave(4, 6144)), 4);
        assert_eq!(measure_concurrency(enclave(8, 16_384)), 8);
        // MemTotal is somewhat below `--memory`; 2 GiB still runs two jobs.
        assert_eq!(measure_concurrency(enclave(2, 1900)), 2);
    }

    #[test]
    fn memory_bounds_the_jobs_when_vcpus_are_plentiful() {
        // 128 MiB reserved; 1024 - 128 = 896 MiB is room for 18 jobs.
        assert_eq!(measure_concurrency(enclave(32, 1024)), 18);
        assert_eq!(measure_concurrency(enclave(64, 128 + 48 * 10 - 1)), 9);
        assert_eq!(measure_concurrency(enclave(64, 128 + 48 * 10)), 10);
    }

    #[test]
    fn low_memory_still_runs_one_job() {
        assert_eq!(measure_concurrency(enclave(8, 128 + 48 * 2 - 1)), 1);
        assert_eq!(measure_concurrency(enclave(2, 100)), 1);
        assert_eq!(measure_concurrency(enclave(4, 0)), 1);
    }

    #[test]
    fn unknown_resources_fall_back_to_one_job() {
        let unknown = Resources {
            cpus: None,
            memory_bytes: None,
        };
        assert_eq!(measure_concurrency(unknown), 1);
        let no_memory = Resources {
            cpus: Some(32),
            memory_bytes: None,
        };
        assert_eq!(measure_concurrency(no_memory), 1);
        let no_cpus = Resources {
            cpus: None,
            memory_bytes: Some(64 * 1024 * MIB),
        };
        assert_eq!(measure_concurrency(no_cpus), 1);
    }

    #[test]
    fn mem_total_is_read_from_meminfo() {
        let meminfo = "MemTotal:        1967392 kB\nMemFree:         1803040 kB\n";
        assert_eq!(mem_total(meminfo), Some(1_967_392 * 1024));
        let later = "MemFree:  10 kB\nMemTotal:\t64 kB\n";
        assert_eq!(mem_total(later), Some(64 * 1024));
        assert_eq!(mem_total(""), None);
        assert_eq!(mem_total("MemFree: 10 kB\n"), None);
        assert_eq!(mem_total("MemTotal: lots kB\n"), None);
        assert_eq!(mem_total("MemTotal: 10 MB\n"), None);
        assert_eq!(mem_total("MemTotal: 18446744073709551615 kB\n"), None);
    }

    #[test]
    fn detected_resources_are_plausible() {
        let resources = Resources::detect();
        assert!(resources.cpus.is_some_and(|cpus| cpus >= 1));
        if cfg!(target_os = "linux") {
            assert!(resources.memory_bytes.is_some_and(|bytes| bytes > 0));
        }
        assert!(measure_concurrency(resources) >= 1);
    }
}
