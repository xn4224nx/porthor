/*
 * PORTHOR
 * =======
 *
 * A rust library with a suite of functions to detect the executable runing in
 * a sandbox environment.
 *
 */

const MIN_CPU: usize = 4;
const MIN_PHYS_CORES: usize = 4;
const MIN_RAM: u64 = 8_000_000_000; // Aproximately 8GB
const MIN_SWAP: u64 = 512_000_000; // Aproximately 512MB
const MIN_GB_STORAGE: usize = 512;

/// Read certain attributes of the system and using pre-determined thresholds
/// make a judgement about whether this code is running in a sandbox.
pub fn is_sys_attr_valid() -> Option<usize> {
    let mut danger_score = 0;

    if !sysinfo::IS_SUPPORTED_SYSTEM {
        return None;
    }

    /* Extract the system data if the system is supported. */
    let mut sys_data = sysinfo::System::new_all();
    sys_data.refresh_all();

    /* Limited number of cpus is also indicative of a sandbox. */
    if sys_data.cpus().len() < MIN_CPU {
        danger_score += 1;
    }
    if sysinfo::System::physical_core_count().unwrap_or(MIN_PHYS_CORES) < MIN_PHYS_CORES {
        danger_score += 1;
    }

    /* Sandboxes can be limited in the ammount of RAM they have access to. */
    if sys_data.total_memory() < MIN_RAM {
        danger_score += 1;
    }
    if sys_data.total_swap() < MIN_SWAP {
        danger_score += 1;
    }

    return Some(danger_score);
}

/// Calculate the total storage on the system in gigabytes and determine how
/// unusually low it is.
pub fn is_storage_valid() -> Option<usize> {
    let mut gigabytes_found = 0;

    if !sysinfo::IS_SUPPORTED_SYSTEM {
        return None;
    }

    /* Sum all available storage. */
    for disk in &sysinfo::Disks::new_with_refreshed_list() {
        gigabytes_found += disk.total_space().div_ceil(1_000_000_000) as usize;
    }

    return Some(
        MIN_GB_STORAGE
            .saturating_sub(gigabytes_found)
            .saturating_div(gigabytes_found.saturating_add(1)),
    );
}

/// Sandboxes are usually just booted into so a low uptime can indicate an
/// artifical environment.
pub fn is_uptime_valid() -> Option<usize> {
    None
}

/// Sleep functions can be altered before inserting the program in a sandbox.
pub fn is_sleep_valid() -> Option<usize> {
    None
}

/// The Sandbox is expected to be isolated from the internet and the network
/// traffic will be low or nil when in an artifical host.
pub fn is_network_valid() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_is_sys_attr_valid() {
        assert_eq!(is_sys_attr_valid(), Some(0));
    }

    #[test]
    fn run_is_storage_valid() {
        assert_eq!(is_storage_valid(), Some(0));
    }
}
