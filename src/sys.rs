/*
 * SYSTEM BASED DETECTION
 * ======================
 *
 * Methods to detect a sandbox using attributes of the system the code is
 * running on. This is all based on the `sysinfo` rust crate.
 * https://github.com/GuillaumeGomez/sysinfo
 *
 */

use rand::prelude::*;
use std::collections::HashMap;

const MIN_CPU: usize = 4;
const MIN_PHYS_CORES: usize = 4;
const MIN_RAM: u64 = 8_000_000_000; // Aproximately 8GB
const MIN_SWAP: u64 = 512_000_000; // Aproximately 512MB
const MIN_GB_STORAGE: usize = 512;

/// Read certain attributes of the system and using pre-determined thresholds
/// make a judgement about whether this code is running in a sandbox.
pub fn is_sys_attr_valid() -> Option<f32> {
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

    return Some((danger_score as f32) / 4.0);
}

/// Calculate the total storage on the system in gigabytes and determine how
/// unusually low it is.
pub fn is_storage_valid() -> Option<f32> {
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
            .saturating_div(gigabytes_found.saturating_add(1)) as f32,
    );
}

/// Sandboxes are usually just booted into so a low uptime can indicate an
/// artifical environment.
pub fn is_uptime_valid() -> Option<f32> {
    let utime = sysinfo::System::uptime() as usize;
    return Some(
        1000_usize
            .saturating_sub(utime)
            .saturating_div(utime.saturating_add(1)) as f32,
    );
}

/// Sleep functions can be altered before inserting the program in a sandbox.
pub fn is_sleep_valid() -> Option<f32> {
    let mut rng = rand::rng();
    let sleep_dur = rng.random_range(30..=60);
    let utime_0 = sysinfo::System::uptime();

    /* Sleep for a random number of seconds. */
    std::thread::sleep(std::time::Duration::from_secs(sleep_dur));

    /* Read the uptime after the sleep has happened.  */
    let utime_1 = sysinfo::System::uptime();

    return Some(
        utime_1
            .saturating_add(sleep_dur)
            .saturating_sub(utime_0 + 100) as f32,
    );
}

/// The Sandbox is expected to be isolated from the internet and the network
/// traffic will be low or nil when in an artifical host.
pub fn is_network_valid() -> Option<f32> {
    let mut total_trans: usize = 0;
    let mut total_recev: usize = 0;

    /* Sum the total data receieved and transmitted. */
    for (_, data) in &sysinfo::Networks::new_with_refreshed_list() {
        total_trans += data.total_transmitted() as usize;
        total_recev += data.total_received() as usize;
    }
    return Some(10_000_usize.saturating_div(total_trans + total_recev) as f32);
}

/// Within a sandbox the supplied temperatur value might not vary like a real
/// computer.
pub fn is_temp_valid() -> Option<f32> {
    let mut component_temps: HashMap<String, Vec<f32>> = HashMap::new();
    let time_iterval_secs = 1;
    let num_samples = 10;

    /* Collect the temperatures of all the system components */
    for _ in 0..num_samples {
        let component_data = sysinfo::Components::new_with_refreshed_list();

        for comp in &component_data {
            if let Some(temp) = comp.temperature() {
                /* Ignore 'null' values. */
                if temp <= 0.0 {
                    continue;
                }

                component_temps
                    .entry(comp.label().to_string())
                    .and_modify(|x| x.push(temp))
                    .or_insert(vec![temp]);
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(time_iterval_secs));
    }

    /* No valid temperature results is a bad sign! */
    if component_temps.is_empty() {
        return Some(1.0);
    }

    let total_results = component_temps.len() as f32;

    /* Perform the Shapiro-Wilk test for normality. */
    return Some(
        component_temps
            .into_values()
            .filter_map(|x| shapiro_wilks_norm_test(&x))
            .map(|x| 1.0 - x)
            .sum::<f32>()
            / total_results,
    );
}

/// Determine how close to normalcy a group of values are using the Shapiro-Wilk
/// Test.
pub fn shapiro_wilks_norm_test(values: &Vec<f32>) -> Option<f32> {
    let p_val_header = vec![0.01, 0.02, 0.05, 0.1, 0.5, 0.9, 0.95, 0.98, 0.99];
    let p_val_lookup = vec![
        vec![
            0.753, 0.756, 0.767, 0.789, 0.959, 0.998, 0.999, 1.000, 1.000,
        ],
        vec![
            0.687, 0.707, 0.748, 0.792, 0.935, 0.987, 0.992, 0.996, 0.997,
        ],
        vec![
            0.686, 0.715, 0.762, 0.806, 0.927, 0.979, 0.986, 0.991, 0.993,
        ],
        vec![
            0.713, 0.743, 0.788, 0.826, 0.927, 0.974, 0.981, 0.986, 0.989,
        ],
        vec![
            0.730, 0.760, 0.803, 0.838, 0.928, 0.972, 0.979, 0.985, 0.988,
        ],
        vec![
            0.749, 0.778, 0.818, 0.851, 0.932, 0.972, 0.978, 0.984, 0.987,
        ],
        vec![
            0.764, 0.791, 0.829, 0.859, 0.935, 0.972, 0.978, 0.984, 0.986,
        ],
        vec![
            0.781, 0.806, 0.842, 0.869, 0.938, 0.972, 0.978, 0.983, 0.986,
        ],
        vec![
            0.792, 0.817, 0.850, 0.876, 0.940, 0.973, 0.979, 0.984, 0.986,
        ],
        vec![
            0.805, 0.828, 0.859, 0.883, 0.943, 0.973, 0.979, 0.984, 0.986,
        ],
        vec![
            0.814, 0.837, 0.866, 0.889, 0.945, 0.974, 0.979, 0.984, 0.986,
        ],
        vec![
            0.825, 0.846, 0.874, 0.895, 0.947, 0.975, 0.980, 0.984, 0.986,
        ],
        vec![
            0.835, 0.855, 0.881, 0.901, 0.950, 0.975, 0.980, 0.984, 0.987,
        ],
        vec![
            0.844, 0.863, 0.887, 0.906, 0.952, 0.976, 0.981, 0.985, 0.987,
        ],
        vec![
            0.851, 0.869, 0.892, 0.910, 0.954, 0.977, 0.981, 0.985, 0.987,
        ],
        vec![
            0.858, 0.874, 0.897, 0.914, 0.956, 0.978, 0.982, 0.986, 0.988,
        ],
        vec![
            0.863, 0.879, 0.901, 0.917, 0.957, 0.978, 0.982, 0.986, 0.988,
        ],
        vec![
            0.868, 0.884, 0.905, 0.920, 0.959, 0.979, 0.983, 0.986, 0.988,
        ],
        vec![
            0.873, 0.888, 0.908, 0.923, 0.960, 0.980, 0.983, 0.987, 0.989,
        ],
        vec![
            0.878, 0.892, 0.911, 0.926, 0.961, 0.980, 0.984, 0.987, 0.989,
        ],
        vec![
            0.881, 0.895, 0.914, 0.928, 0.962, 0.981, 0.984, 0.987, 0.989,
        ],
        vec![
            0.884, 0.898, 0.916, 0.930, 0.963, 0.981, 0.984, 0.987, 0.989,
        ],
        vec![
            0.888, 0.901, 0.918, 0.931, 0.964, 0.981, 0.985, 0.988, 0.989,
        ],
        vec![
            0.891, 0.904, 0.920, 0.933, 0.965, 0.982, 0.985, 0.988, 0.989,
        ],
        vec![
            0.894, 0.906, 0.923, 0.935, 0.965, 0.982, 0.985, 0.988, 0.990,
        ],
        vec![
            0.896, 0.908, 0.924, 0.936, 0.966, 0.982, 0.985, 0.988, 0.990,
        ],
        vec![
            0.898, 0.910, 0.926, 0.937, 0.966, 0.982, 0.985, 0.988, 0.990,
        ],
        vec![
            0.900, 0.912, 0.927, 0.939, 0.967, 0.983, 0.985, 0.988, 0.990,
        ],
        vec![
            0.902, 0.914, 0.929, 0.940, 0.967, 0.983, 0.986, 0.988, 0.990,
        ],
        vec![
            0.904, 0.915, 0.930, 0.941, 0.968, 0.983, 0.986, 0.988, 0.990,
        ],
        vec![
            0.906, 0.917, 0.931, 0.942, 0.968, 0.983, 0.986, 0.989, 0.990,
        ],
        vec![
            0.908, 0.919, 0.933, 0.943, 0.969, 0.983, 0.986, 0.989, 0.990,
        ],
        vec![
            0.910, 0.920, 0.934, 0.944, 0.969, 0.984, 0.986, 0.989, 0.990,
        ],
        vec![
            0.912, 0.922, 0.935, 0.945, 0.970, 0.984, 0.986, 0.989, 0.990,
        ],
        vec![
            0.914, 0.924, 0.936, 0.946, 0.970, 0.984, 0.987, 0.989, 0.990,
        ],
        vec![
            0.916, 0.925, 0.938, 0.947, 0.971, 0.984, 0.987, 0.989, 0.990,
        ],
        vec![
            0.917, 0.927, 0.939, 0.948, 0.971, 0.984, 0.987, 0.989, 0.991,
        ],
        vec![
            0.919, 0.928, 0.940, 0.949, 0.972, 0.985, 0.987, 0.989, 0.991,
        ],
        vec![
            0.920, 0.929, 0.941, 0.950, 0.972, 0.985, 0.987, 0.989, 0.991,
        ],
        vec![
            0.922, 0.930, 0.942, 0.951, 0.972, 0.985, 0.987, 0.989, 0.991,
        ],
        vec![
            0.923, 0.932, 0.943, 0.951, 0.973, 0.985, 0.987, 0.990, 0.991,
        ],
        vec![
            0.924, 0.933, 0.944, 0.952, 0.973, 0.985, 0.987, 0.990, 0.991,
        ],
        vec![
            0.926, 0.934, 0.945, 0.953, 0.973, 0.985, 0.988, 0.990, 0.991,
        ],
        vec![
            0.927, 0.935, 0.945, 0.953, 0.974, 0.985, 0.988, 0.990, 0.991,
        ],
        vec![
            0.928, 0.936, 0.946, 0.954, 0.974, 0.985, 0.988, 0.990, 0.991,
        ],
        vec![
            0.929, 0.937, 0.947, 0.954, 0.974, 0.985, 0.988, 0.990, 0.991,
        ],
        vec![
            0.929, 0.939, 0.947, 0.955, 0.974, 0.985, 0.988, 0.990, 0.991,
        ],
        vec![
            0.930, 0.938, 0.947, 0.955, 0.974, 0.985, 0.988, 0.990, 0.991,
        ],
    ];
    let a_coeffs = vec![
        vec![0.7071],
        vec![0.7071],
        vec![0.6872, 0.1677],
        vec![0.6646, 0.2413],
        vec![0.6431, 0.2806, 0.0875],
        vec![0.6233, 0.3031, 0.1401],
        vec![0.6052, 0.3164, 0.1743, 0.0561],
        vec![0.5888, 0.3244, 0.1976, 0.0947],
        vec![0.5739, 0.3291, 0.2141, 0.1224, 0.0399],
        vec![0.5601, 0.3315, 0.2260, 0.1429, 0.0695],
        vec![0.5475, 0.3325, 0.2347, 0.1586, 0.0922, 0.0303],
        vec![0.5359, 0.3325, 0.2412, 0.1707, 0.1099, 0.0539],
        vec![0.5251, 0.3318, 0.2460, 0.1802, 0.1240, 0.0727, 0.0240],
        vec![0.5150, 0.3306, 0.2495, 0.1878, 0.1353, 0.0880, 0.0433],
        vec![
            0.5056, 0.3290, 0.2521, 0.1939, 0.1447, 0.1005, 0.0593, 0.0196,
        ],
        vec![
            0.4968, 0.3273, 0.2540, 0.1988, 0.1524, 0.1109, 0.0725, 0.0359,
        ],
        vec![
            0.4886, 0.3253, 0.2553, 0.2027, 0.1587, 0.1197, 0.0837, 0.0496, 0.0163,
        ],
        vec![
            0.4808, 0.3232, 0.2561, 0.2059, 0.1641, 0.1271, 0.0932, 0.0612, 0.0303,
        ],
        vec![
            0.4734, 0.3211, 0.2565, 0.2085, 0.1686, 0.1334, 0.1013, 0.0711, 0.0422, 0.0140,
        ],
        vec![
            0.4643, 0.3185, 0.2578, 0.2119, 0.1736, 0.1399, 0.1092, 0.0804, 0.0530, 0.0263,
        ],
        vec![
            0.4590, 0.3156, 0.2571, 0.2131, 0.1764, 0.1443, 0.1150, 0.0878, 0.0618, 0.0368, 0.0122,
        ],
        vec![
            0.4542, 0.3126, 0.2563, 0.2139, 0.1787, 0.1480, 0.1201, 0.0941, 0.0696, 0.0459, 0.0228,
            0.0000,
        ],
        vec![
            0.4493, 0.3098, 0.2554, 0.2145, 0.1807, 0.1512, 0.1245, 0.0997, 0.0764, 0.0539, 0.0321,
            0.0107,
        ],
        vec![
            0.4450, 0.3069, 0.2543, 0.2148, 0.1822, 0.1539, 0.1283, 0.1046, 0.0823, 0.0610, 0.0403,
            0.0200, 0.0000,
        ],
        vec![
            0.4407, 0.3043, 0.2533, 0.2151, 0.1836, 0.1563, 0.1316, 0.1089, 0.0876, 0.0672, 0.0476,
            0.0284, 0.0094,
        ],
        vec![
            0.4366, 0.3018, 0.2522, 0.2152, 0.1848, 0.1584, 0.1346, 0.1128, 0.0923, 0.0728, 0.0540,
            0.0358, 0.0178, 0.0000,
        ],
        vec![
            0.4328, 0.2992, 0.2510, 0.2151, 0.1857, 0.1601, 0.1372, 0.1162, 0.0965, 0.0778, 0.0598,
            0.0424, 0.0253, 0.0084,
        ],
        vec![
            0.4291, 0.2968, 0.2499, 0.2150, 0.1864, 0.1616, 0.1395, 0.1192, 0.1002, 0.0822, 0.0650,
            0.0483, 0.0320, 0.0159, 0.0000,
        ],
        vec![
            0.4254, 0.2944, 0.2487, 0.2148, 0.1870, 0.1630, 0.1415, 0.1219, 0.1036, 0.0862, 0.0697,
            0.0537, 0.0381, 0.0227, 0.0076,
        ],
        vec![
            0.4220, 0.2921, 0.2475, 0.2145, 0.1874, 0.1641, 0.1433, 0.1243, 0.1066, 0.0899, 0.0739,
            0.0585, 0.0435, 0.0289, 0.0144, 0.0000,
        ],
        vec![
            0.4188, 0.2898, 0.2463, 0.2141, 0.1878, 0.1651, 0.1449, 0.1265, 0.1093, 0.0931, 0.0777,
            0.0629, 0.0485, 0.0344, 0.0206, 0.0068,
        ],
        vec![
            0.4156, 0.2876, 0.2451, 0.2137, 0.1880, 0.1660, 0.1463, 0.1284, 0.1118, 0.0961, 0.0812,
            0.0669, 0.0530, 0.0395, 0.0262, 0.0131, 0.0000,
        ],
        vec![
            0.4127, 0.2854, 0.2439, 0.2132, 0.1882, 0.1667, 0.1475, 0.1301, 0.1140, 0.0988, 0.0844,
            0.0706, 0.0572, 0.0441, 0.0314, 0.0187, 0.0062,
        ],
        vec![
            0.4096, 0.2834, 0.2427, 0.2127, 0.1883, 0.1673, 0.1487, 0.1317, 0.1160, 0.1013, 0.0873,
            0.0739, 0.0610, 0.0484, 0.0361, 0.0239, 0.0119, 0.0000,
        ],
        vec![
            0.4068, 0.2813, 0.2415, 0.2121, 0.1883, 0.1678, 0.1496, 0.1331, 0.1179, 0.1036, 0.0900,
            0.0770, 0.0645, 0.0523, 0.0404, 0.0287, 0.0172, 0.0057,
        ],
        vec![
            0.4040, 0.2794, 0.2403, 0.2116, 0.1883, 0.1683, 0.1505, 0.1344, 0.1196, 0.1056, 0.0924,
            0.0798, 0.0677, 0.0559, 0.0444, 0.0331, 0.0220, 0.0110, 0.0000,
        ],
        vec![
            0.4015, 0.2774, 0.2391, 0.2110, 0.1881, 0.1686, 0.1513, 0.1356, 0.1211, 0.1075, 0.0947,
            0.0824, 0.0706, 0.0592, 0.0481, 0.0372, 0.0264, 0.0158, 0.0053,
        ],
        vec![
            0.3989, 0.2755, 0.2380, 0.2104, 0.1880, 0.1689, 0.1520, 0.1366, 0.1225, 0.1092, 0.0967,
            0.0848, 0.0733, 0.0622, 0.0515, 0.0409, 0.0305, 0.0203, 0.0101, 0.0000,
        ],
        vec![
            0.3964, 0.2737, 0.2368, 0.2098, 0.1878, 0.1691, 0.1526, 0.1376, 0.1237, 0.1108, 0.0986,
            0.0870, 0.0759, 0.0651, 0.0546, 0.0444, 0.0343, 0.0244, 0.0146, 0.0049,
        ],
        vec![
            0.3940, 0.2719, 0.2357, 0.2091, 0.1876, 0.1693, 0.1531, 0.1384, 0.1249, 0.1123, 0.1004,
            0.0891, 0.0782, 0.0677, 0.0575, 0.0476, 0.0379, 0.0283, 0.0188, 0.0094, 0.0000,
        ],
        vec![
            0.3917, 0.2701, 0.2345, 0.2085, 0.1874, 0.1694, 0.1535, 0.1392, 0.1259, 0.1136, 0.1020,
            0.0909, 0.0804, 0.0701, 0.0602, 0.0506, 0.0411, 0.0318, 0.0227, 0.0136, 0.0045,
        ],
        vec![
            0.3894, 0.2684, 0.2334, 0.2078, 0.1871, 0.1695, 0.1539, 0.1398, 0.1269, 0.1149, 0.1035,
            0.0927, 0.0824, 0.0724, 0.0628, 0.0534, 0.0442, 0.0352, 0.0263, 0.0175, 0.0087, 0.0000,
        ],
        vec![
            0.3872, 0.2667, 0.2323, 0.2072, 0.1868, 0.1695, 0.1542, 0.1405, 0.1278, 0.1160, 0.1049,
            0.0943, 0.0842, 0.0745, 0.0651, 0.0560, 0.0471, 0.0383, 0.0296, 0.0211, 0.0126, 0.0042,
        ],
        vec![
            0.3850, 0.2651, 0.2313, 0.2065, 0.1865, 0.1695, 0.1545, 0.1410, 0.1286, 0.1170, 0.1062,
            0.0959, 0.0860, 0.0765, 0.0673, 0.0584, 0.0497, 0.0412, 0.0328, 0.0245, 0.0163, 0.0081,
            0.0000,
        ],
        vec![
            0.3830, 0.2635, 0.2302, 0.2058, 0.1862, 0.1695, 0.1548, 0.1415, 0.1293, 0.1180, 0.1073,
            0.0972, 0.0876, 0.0783, 0.0694, 0.0607, 0.0522, 0.0439, 0.0357, 0.0277, 0.0197, 0.0118,
            0.0039,
        ],
        vec![
            0.3808, 0.2620, 0.2291, 0.2052, 0.1859, 0.1695, 0.1550, 0.1420, 0.1300, 0.1189, 0.1085,
            0.0986, 0.0892, 0.0801, 0.0713, 0.0628, 0.0546, 0.0465, 0.0385, 0.0307, 0.0229, 0.0153,
            0.0076, 0.0000,
        ],
        vec![
            0.3789, 0.2604, 0.2281, 0.2045, 0.1855, 0.1693, 0.1551, 0.1423, 0.1306, 0.1197, 0.1095,
            0.0998, 0.0906, 0.0817, 0.0731, 0.0648, 0.0568, 0.0489, 0.0411, 0.0335, 0.0259, 0.0185,
            0.0111, 0.0037,
        ],
        vec![
            0.3770, 0.2589, 0.2271, 0.2038, 0.1851, 0.1692, 0.1553, 0.1427, 0.1312, 0.1205, 0.1105,
            0.1010, 0.0919, 0.0832, 0.0748, 0.0667, 0.0588, 0.0511, 0.0436, 0.0361, 0.0288, 0.0215,
            0.0143, 0.0071, 0.0000,
        ],
        vec![
            0.3751, 0.2574, 0.2260, 0.2032, 0.1847, 0.1691, 0.1554, 0.1430, 0.1317, 0.1212, 0.1113,
            0.1020, 0.0932, 0.0846, 0.0764, 0.0685, 0.0608, 0.0532, 0.0459, 0.0386, 0.0314, 0.0244,
            0.0174, 0.0104, 0.0035,
        ],
    ];

    /* This test only works within a very constrained range. */
    if values.len() < 3 || values.len() > 50 {
        return None;
    }

    let mean_temp = values.iter().sum::<f32>() / (values.len() as f32);
    let temp_vara = values.iter().map(|x| x * x).sum::<f32>() - (mean_temp * mean_temp);

    /* No variance at all is a sign of artifical values. */
    if temp_vara <= 0.0 {
        Some(1.0);
    }

    let sum_sqr = values
        .iter()
        .map(|x| (x - mean_temp) * (x - mean_temp))
        .sum::<f32>();

    /* The final comparison index changes for odd or even sample sizes. */
    let final_comp_idx = if values.len() % 2 == 0 {
        values.len() / 2 - 1
    } else {
        (values.len() - 1) / 2 - 1
    };

    /* Cross difference requires a sorted sample, smallest to largest. */
    let mut ordered_samp = values.clone();
    ordered_samp.sort_by(f32::total_cmp);

    let cross_diff_sum = (0..final_comp_idx)
        .map(|x| {
            a_coeffs[values.len() - 3][x] * (ordered_samp[values.len() - 1 - x] - ordered_samp[x])
        })
        .sum::<f32>();

    let test_result: f32 = cross_diff_sum * cross_diff_sum / sum_sqr;

    /* Ensure the test result if covered by the p_value lookup. */
    if test_result < p_val_header[0] {
        return Some(0.0);
    } else if p_val_header[p_val_header.len() - 1] < test_result {
        return Some(1.0);
    }

    /* Determine the upper and lower p-values the final result is between. */
    let mut pvh_idx = 1;
    while pvh_idx < p_val_header.len() {
        if p_val_header[pvh_idx - 1] <= test_result && test_result <= p_val_header[pvh_idx] {
            break;
        }
        pvh_idx += 1;
    }

    /* Calculate how far between the header this test is. */
    let intr_frac: f32 = (test_result - p_val_header[pvh_idx - 1])
        / (p_val_header[pvh_idx] - p_val_header[pvh_idx - 1]);

    /* Determine the final p-value */
    return Some(
        (p_val_lookup[values.len() - 3][pvh_idx - 1]
            + (p_val_lookup[values.len() - 3][pvh_idx]
                - p_val_lookup[values.len() - 3][pvh_idx - 1])
                * intr_frac)
            .clamp(0.0, 1.0),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_is_sys_attr_valid() {
        assert_eq!(is_sys_attr_valid(), Some(0.0));
    }

    #[test]
    fn run_is_storage_valid() {
        assert_eq!(is_storage_valid(), Some(0.0));
    }

    #[test]
    fn run_is_uptime_valid() {
        assert_eq!(is_uptime_valid(), Some(0.0));
    }

    #[test]
    fn run_is_sleep_valid() {
        assert_eq!(is_sleep_valid(), Some(0.0));
    }

    #[test]
    fn run_is_network_valid() {
        assert_eq!(is_network_valid(), Some(0.0));
    }

    #[test]
    fn run_is_temp_valid() {
        assert_eq!(is_temp_valid(), Some(0.0));
    }
}
