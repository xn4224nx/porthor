/*
 * Porthor Function Access Tests
 * =============================
 */

use porthor::*;

#[test]
fn access_sys_fn() {
    is_sys_attr_valid();
    is_storage_valid();
    is_uptime_valid();
    is_sleep_valid();
    is_network_valid();
    is_temp_valid();
}

#[test]
fn access_net_fn() {
    connect_to_random_domain();
    ntp_sleep_check();
}
