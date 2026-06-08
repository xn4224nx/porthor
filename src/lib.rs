/*
 * PORTHOR
 * =======
 *
 * A rust library with a suite of functions to detect the executable runing in
 * a sandbox environment.
 *
 */

mod net;
mod statistics;
mod sys;

/* Expose the internal detection functions. */
pub use crate::net::{connect_to_random_domain, ntp_sleep_check};
pub use crate::sys::{
    is_network_valid, is_sleep_valid, is_storage_valid, is_sys_attr_valid, is_temp_valid,
    is_uptime_valid,
};
