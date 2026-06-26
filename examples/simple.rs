#![crate_type = "bin"]

use porthor;

fn main() {
    println!(
        "Domain Connection: {:?}",
        porthor::connect_to_random_domain()
    );
    println!("Network:           {:?}", porthor::is_network_valid());
    println!("Uptime:            {:?}", porthor::is_uptime_valid());
    println!("Temperature:       {:?}", porthor::is_temp_valid());
    println!("System Attributes: {:?}", porthor::is_sys_attr_valid());
    println!("Storage:           {:?}", porthor::is_storage_valid());
    println!("Sleep:             {:?}", porthor::is_sleep_valid());
    println!("NTP Sleep:         {:?}", porthor::ntp_sleep_check());
}
