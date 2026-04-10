/*
 * NETWORK BASED DETECTION
 * =======================
 *
 * Functions to detect a sandbox by making network connections.
 */

use rand::{RngExt, rngs::SmallRng};
use std::net::TcpStream;

/// Sandboxes will allow the executable to connect to any doamin and pretend
/// that it was successful. This function connects to domains that do not exist.
/// If these connections are successful the executable is most likely in a
/// sandbox.
pub fn connect_to_random_domain() -> Option<usize> {
    let mut successful_connections = 0;
    let letters = vec![
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    ];
    let top_level_domains = vec!["com", "org", "net", "gov", "edu"];

    /* First check that there is network access by connecting to a dns server. */
    TcpStream::connect("8.8.8.8:53").ok()?;

    /* Generate and then try and connect to 10 domains. */
    let mut rng: SmallRng = rand::make_rng();
    for _ in 0..10 {
        let site_len = rng.random_range(5..=12);

        /* Generate the site name. */
        let site = (0..site_len)
            .map(|_| letters[rng.random_range(0..letters.len())])
            .collect::<String>();

        /* Create the full site url. */
        let url = format!(
            "http://www.{}.{}",
            site,
            top_level_domains[rng.random_range(0..top_level_domains.len())]
        );

        /* Attempt to connect to it. */
        let Ok(res) = reqwest::blocking::get(url) else {
            continue;
        };

        if res.status().is_success() {
            successful_connections += 1;
        };
    }
    return Some(successful_connections);
}

/// Sleep functions can be altered before inserting the program in a sandbox.
/// Ensure that sleep functions have not been tampered with by accessing a
/// network time protocal server.
pub fn ntp_sleep_check() -> Option<usize> {
    let ntp_server = String::from("time.windows.com:123");

    /* Sleep for a random number of seconds. */
    let mut rng: SmallRng = rand::make_rng();
    let sleep_len = rng.random_range(10..=90);

    /* Consult the NTP server. */
    let response: ntp::packet::Packet = ntp::request(&ntp_server).ok()?;
    let old_ntp_time = response.transmit_time.sec;

    std::thread::sleep(std::time::Duration::from_secs(sleep_len));

    /* After the sleep check again. */
    let response: ntp::packet::Packet = ntp::request(&ntp_server).ok()?;
    let new_ntp_time = response.transmit_time.sec;

    return Some(
        new_ntp_time
            .abs_diff(old_ntp_time)
            .abs_diff(sleep_len as u32) as usize,
    );
}

/// Connect to a random news site and collect the date of a news article.
/// Compare that date to the current system data and see if they match.
pub fn news_site_date_check() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_connect_to_random_domain() {
        assert_eq!(connect_to_random_domain(), Some(0));
    }

    #[test]
    fn run_ntp_sleep_check() {
        assert_eq!(ntp_sleep_check(), Some(0));
    }

    #[test]
    fn run_news_site_date_check() {
        assert_eq!(news_site_date_check(), Some(0));
    }
}
