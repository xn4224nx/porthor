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
pub fn connect_to_random_domain() -> Option<f32> {
    let total_conns = 10;
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
    for _ in 0..total_conns {
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

    /* Return the fraction of sites that connected. */
    return Some((successful_connections as f32) / (total_conns as f32));
}

/// Sleep functions can be altered before inserting the program in a sandbox.
/// Ensure that sleep functions have not been tampered with by accessing a
/// network time protocal server.
pub fn ntp_sleep_check() -> Option<f32> {
    let ntp_server = String::from("time.windows.com:123");
    let margin_err_secs = 10;

    /* Sleep for a random number of seconds. */
    let mut rng: SmallRng = rand::make_rng();
    let sleep_len = rng.random_range(10..=90);

    /* Consult the NTP server. */
    let response: ntp::packet::Packet = ntp::request(&ntp_server).ok()?;
    let old_ntp_time = response.transmit_time.sec;

    std::thread::sleep(std::time::Duration::from_secs(sleep_len));

    /* After the sleep check again. */
    let response: ntp::packet::Packet = ntp::request(&ntp_server).ok()?;
    let ntp_time_diff = response.transmit_time.sec.abs_diff(old_ntp_time);

    return Some(
        (ntp_time_diff
            .abs_diff(sleep_len as u32)
            .saturating_sub(margin_err_secs) as f32
            / sleep_len as f32)
            .clamp(0.0, 1.0),
    );
}

/// Connect to a random news site and collect the date of a news article.
/// Compare that date to the current system data and see if they match.
pub fn news_site_date_check() -> Option<f32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_connect_to_random_domain() {
        assert_eq!(connect_to_random_domain(), Some(0.0));
    }

    #[test]
    fn run_ntp_sleep_check() {
        assert_eq!(ntp_sleep_check(), Some(0.0));
    }

    #[test]
    fn run_news_site_date_check() {
        assert_eq!(news_site_date_check(), Some(0.0));
    }
}
