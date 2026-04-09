/*
 * NETWORK BASED DETECTION
 * =======================
 *
 * Functions to detect a sandbox by making network connections.
 */

/// Sandboxes will allow the executable to connect to any doamin and pretend
/// that it was successful. This function connects to domains that do not exist.
/// If these connections are successful the executable is most likely in a
/// sandbox.
pub fn connect_to_random_domain() -> Option<usize> {
    None
}

/// Sleep functions can be altered before inserting the program in a sandbox.
/// Ensure that sleep functions have not been tampered with by accessing a
/// network time protocal server.
pub fn ntp_sleep_check() -> Option<usize> {
    None
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
    fn run_iconnect_to_random_domain() {
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
