use hawk::Error;

/// HawkError represents errors in parsing Authorization or ServerAuthorization headers.
#[derive(Debug)]
pub enum HawkError {
    /// No header was found, or a header was found but with the wrong scheme (that is, not "Hawk"),
    /// or multiple headers were found.
    NoHeader,

    /// A header was found, but parsing failed with the embedded error
    BadHawk(Error),
}
