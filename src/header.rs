use super::HawkError;
use hawk::Header;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;
use std::ops::Deref;
use std::str::FromStr;

// A base type for the two public header types
#[derive(Debug)]
struct AuthzHeader(Header);

fn parse_header<'a, 'r>(
    request: &'a Request<'r>,
    header_name: &str,
) -> request::Outcome<AuthzHeader, HawkError> {
    // extract the header from the request, checking that there is exactly one
    let hdrs: Vec<_> = request.headers().get(header_name).collect();
    let hdr = match hdrs.len() {
        0 => return Outcome::Failure((Status::Unauthorized, HawkError::NoHeader)),
        1 => hdrs[0],
        _ => return Outcome::Failure((Status::BadRequest, HawkError::NoHeader)),
    };

    // split 'Hawk <value>' (case-insensitive)
    let hawk = match hdr.find(' ') {
        Some(i) => {
            if hdr[..i].eq_ignore_ascii_case("hawk") {
                &hdr[i + 1..]
            } else {
                return Outcome::Failure((Status::Unauthorized, HawkError::NoHeader));
            }
        }
        None => return Outcome::Failure((Status::Unauthorized, HawkError::NoHeader)),
    };

    // parse the hawk-specific value
    match Header::from_str(hawk) {
        Ok(h) => Outcome::Success(AuthzHeader(h)),
        Err(e) => Outcome::Failure((Status::Unauthorized, HawkError::BadHawk(e))),
    }
}

/// A request guard to require an "Authorization" header containing a syntactically valid Hawk
/// value.  Note that it is up to the user to validate the header (perhaps by wrapping this
/// type in another, application-specific request guard).
#[derive(Debug)]
pub struct AuthorizationHeader(AuthzHeader);

impl<'a, 'r> FromRequest<'a, 'r> for AuthorizationHeader {
    type Error = HawkError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        parse_header(request, "authorization").map(|h| AuthorizationHeader(h))
    }
}

impl Deref for AuthorizationHeader {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &(self.0).0
    }
}

/// Similar to `AuthorizationHeader`, but looking instead in the Hawk-specific
/// "Servier-Authorization" header.
#[derive(Debug)]
pub struct ServerAuthorizationHeader(AuthzHeader);

impl<'a, 'r> FromRequest<'a, 'r> for ServerAuthorizationHeader {
    type Error = HawkError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        parse_header(request, "server-authorization").map(|h| ServerAuthorizationHeader(h))
    }
}

impl Deref for ServerAuthorizationHeader {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &(self.0).0
    }
}

#[cfg(test)]
mod test {
    use super::{AuthorizationHeader, HawkError, ServerAuthorizationHeader};
    use rocket::http::{Header, Status};
    use rocket::local::{Client, LocalRequest};
    use rocket::response::status;
    use rocket::Route;

    const HEADER: &str = "id=\"xyz\", ts=\"1353832234\", nonce=\"abc\", mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"";

    // create a rocket and a client, then assert that the response is OK
    fn check_route(routes: Vec<Route>, setup_request: impl FnOnce(LocalRequest) -> LocalRequest) {
        let rocket = rocket::ignite().mount("/", routes);
        let client = Client::new(rocket).unwrap();
        let mut res = setup_request(client.get("/")).dispatch();
        assert_eq!(
            (res.status(), res.body_string()),
            (Status::Ok, Some("ok".into()))
        );
    }

    #[test]
    fn test_noheader() {
        #[get("/")]
        fn method(hawk: Result<AuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Err(HawkError::NoHeader) => status::Custom(Status::Ok, "ok".to_string()),
                _ => status::Custom(Status::BadRequest, "did not get NoHeader".to_string()),
            }
        }

        check_route(routes![method], |c| c);
    }

    #[test]
    fn test_header_diff_scheme() {
        #[get("/")]
        fn method(hawk: Result<AuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Err(HawkError::NoHeader) => status::Custom(Status::Ok, "ok".to_string()),
                _ => status::Custom(Status::BadRequest, "did not get NoHeader".to_string()),
            }
        }

        check_route(routes![method], |c| {
            c.header(Header::new("Authorization", "bearer 123"))
        });
    }

    #[test]
    fn test_header_bad_header_no_space() {
        #[get("/")]
        fn method(hawk: Result<AuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Err(HawkError::NoHeader) => status::Custom(Status::Ok, "ok".to_string()),
                _ => status::Custom(Status::BadRequest, "did not get NoHeader".to_string()),
            }
        }

        check_route(routes![method], |c| {
            c.header(Header::new("Authorization", "abcdefg"))
        });
    }

    #[test]
    fn test_header_bad_header_bad_hawk() {
        #[get("/")]
        fn method(hawk: Result<AuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Err(HawkError::BadHawk(hawk::Error(hawk::ErrorKind::Msg(ref msg), _)))
                    if msg == "Invalid Hawk field nosuchfield" =>
                {
                    status::Custom(Status::Ok, "ok".to_string())
                }
                _ => status::Custom(Status::BadRequest, "did not get BadHawk".to_string()),
            }
        }

        check_route(routes![method], |c| {
            c.header(Header::new("Authorization", "Hawk nosuchfield=\"abc\""))
        });
    }

    #[test]
    fn test_header_multiple_header() {
        #[get("/")]
        fn method(hawk: Result<AuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Err(HawkError::NoHeader) => status::Custom(Status::Ok, "ok".to_string()),
                _ => status::Custom(Status::BadRequest, "did not get NoHeader".to_string()),
            }
        }

        check_route(routes![method], |c| {
            // note that even two Hawk headers are not allowed
            c.header(Header::new("Authorization", format!("Hawk {}", HEADER)))
                .header(Header::new("Authorization", format!("Hawk {}", HEADER)))
        });
    }

    #[test]
    fn test_header_good_header() {
        #[get("/")]
        fn method(hawk: Result<AuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Ok(ref h) if (h.id == Some("xyz".to_string())) => {
                    status::Custom(Status::Ok, "ok".to_string())
                }
                _ => status::Custom(Status::BadRequest, "did not get header".to_string()),
            }
        }

        check_route(routes![method], |c| {
            c.header(Header::new("Authorization", format!("Hawk {}", HEADER)))
        });
    }

    // Just one test for ServerAuthorization, since it shares its implementation with
    // Authorization.
    #[test]
    fn test_header_good_server_auth_header() {
        #[get("/")]
        fn method(hawk: Result<ServerAuthorizationHeader, HawkError>) -> status::Custom<String> {
            match hawk {
                Ok(ref h) if (h.id == Some("xyz".to_string())) => {
                    status::Custom(Status::Ok, "ok".to_string())
                }
                _ => status::Custom(Status::BadRequest, "did not get header".to_string()),
            }
        }

        check_route(routes![method], |c| {
            c.header(Header::new(
                "Server-Authorization",
                format!("Hawk {}", HEADER),
            ))
        });
    }
}
