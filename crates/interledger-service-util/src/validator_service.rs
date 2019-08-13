use futures::{future::err, Future};
use hex;
use interledger_packet::{Address, ErrorCode, RejectBuilder};
use interledger_service::{
    Account, BoxedIlpFuture, IncomingRequest, IncomingService, OutgoingRequest, OutgoingService,
};
use log::error;
use ring::digest::{digest, SHA256};
use std::marker::PhantomData;
use std::time::{Duration, SystemTime};
use tokio::prelude::FutureExt;

const DEFAULT_MAXIMUM_EXPIRY_DURATION: u64 = 60000; // seconds

/// # Validator Service
///
/// Incoming or Outgoing Service responsible for rejecting timed out
/// requests and checking that fulfillments received match the `execution_condition` from the original `Prepare` packets.
/// Forwards everything else.
///
#[derive(Clone)]
pub struct ValidatorService<IO, A> {
    ilp_address: Address,
    next: IO,
    account_type: PhantomData<A>,
    maximum_expiry_duration: u64,
}

impl<I, A> ValidatorService<I, A>
where
    I: IncomingService<A>,
    A: Account,
{
    pub fn incoming(ilp_address: Address, next: I) -> Self {
        ValidatorService {
            ilp_address,
            next,
            account_type: PhantomData,
            maximum_expiry_duration: DEFAULT_MAXIMUM_EXPIRY_DURATION,
        }
    }

    pub fn set_max_expiry_duration(&mut self, millis: u64) -> &mut Self {
        self.maximum_expiry_duration = millis;
        self
    }
}

impl<O, A> ValidatorService<O, A>
where
    O: OutgoingService<A>,
    A: Account,
{
    pub fn outgoing(ilp_address: Address, next: O) -> Self {
        ValidatorService {
            ilp_address,
            next,
            account_type: PhantomData,
            maximum_expiry_duration: DEFAULT_MAXIMUM_EXPIRY_DURATION,
        }
    }
}

impl<I, A> IncomingService<A> for ValidatorService<I, A>
where
    I: IncomingService<A>,
    A: Account,
{
    type Future = BoxedIlpFuture;

    /// On receiving a request:
    /// 1. If the prepare packet in the request is not expired, forward it, otherwise return a reject
    fn handle_request(&mut self, request: IncomingRequest<A>) -> Self::Future {
        let now = SystemTime::now();
        if request.prepare.expires_at() < now {
            error!(
                "Incoming packet expired {}ms ago at {:?} (time now: {:?})",
                SystemTime::now()
                    .duration_since(request.prepare.expires_at())
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_millis(),
                request.prepare.expires_at(),
                now
            );
            let result = Box::new(err(RejectBuilder {
                code: ErrorCode::R00_TRANSFER_TIMED_OUT,
                message: &[],
                triggered_by: Some(&self.ilp_address),
                data: &[],
            }
            .build()));
            Box::new(result)
        } else if now + Duration::from_millis(self.maximum_expiry_duration)
            < request.prepare.expires_at()
        {
            error!("Incoming packet's expiry is too long in the future (it would place funds on hold for too long). Packet expires in {}ms, maximum is {}",
            request.prepare.expires_at().duration_since(now).unwrap_or_else(|_| Duration::from_secs(0)).as_millis(), self.maximum_expiry_duration);
            let result = Box::new(err(RejectBuilder {
                // TODO should this be a different error code?
                // We don't currently have one specifically for this case
                code: ErrorCode::F00_BAD_REQUEST,
                message: b"Packet expires too far in the future",
                triggered_by: Some(&self.ilp_address),
                data: &[],
            }
            .build()));
            Box::new(result)
        } else {
            Box::new(self.next.handle_request(request))
        }
    }
}

impl<O, A> OutgoingService<A> for ValidatorService<O, A>
where
    O: OutgoingService<A>,
    A: Account,
{
    type Future = BoxedIlpFuture;

    /// On sending a request:
    /// 1. If the outgoing packet has expired, return a reject with the appropriate ErrorCode
    /// 1. Tries to forward the request
    ///     - If no response is received before the prepare packet's expiration, it assumes that the outgoing request has timed out.
    ///     - If no timeout occurred, but still errored it will just return the reject
    ///     - If the forwarding is successful, it should receive a fulfill packet. Depending on if the hash of the fulfillment condition inside the fulfill is a preimage of the condition of the prepare:
    ///         - return the fulfill if it matches
    ///         - otherwise reject
    fn send_request(&mut self, request: OutgoingRequest<A>) -> Self::Future {
        let mut condition: [u8; 32] = [0; 32];
        condition[..].copy_from_slice(request.prepare.execution_condition()); // why?
        let ilp_address = self.ilp_address.clone();
        let ilp_address_clone = ilp_address.clone();

        if let Ok(time_left) = request
            .prepare
            .expires_at()
            .duration_since(SystemTime::now())
        {
            Box::new(
                self.next
                    .send_request(request)
                    .timeout(time_left)
                    .map_err(move |err| {
                        // If the error was caused by the timer, into_inner will return None
                        if let Some(reject) = err.into_inner() {
                            reject
                        } else {
                            error!(
                                "Outgoing request timed out after {}ms",
                                time_left.as_millis()
                            );
                            RejectBuilder {
                                code: ErrorCode::R00_TRANSFER_TIMED_OUT,
                                message: &[],
                                triggered_by: Some(&ilp_address),
                                data: &[],
                            }
                            .build()
                        }
                    })
                    .and_then(move |fulfill| {
                        let generated_condition = digest(&SHA256, fulfill.fulfillment());
                        if generated_condition.as_ref() == condition {
                            Ok(fulfill)
                        } else {
                            error!("Fulfillment did not match condition. Fulfillment: {}, hash: {}, actual condition: {}", hex::encode(fulfill.fulfillment()), hex::encode(generated_condition), hex::encode(condition));
                            Err(RejectBuilder {
                                code: ErrorCode::F09_INVALID_PEER_RESPONSE,
                                message: b"Fulfillment did not match condition",
                                triggered_by: Some(&ilp_address_clone),
                                data: &[],
                            }
                            .build())
                        }
                    }),
            )
        } else {
            error!(
                "Outgoing packet expired {}ms ago",
                SystemTime::now()
                    .duration_since(request.prepare.expires_at())
                    .unwrap_or_default()
                    .as_millis(),
            );
            // Already expired
            Box::new(err(RejectBuilder {
                code: ErrorCode::R00_TRANSFER_TIMED_OUT,
                message: &[],
                triggered_by: Some(&ilp_address),
                data: &[],
            }
            .build()))
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct TestAccount(u64);
#[cfg(test)]
impl Account for TestAccount {
    type AccountId = u64;

    fn id(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod incoming {
    use super::*;
    use interledger_packet::*;
    use interledger_service::incoming_service_fn;
    use std::str::FromStr;
    use std::{
        sync::{Arc, Mutex},
        time::SystemTime,
    };

    #[test]
    fn lets_through_valid_incoming_packet() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        let mut validator = ValidatorService::incoming(
            Address::from_str("example.connector").unwrap(),
            incoming_service_fn(move |request| {
                requests_clone.lock().unwrap().push(request);
                Ok(FulfillBuilder {
                    fulfillment: &[0; 32],
                    data: b"test data",
                }
                .build())
            }),
        );
        let result = validator
            .handle_request(IncomingRequest {
                from: TestAccount(0),
                prepare: PrepareBuilder {
                    destination: Address::from_str("example.destination").unwrap(),
                    amount: 100,
                    expires_at: SystemTime::now() + Duration::from_secs(30),
                    execution_condition: &[
                        102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142,
                        32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
                    ],
                    data: b"test data",
                }
                .build(),
            })
            .wait();

        assert_eq!(requests.lock().unwrap().len(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_expired_incoming_packet() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        let mut validator = ValidatorService::incoming(
            Address::from_str("example.connector").unwrap(),
            incoming_service_fn(move |request| {
                requests_clone.lock().unwrap().push(request);
                Ok(FulfillBuilder {
                    fulfillment: &[0; 32],
                    data: b"test data",
                }
                .build())
            }),
        );
        let result = validator
            .handle_request(IncomingRequest {
                from: TestAccount(0),
                prepare: PrepareBuilder {
                    destination: Address::from_str("example.destination").unwrap(),
                    amount: 100,
                    expires_at: SystemTime::now() - Duration::from_secs(30),
                    execution_condition: &[
                        102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142,
                        32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
                    ],
                    data: b"test data",
                }
                .build(),
            })
            .wait();

        assert!(requests.lock().unwrap().is_empty());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            ErrorCode::R00_TRANSFER_TIMED_OUT
        );
    }

    #[test]
    fn rejects_packet_with_too_long_expiry() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        let mut validator = ValidatorService::incoming(
            Address::from_str("example.connector").unwrap(),
            incoming_service_fn(move |request| {
                requests_clone.lock().unwrap().push(request);
                Ok(FulfillBuilder {
                    fulfillment: &[0; 32],
                    data: b"test data",
                }
                .build())
            }),
        );
        let result = validator
            .handle_request(IncomingRequest {
                from: TestAccount(0),
                prepare: PrepareBuilder {
                    destination: Address::from_str("example.destination").unwrap(),
                    amount: 100,
                    expires_at: SystemTime::now() + Duration::from_secs(61),
                    execution_condition: &[
                        102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142,
                        32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
                    ],
                    data: b"test data",
                }
                .build(),
            })
            .wait();

        assert!(requests.lock().unwrap().is_empty());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::F00_BAD_REQUEST);
    }
}

#[cfg(test)]
mod outgoing {
    use super::*;
    use interledger_packet::*;
    use interledger_service::outgoing_service_fn;
    use std::str::FromStr;
    use std::{
        sync::{Arc, Mutex},
        time::SystemTime,
    };

    #[test]
    fn lets_through_valid_outgoing_response() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        let mut validator = ValidatorService::outgoing(
            Address::from_str("example.connector").unwrap(),
            outgoing_service_fn(move |request| {
                requests_clone.lock().unwrap().push(request);
                Ok(FulfillBuilder {
                    fulfillment: &[0; 32],
                    data: b"test data",
                }
                .build())
            }),
        );
        let result = validator
            .send_request(OutgoingRequest {
                from: TestAccount(1),
                to: TestAccount(2),
                original_amount: 100,
                prepare: PrepareBuilder {
                    destination: Address::from_str("example.destination").unwrap(),
                    amount: 100,
                    expires_at: SystemTime::now() + Duration::from_secs(30),
                    execution_condition: &[
                        102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142,
                        32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
                    ],
                    data: b"test data",
                }
                .build(),
            })
            .wait();

        assert_eq!(requests.lock().unwrap().len(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn returns_reject_instead_of_invalid_fulfillment() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = requests.clone();
        let mut validator = ValidatorService::outgoing(
            Address::from_str("example.connector").unwrap(),
            outgoing_service_fn(move |request| {
                requests_clone.lock().unwrap().push(request);
                Ok(FulfillBuilder {
                    fulfillment: &[1; 32],
                    data: b"test data",
                }
                .build())
            }),
        );
        let result = validator
            .send_request(OutgoingRequest {
                from: TestAccount(1),
                to: TestAccount(2),
                original_amount: 100,
                prepare: PrepareBuilder {
                    destination: Address::from_str("example.destination").unwrap(),
                    amount: 100,
                    expires_at: SystemTime::now() + Duration::from_secs(30),
                    execution_condition: &[
                        102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142,
                        32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
                    ],
                    data: b"test data",
                }
                .build(),
            })
            .wait();

        assert_eq!(requests.lock().unwrap().len(), 1);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code(),
            ErrorCode::F09_INVALID_PEER_RESPONSE
        );
    }
}
