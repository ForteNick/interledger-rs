use super::HttpStore;
use bytes::BytesMut;
use futures::{
    future::{err, Either},
    Future, Stream,
};
use hyper::{body::Body, service::Service as HttpService, Error, Request, Response};
use interledger_packet::{Fulfill, Prepare, Reject};
use interledger_service::*;

pub struct HttpServerService<S, T> {
    next: S,
    store: T,
}

impl<S, T> HttpServerService<S, T>
where
    S: IncomingService<T::Account> + Clone + 'static,
    T: HttpStore,
{
    pub fn new(next: S, store: T) -> Self {
        HttpServerService { next: next, store }
    }

    // TODO support certificate-based authentication
    fn check_authorization(
        &self,
        request: &Request<Body>,
    ) -> impl Future<Item = T::Account, Error = Response<Body>> {
        let authorization: Option<&str> = request
            .headers()
            .get("authorization")
            .and_then(|auth| auth.to_str().ok());
        if authorization.is_some() {
            Either::A(
                self.store
                    .get_account_from_authorization(authorization.unwrap())
                    .map_err(|_err| Response::builder().status(401).body(Body::empty()).unwrap()),
            )
        } else {
            Either::B(err(Response::builder()
                .status(401)
                .body(Body::empty())
                .unwrap()))
        }
    }

    fn handle_http_request(
        &mut self,
        request: Request<Body>,
    ) -> impl Future<Item = Response<Body>, Error = Error> {
        let mut next = self.next.clone();
        self.check_authorization(&request)
            .and_then(|from_account| {
                parse_prepare_from_request(request).and_then(move |prepare| {
                    // Call the inner ILP service
                    next.handle_request(IncomingRequest {
                        from: from_account,
                        prepare,
                    })
                    .then(ilp_response_to_http_response)
                })
            })
            .then(|result| match result {
                Ok(response) => Ok(response),
                Err(response) => Ok(response),
            })
    }
}

impl<S, T> HttpService for HttpServerService<S, T>
where
    S: IncomingService<T::Account> + Clone + 'static,
    T: HttpStore + 'static,
{
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Box<Future<Item = Response<Self::ResBody>, Error = Self::Error> + 'static>;

    fn call(&mut self, request: Request<Self::ReqBody>) -> Self::Future {
        Box::new(self.handle_http_request(request))
    }
}

fn parse_prepare_from_request(
    request: Request<Body>,
) -> impl Future<Item = Prepare, Error = Response<Body>> + 'static {
    request
        .into_body()
        .concat2()
        .map_err(|_err| Response::builder().status(500).body(Body::empty()).unwrap())
        .and_then(|body| {
            let bytes = body.into_bytes().try_mut().unwrap_or_else(|bytes| {
                debug!("Copying bytes from incoming HTTP request into Prepare packet");
                BytesMut::from(bytes)
            });
            Prepare::try_from(bytes)
                .map_err(|_err| Response::builder().status(400).body(Body::empty()).unwrap())
        })
}

fn ilp_response_to_http_response(
    result: Result<Fulfill, Reject>,
) -> Result<Response<Body>, Response<Body>> {
    let bytes: BytesMut = match result {
        Ok(fulfill) => fulfill.into(),
        Err(reject) => reject.into(),
    };
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .body(bytes.freeze().into())
        .unwrap())
}
