use std::error::Error as StdError;
use btp_packet::{BtpMessage, BtpResponse, Serializable};
use tokio_tungstenite::{connect_async as connect_websocket, WebSocketStream, MaybeTlsStream};
use tungstenite::{Error as WebSocketError};
use tokio_tcp::TcpStream;
use futures::Future;
use futures::future::{ok};
use futures::stream::{Stream, SplitSink, SplitStream};
use url::{Url, ParseError};

pub trait Plugin {
  fn send_data(&mut self, data: &[u8]) -> Box<Future<Item = (Self, Vec<u8>), Error = ()>>;
  fn send_money(&mut self, amount: u64) -> Box<Future<Item = Self, Error = ()>>;
}

pub struct PluginBtp {
  server: Url,
  ws_sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>>,
  ws_stream: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl Plugin for PluginBtp {
  fn send_data(&mut self, data: &[u8]) -> Box<Future<Item = (Self, Vec<u8>), Error = ()>> {
    let future = ok(()).and_then(|_| {
      Ok((self, vec![]))
    });
    Box::new(future)
  }

  fn send_money(&mut self, amount: u64) -> Box<Future<Item = Self, Error = ()>> {
    let future = ok(()).and_then(|_| {
      Ok(self)
    });
    Box::new(future)
  }
}

pub fn connect_async(server: &str) -> Box<Future<Item = PluginBtp, Error = ()> + 'static + Send> {
  let server = Url::parse(server).unwrap();
  let future = connect_websocket(server).and_then(move |(ws_stream, _ )| {
    println!("Connected to ${}", server);
    let (ws_sink, ws_stream) = ws_stream.split();
    Ok(PluginBtp {
      server,
      ws_sink,
      ws_stream,
    })
  }).map_err(|e| {
    println!("Error connecting: {}", e);
  });
  Box::new(future)
}