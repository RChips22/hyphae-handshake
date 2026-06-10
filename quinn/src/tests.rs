use std::{net::UdpSocket, sync::Arc};

use hyphae_handshake::crypto::SyncCryptoBackend;
use hyphae_handshake::{customization::SyncHandshakeConfig, quic::HYPHAE_H_V1_QUIC_V1_VERSION};
use quinn_proto::{crypto::ServerConfig as CryptoServerConfig, transport_parameters::TransportParameters, ConnectionId, Side};
use rand_core::OsRng;
use tokio::time::Duration;

use crate::RustCryptoBackend;
use crate::HandshakeBuilder;
use crate::V1_PATTERN;
use crate::api::{HandshakeError, HandshakeOptions, client_connect, server_accept};
use crate::buffer::Buffer;
use crate::customization::{HandshakeInfo, PayloadDriver};
use crate::helper::{hyphae_client_endpoint, hyphae_server_endpoint};
use crate::{config::HyphaeCryptoConfig, customization::{HyphaePeerIdentity, QuinnHandshakeData}};

#[tokio::test]
async fn quinn_echo_test() {
    quinn_echo_test_proto(V1_PATTERN).await;
}

async fn quinn_echo_test_proto(protocol: &str) {
    let initiator_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let client_crypto = 
        HandshakeBuilder::new(protocol)
        .with_static_key(&initiator_s)
        .build(RustCryptoBackend)
        .unwrap();
    
    let responder_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let server_crypto = 
        HandshakeBuilder::new(protocol)
        .with_static_key(&responder_s)
        .build(RustCryptoBackend)
        .unwrap();

    echo_server_test(
        client_crypto,
        server_crypto,
        Some(RustCryptoBackend.public_key(&initiator_s).to_vec()), 
        Some(RustCryptoBackend.public_key(&responder_s).to_vec())
    ).await;
}

#[derive(Clone)]
struct Msg1PayloadDriver {
    payload: Vec<u8>,
}

impl PayloadDriver for Msg1PayloadDriver {
    fn write_noise_payload(&mut self, payload_buffer: &mut impl Buffer, noise_handshake: &mut impl HandshakeInfo) -> Result<(), crate::Error> {
        if noise_handshake.is_initiator() && noise_handshake.handshake_position() == Some(1) {
            payload_buffer.extend_from_slice(self.payload.as_slice())?;
        }
        Ok(())
    }

    fn read_noise_payload(&mut self, _payload: &[u8], _noise_handshake: &mut impl HandshakeInfo) -> Result<(), crate::Error> {
        Ok(())
    }
}

impl QuinnHandshakeData for Msg1PayloadDriver {
    type HandshakeData = ();

    fn handshake_data(&self) -> Option<Self::HandshakeData> {
        Some(())
    }

    fn peer_identity(&self, remote_public: Option<&[u8]>, final_handshake_hash: Option<&[u8]>) -> Option<HyphaePeerIdentity> {
        Some(HyphaePeerIdentity::new(remote_public, final_handshake_hash))
    }
}

#[tokio::test]
async fn handshake_result_hash_and_peer_static() {
    let client_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let server_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let expected_client_pub = RustCryptoBackend.public_key(&client_s);
    let expected_server_pub = RustCryptoBackend.public_key(&server_s);

    let client_crypto = HandshakeBuilder::new_v1()
        .with_static_key(&client_s)
        .build(RustCryptoBackend)
        .unwrap();

    let server_crypto = HandshakeBuilder::new_v1()
        .with_static_key(&server_s)
        .build(RustCryptoBackend)
        .unwrap();

    let listen_addr = "[0::1]:0";
    let server_socket = UdpSocket::bind(listen_addr).unwrap();
    let server_endpoint = hyphae_server_endpoint(server_crypto, None, server_socket).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = async move {
        let (_conn, result) = server_accept(&server_endpoint, HandshakeOptions::default()).await.unwrap();
        result
    };

    let client_task = async move {
        let client_socket = UdpSocket::bind(listen_addr).unwrap();
        let client_endpoint = hyphae_client_endpoint(client_crypto, None, client_socket).unwrap();
        let (_conn, result) = client_connect(&client_endpoint, server_addr, "", HandshakeOptions::default()).await.unwrap();
        result
    };

    let (server_result, client_result) = tokio::join!(server_task, client_task);

    assert_eq!(server_result.handshake_hash, client_result.handshake_hash, "handshake hashes should match");
    assert_eq!(client_result.peer_static, Some(expected_server_pub), "client should observe responder static");
    assert_eq!(server_result.peer_static, Some(expected_client_pub), "server should observe initiator static");
}

#[tokio::test]
async fn msg1_payload_roundtrip() {
    let payload = b"exchange-payload-v1".to_vec();
    let client_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let server_s = RustCryptoBackend.new_secret_key(&mut OsRng);

    let client_crypto = HandshakeBuilder::new_v1()
        .with_static_key(&client_s)
        .with_cloned_payload_driver(Msg1PayloadDriver { payload: payload.clone() })
        .build(RustCryptoBackend)
        .unwrap();

    let server_crypto = HandshakeBuilder::new_v1()
        .with_static_key(&server_s)
        .with_cloned_payload_driver(Msg1PayloadDriver { payload: Vec::new() })
        .build(RustCryptoBackend)
        .unwrap();

    let listen_addr = "[0::1]:0";
    let server_socket = UdpSocket::bind(listen_addr).unwrap();
    let server_endpoint = hyphae_server_endpoint(server_crypto, None, server_socket).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = async move {
        let (_conn, result) = server_accept(&server_endpoint, HandshakeOptions::default()).await.unwrap();
        result
    };

    let client_task = async move {
        let client_socket = UdpSocket::bind(listen_addr).unwrap();
        let client_endpoint = hyphae_client_endpoint(client_crypto, None, client_socket).unwrap();
        let (_conn, result) = client_connect(&client_endpoint, server_addr, "", HandshakeOptions::default()).await.unwrap();
        result
    };

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    assert_eq!(server_result.msg1_payload, Some(payload.clone()));
    assert_eq!(client_result.msg1_payload, Some(payload));
}

#[tokio::test]
async fn handshake_timeout_is_enforced() {
    let server_crypto = HandshakeBuilder::new_v1().build(RustCryptoBackend).unwrap();
    let listen_addr = "[0::1]:0";
    let server_socket = UdpSocket::bind(listen_addr).unwrap();
    let server_endpoint = hyphae_server_endpoint(server_crypto, None, server_socket).unwrap();

    let mut options = HandshakeOptions::default();
    options.timeout = Duration::from_millis(30);

    let result = server_accept(&server_endpoint, options).await;
    assert!(matches!(result, Err(HandshakeError::Timeout)));
}

#[tokio::test]
async fn oversize_payload_is_rejected() {
    let payload = vec![7u8; 200];
    let client_s = RustCryptoBackend.new_secret_key(&mut OsRng);
    let server_s = RustCryptoBackend.new_secret_key(&mut OsRng);

    let client_crypto = HandshakeBuilder::new_v1()
        .with_static_key(&client_s)
        .with_cloned_payload_driver(Msg1PayloadDriver { payload: payload.clone() })
        .build(RustCryptoBackend)
        .unwrap();

    let server_crypto = HandshakeBuilder::new_v1()
        .with_static_key(&server_s)
        .with_cloned_payload_driver(Msg1PayloadDriver { payload: Vec::new() })
        .build(RustCryptoBackend)
        .unwrap();

    let listen_addr = "[0::1]:0";
    let server_socket = UdpSocket::bind(listen_addr).unwrap();
    let server_endpoint = hyphae_server_endpoint(server_crypto, None, server_socket).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = async move {
        let _ = server_accept(&server_endpoint, HandshakeOptions::default()).await;
    };

    let client_task = async move {
        let client_socket = UdpSocket::bind(listen_addr).unwrap();
        let client_endpoint = hyphae_client_endpoint(client_crypto, None, client_socket).unwrap();
    let mut options = HandshakeOptions::default();
    options.max_payload_len = 100;
        client_connect(&client_endpoint, server_addr, "", options).await
    };

    let (_server_result, client_result) = tokio::join!(server_task, client_task);
    assert!(matches!(client_result, Err(HandshakeError::Io(_)) | Err(HandshakeError::Payload(_))));
}

async fn echo_server_test<IC, IB, RC, RB> (
    client_crypto: Arc<HyphaeCryptoConfig<IC, IB>>,
    server_crypto: Arc<HyphaeCryptoConfig<RC, RB>>,
    client_public: Option<Vec<u8>>,
    server_public: Option<Vec<u8>>,
)
where 
    IC: SyncHandshakeConfig,
    IC::Driver: QuinnHandshakeData,
    IB: SyncCryptoBackend,
    RC: SyncHandshakeConfig,
    RC::Driver: QuinnHandshakeData,
    RB: SyncCryptoBackend,
{
    let listen_addr = "[0::1]:0";
    let echo_payload = b"hello hyphae-h-v1.quic-v1.";

    let socket = UdpSocket::bind(listen_addr).unwrap();
    let server_endpoint = hyphae_server_endpoint(server_crypto, None, socket).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = async move {
        let conn = server_endpoint.accept().await.unwrap().await.unwrap();
        let handshake_rs = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap().remote_public;

        let mut recv = conn.accept_uni().await.unwrap();

        let mut buffer = vec![0u8; echo_payload.len()];
        recv.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, echo_payload);

        handshake_rs
    };

    let client_task = async move {
        let socket = UdpSocket::bind(listen_addr).unwrap();
        let endpoint = hyphae_client_endpoint(client_crypto, None, socket).unwrap();

        let conn = endpoint.connect(server_addr, "").unwrap().await.unwrap();
        let handshake_rs = conn.peer_identity().unwrap().downcast::<HyphaePeerIdentity>().unwrap().remote_public;

        let mut send = conn.open_uni().await.unwrap();
        send.write_all(echo_payload).await.unwrap();
        send.finish().unwrap();
        send.stopped().await.unwrap();

        handshake_rs
    };

    let (client_handshake_rs, server_handshake_rs) = tokio::join!(client_task, server_task);
    assert_eq!(client_handshake_rs, server_public, "server had unexpected public key");
    assert_eq!(server_handshake_rs, client_public, "client had unexpected public key");
}

#[test]
fn retry_tag_test() {
    let protocol = V1_PATTERN;
    let config = HandshakeBuilder::new(protocol).build(RustCryptoBackend).unwrap();

    let orig_dcid = ConnectionId::new(b"12345");
    let retry_packet_no_tag = b"abcdefg";

    let tag = config.retry_tag(HYPHAE_H_V1_QUIC_V1_VERSION, &orig_dcid, retry_packet_no_tag);
    
    let mut retry_packet_with_tag = Vec::new();
    retry_packet_with_tag.extend_from_slice(retry_packet_no_tag);
    retry_packet_with_tag.extend_from_slice(&tag);

    let start_session = CryptoServerConfig::start_session(config.clone(), HYPHAE_H_V1_QUIC_V1_VERSION, &fake_server_params());
    let session = start_session;
    assert!(session.is_valid_retry(&orig_dcid, &retry_packet_with_tag[0..2], &retry_packet_with_tag[2..]));
    retry_packet_with_tag[0] = !retry_packet_with_tag[0];
    assert!(!session.is_valid_retry(&orig_dcid, &retry_packet_with_tag[0..2], &retry_packet_with_tag[2..]));
}

fn fake_server_params() -> TransportParameters {
    let params = [
        1u8, 4, 128, 0, 117, 48, 3, 2, 69, 192, 4, 8, 255, 255, 255,
        255, 255, 255, 255, 255, 5, 4, 128, 19, 18, 208, 6, 4, 128,
        19, 18, 208, 7, 4, 128, 19, 18, 208, 8, 2, 64, 100, 9, 2,
        64, 100, 14, 1, 5, 64, 182, 0, 32, 4, 128, 0, 255, 255, 15,
        8, 107, 252, 186, 239, 84, 56, 32, 254, 106, 178, 0, 192, 0,
        0, 0, 255, 4, 222, 27, 2, 67, 232
    ];

    TransportParameters::read(Side::Server, &mut params.as_slice()).unwrap()
}
