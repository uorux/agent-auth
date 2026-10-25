//! The daemon channel from arbitrary bytes: handshake frames, and envelope
//! bodies read as each direction's messages. No input panics; a message
//! that parses re-serializes to one that parses to the same value.
#![no_main]

use agent_auth_wire::daemon::channel::{ChannelMessage, Incoming, parse};
use agent_auth_wire::daemon::handshake::{
    BrokerHandshake, DaemonHandshake, HelloParams, WelcomeParams,
};
use agent_auth_wire::daemon::host::{BrokerToHost, HostToBroker};
use agent_auth_wire::daemon::sandbox::{BrokerToSandbox, SandboxToBroker};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

fn direction<T: ChannelMessage + PartialEq + std::fmt::Debug>(body: &Map<String, Value>) {
    if let Incoming::Message(m) = parse::<T>(body.clone()) {
        let again = serde_json::to_value(&m).expect("a message serializes");
        let Value::Object(again) = again else {
            panic!("a message is an object")
        };
        match parse::<T>(again) {
            Incoming::Message(back) => assert_eq!(back, m),
            other => panic!("re-parse: {other:?}"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<BrokerHandshake>(data);
    let _ = serde_json::from_slice::<DaemonHandshake>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = HelloParams::from_text(text);
        let secs = WelcomeParams::heartbeat_secs(text);
        assert!((5..=300).contains(&secs));
    }
    if let Ok(body) = serde_json::from_slice::<Map<String, Value>>(data) {
        direction::<BrokerToHost>(&body);
        direction::<HostToBroker>(&body);
        direction::<BrokerToSandbox>(&body);
        direction::<SandboxToBroker>(&body);
    }
});
