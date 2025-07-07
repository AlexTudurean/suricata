/* Copyright (C) 2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use super::parser;
use crate::applayer::*;
use crate::conf::conf_get;
use crate::core::{ALPROTO_UNKNOWN, IPPROTO_TCP};
use crate::flow::Flow;
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

static mut AMQP_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_AMQP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum AMQPEvent {
    TooManyTransactions,
    InvalidFrame,
    ProtocolVersionMismatch,
    InvalidMethod,
}

// AMQP Protocol Constants
const AMQP_PROTOCOL_HEADER: &[u8] = b"AMQP";
const AMQP_FRAME_METHOD: u8 = 1;
const AMQP_FRAME_HEADER: u8 = 2;
const AMQP_FRAME_BODY: u8 = 3;
const AMQP_FRAME_HEARTBEAT: u8 = 8;

// AMQP 0.9.1 class IDs
const AMQP_CLASS_CONNECTION: u16 = 10;
const AMQP_CLASS_CHANNEL: u16 = 20;
const AMQP_CLASS_EXCHANGE: u16 = 40;
const AMQP_CLASS_QUEUE: u16 = 50;
const AMQP_CLASS_BASIC: u16 = 60;

#[derive(Debug, Clone)]
pub enum AMQPFrameType {
    Method = 1,
    Header = 2,
    Body = 3,
    Heartbeat = 8,
}

#[derive(Debug, Clone)]
pub struct AMQPFrame {
    pub frame_type: u8,
    pub channel: u16,
    pub length: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AMQPMethod {
    pub class_id: u16,
    pub method_id: u16,
    pub arguments: Vec<u8>,
}

pub struct AMQPTransaction {
    tx_id: u64,
    pub method_class: Option<u16>,
    pub method_id: Option<u16>,
    pub channel: u16,
    pub request_frame: Option<AMQPFrame>,
    pub response_frame: Option<AMQPFrame>,
    pub properties: Option<Vec<u8>>,
    pub body: Option<Vec<u8>>,

    tx_data: AppLayerTxData,
}

impl Default for AMQPTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl AMQPTransaction {
    pub fn new() -> AMQPTransaction {
        Self {
            tx_id: 0,
            method_class: None,
            method_id: None,
            channel: 0,
            request_frame: None,
            response_frame: None,
            properties: None,
            body: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for AMQPTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct AMQPState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<AMQPTransaction>,
    request_gap: bool,
    response_gap: bool,
    
    // AMQP connection state
    pub protocol_header_seen: bool,
    pub major_version: u8,
    pub minor_version: u8,
    pub revision: u8,
    pub max_frame_size: u32,
    pub heartbeat_interval: u16,
}

impl State<AMQPTransaction> for AMQPState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&AMQPTransaction> {
        self.transactions.get(index)
    }
}

impl AMQPState {
    pub fn new() -> Self {
        Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            request_gap: false,
            response_gap: false,
            protocol_header_seen: false,
            major_version: 0,
            minor_version: 9,
            revision: 1,
            max_frame_size: 131072, // Default max frame size
            heartbeat_interval: 0,
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&AMQPTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> AMQPTransaction {
        let mut tx = AMQPTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut AMQPTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response_frame.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if parser::probe_amqp(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For AMQP, we'll try to find the next frame boundary.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        
        // Check for AMQP protocol header first
        if !self.protocol_header_seen {
            match parser::parse_protocol_header(start) {
                Ok((rem, header)) => {
                    self.protocol_header_seen = true;
                    self.major_version = header.0;
                    self.minor_version = header.1;
                    self.revision = header.2;
                    start = rem;
                    SCLogNotice!("AMQP Protocol Header: {}.{}.{}", header.0, header.1, header.2);
                }
                Err(nom::Err::Incomplete(_)) => {
                    let needed = 8 - start.len(); // AMQP protocol header is 8 bytes
                    return AppLayerResult::incomplete(0, needed as u32);
                }
                Err(_) => {
                    // Not a valid AMQP protocol header, continue as normal frames
                }
            }
        }
        
        while !start.is_empty() {
            match parser::parse_amqp_frame(start) {
                Ok((rem, frame)) => {
                    start = rem;

                    SCLogNotice!("AMQP Frame: type={}, channel={}, length={}", 
                               frame.frame_type, frame.channel, frame.length);
                    
                    let mut tx = self.new_tx();
                    tx.channel = frame.channel;
                    tx.request_frame = Some(frame.clone());
                    
                    // Parse method if it's a method frame
                    if frame.frame_type == AMQP_FRAME_METHOD {
                        if let Ok((_, method)) = parser::parse_amqp_method(&frame.payload) {
                            tx.method_class = Some(method.class_id);
                            tx.method_id = Some(method.method_id);
                            SCLogNotice!("AMQP Method: class={}, method={}", 
                                       method.class_id, method.method_id);
                        }
                    }
                    
                    if self.transactions.len() >= unsafe { AMQP_MAX_TX } {
                        tx.tx_data
                            .set_event(AMQPEvent::TooManyTransactions as u8);
                    }
                    self.transactions.push_back(tx);
                    if self.transactions.len() >= unsafe { AMQP_MAX_TX } {
                        return AppLayerResult::err();
                    }
                }
                Err(nom::Err::Incomplete(needed)) => {
                    // Not enough data. Calculate how much more we need.
                    let consumed = input.len() - start.len();
                    let needed_bytes = match needed {
                        nom::Needed::Size(n) => n.get() as u32,
                        nom::Needed::Unknown => 1,
                    };
                    return AppLayerResult::incomplete(consumed as u32, needed_bytes);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if parser::probe_amqp(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For AMQP, we'll try to find the next frame boundary.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_amqp_frame(start) {
                Ok((rem, frame)) => {
                    start = rem;

                    SCLogNotice!("AMQP Response Frame: type={}, channel={}, length={}", 
                               frame.frame_type, frame.channel, frame.length);

                    if let Some(tx) = self.find_request() {
                        tx.tx_data.updated_tc = true;
                        tx.response_frame = Some(frame);
                        SCLogNotice!("Found response frame for transaction {}", tx.tx_id);
                    }
                }
                Err(nom::Err::Incomplete(needed)) => {
                    let consumed = input.len() - start.len();
                    let needed_bytes = match needed {
                        nom::Needed::Size(n) => n.get() as u32,
                        nom::Needed::Unknown => 1,
                    };
                    return AppLayerResult::incomplete(consumed as u32, needed_bytes);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid AMQP protocol header or frame.
///
/// AMQP protocol starts with "AMQP" followed by protocol version bytes,
/// or frames start with frame type (1-8).
fn probe_amqp(input: &[u8]) -> nom::IResult<&[u8], ()> {
    if input.len() < 4 {
        return Err(nom::Err::Incomplete(nom::Needed::Size(
            std::num::NonZeroUsize::new(4).unwrap(),
        )));
    }
    
    // Check for AMQP protocol header
    if input.len() >= 8 {
        if &input[0..4] == b"AMQP" {
            return Ok((&input[8..], ()));
        }
    }
    
    // Check for valid frame type
    let frame_type = input[0];
    if matches!(frame_type, AMQP_FRAME_METHOD | AMQP_FRAME_HEADER | AMQP_FRAME_BODY | AMQP_FRAME_HEARTBEAT) {
        return Ok((&input[1..], ()));
    }
    
    Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn amqp_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 4 bytes for minimal detection.
    if input_len >= 4 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe_amqp(slice).is_ok() {
            return ALPROTO_AMQP;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn amqp_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = AMQPState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn amqp_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut AMQPState));
}

unsafe extern "C" fn amqp_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, AMQPState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn amqp_parse_request(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, AMQPState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

unsafe extern "C" fn amqp_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, AMQPState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

unsafe extern "C" fn amqp_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, AMQPState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn amqp_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, AMQPState);
    return state.tx_id;
}

unsafe extern "C" fn amqp_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, AMQPTransaction);

    // Transaction is done if we have a response.
    if tx.response_frame.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(amqp_get_tx_data, AMQPTransaction);
export_state_data_get!(amqp_get_state_data, AMQPState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"amqp\0";

#[no_mangle]
pub unsafe extern "C" fn SCRegisterAMQPParser() {
    let default_port = CString::new("[5672]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(amqp_probing_parser),
        probe_tc: Some(amqp_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: amqp_state_new,
        state_free: amqp_state_free,
        tx_free: amqp_state_tx_free,
        parse_ts: amqp_parse_request,
        parse_tc: amqp_parse_response,
        get_tx_count: amqp_state_get_tx_count,
        get_tx: amqp_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: amqp_tx_get_alstate_progress,
        get_eventinfo: Some(AMQPEvent::get_event_info),
        get_eventinfo_byid: Some(AMQPEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<AMQPState, AMQPTransaction>),
        get_tx_data: amqp_get_tx_data,
        get_state_data: amqp_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_AMQP = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.amqp.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                AMQP_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for amqp.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_AMQP);
        SCLogNotice!("Rust amqp parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for AMQP.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe_amqp_protocol_header() {
        assert!(probe_amqp(b"AMQP\x00\x00\x09\x01").is_ok());
        assert!(probe_amqp(b"HTTP").is_err());
    }

    #[test]
    fn test_probe_amqp_frame() {
        assert!(probe_amqp(b"\x01\x00\x00\x00\x00\x00\x04").is_ok()); // Method frame
        assert!(probe_amqp(b"\x02\x00\x00\x00\x00\x00\x04").is_ok()); // Header frame
        assert!(probe_amqp(b"\x03\x00\x00\x00\x00\x00\x04").is_ok()); // Body frame
        assert!(probe_amqp(b"\x08\x00\x00\x00\x00\x00\x00").is_ok()); // Heartbeat frame
        assert!(probe_amqp(b"\x99\x00\x00").is_err()); // Invalid frame type
    }

    #[test]
    fn test_amqp_state_creation() {
        let state = AMQPState::new();
        assert!(!state.protocol_header_seen);
        assert_eq!(state.minor_version, 9);
        assert_eq!(state.revision, 1);
        assert_eq!(state.max_frame_size, 131072);
    }

    #[test]
    fn test_incomplete_data() {
        let mut state = AMQPState::new();
        let buf = b"AM"; // Incomplete AMQP header

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(r.status, 1); // Incomplete
    }
}
