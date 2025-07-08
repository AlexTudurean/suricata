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

use nom7::{
    bytes::streaming::{tag, take},
    number::streaming::{be_u8, be_u16, be_u32},
    IResult,
};
use super::amqp::{AMQPFrame, AMQPMethod};

/// Parse AMQP protocol header: "AMQP" + 3 version bytes + 1 type byte
pub fn parse_protocol_header(input: &[u8]) -> IResult<&[u8], (u8, u8, u8)> {
    let (input, _) = tag(b"AMQP")(input)?;
    let (input, _type_byte) = be_u8(input)?; // Usually 0 for connection start
    let (input, major) = be_u8(input)?;
    let (input, minor) = be_u8(input)?;
    let (input, revision) = be_u8(input)?;
    
    Ok((input, (major, minor, revision)))
}

/// Parse an AMQP frame
pub fn parse_amqp_frame(input: &[u8]) -> IResult<&[u8], AMQPFrame> {
    let (input, frame_type) = be_u8(input)?;
    let (input, channel) = be_u16(input)?;
    let (input, length) = be_u32(input)?;
    
    // Validate frame length to prevent excessive memory allocation
    if length > 1048576 { // 1MB max frame size
        return Err(nom7::Err::Error(nom7::error::Error::new(
            input,
            nom7::error::ErrorKind::TooLarge,
        )));
    }
    
    let (input, payload) = take(length as usize)(input)?;
    let (input, _frame_end) = be_u8(input)?; // Frame end byte (0xCE)
    
    Ok((input, AMQPFrame {
        frame_type,
        channel,
        length,
        payload: payload.to_vec(),
    }))
}

/// Parse an AMQP method from frame payload
pub fn parse_amqp_method(payload: &[u8]) -> IResult<&[u8], AMQPMethod> {
    let (payload, class_id) = be_u16(payload)?;
    let (payload, method_id) = be_u16(payload)?;
    
    Ok((payload, AMQPMethod {
        class_id,
        method_id,
        arguments: payload.to_vec(),
    }))
}

/// Probe function for AMQP protocol detection
pub fn probe_amqp(input: &[u8]) -> IResult<&[u8], ()> {
    if input.len() < 4 {
        return Err(nom7::Err::Incomplete(nom7::Needed::Size(
            std::num::NonZeroUsize::new(4).unwrap(),
        )));
    }
    
    // Check for AMQP protocol header
    if input.len() >= 8 && &input[0..4] == b"AMQP" {
        return Ok((&input[8..], ()));
    }
    
    // Check for valid AMQP frame structure
    if input.len() >= 7 {
        let frame_type = input[0];
        // Check for valid frame type (1=method, 2=header, 3=body, 8=heartbeat)
        if matches!(frame_type, 1 | 2 | 3 | 8) {
            let length = u32::from_be_bytes([input[3], input[4], input[5], input[6]]);
            
            // Validate frame length is reasonable (not too large, not zero for non-heartbeat)
            if length <= 1048576 && (frame_type == 8 || length > 0) {
                // For method frames, do additional validation on class IDs if we have enough data
                if frame_type == 1 && input.len() >= 11 && length >= 4 {
                    let class_id = u16::from_be_bytes([input[7], input[8]]);
                    // Check for known AMQP class IDs (10=connection, 20=channel, 40=exchange, 50=queue, 60=basic)
                    if matches!(class_id, 10 | 20 | 40 | 50 | 60) {
                        return Ok((&input[1..], ()));
                    }
                }
                
                // For non-method frames or if method frame validation fails,
                // still accept if frame structure looks valid
                if length > 0 && length < 65536 {
                    return Ok((&input[1..], ()));
                }
            }
        }
    }
    
    Err(nom7::Err::Error(nom7::error::Error::new(
        input,
        nom7::error::ErrorKind::Tag,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol_header() {
        let data = b"AMQP\x00\x00\x09\x01extra_data";
        let result = parse_protocol_header(data);
        
        match result {
            Ok((remainder, (major, minor, revision))) => {
                assert_eq!(major, 0);
                assert_eq!(minor, 9);
                assert_eq!(revision, 1);
                assert_eq!(remainder, b"extra_data");
            }
            _ => panic!("Failed to parse AMQP protocol header"),
        }
    }

    #[test]
    fn test_probe_amqp_protocol_header() {
        let data = b"AMQP\x00\x00\x09\x01";
        assert!(probe_amqp(data).is_ok());
    }

    #[test]
    fn test_probe_amqp_frame() {
        let data = b"\x01\x00\x00\x00\x00\x00\x10"; // Method frame
        assert!(probe_amqp(data).is_ok());
    }

    #[test]
    fn test_probe_amqp_invalid() {
        let data = b"HTTP/1.1 200 OK";
        assert!(probe_amqp(data).is_err());
    }
}
