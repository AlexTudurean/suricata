/* Copyright (C) 2024 Open Information Security Foundation
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

//! AMQP detection support for Suricata

use crate::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList,
    SCDetectHelperBufferMpmRegister, SCDetectSignatureSetAppProto, Signature,
};

use super::amqp::{AMQPTransaction, ALPROTO_AMQP};
use std::os::raw::{c_int, c_void};
use std::ptr;

static mut G_AMQP_BUFFER_ID: c_int = 0;

unsafe extern "C" fn amqp_tx_get_frame_data(
    tx: *const c_void,
    _flags: u8,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = tx as *const AMQPTransaction;
    if tx.is_null() {
        return false;
    }
    let tx = &*tx;
    
    // Return data from request frame if available
    if let Some(ref frame) = tx.request_frame {
        if !frame.payload.is_empty() {
            *buffer = frame.payload.as_ptr();
            *buffer_len = frame.payload.len() as u32;
            return true;
        }
    }
    
    // Fallback to response frame if available
    if let Some(ref frame) = tx.response_frame {
        if !frame.payload.is_empty() {
            *buffer = frame.payload.as_ptr();
            *buffer_len = frame.payload.len() as u32;
            return true;
        }
    }
    
    // Return body data if available
    if let Some(ref body) = tx.body {
        if !body.is_empty() {
            *buffer = body.as_ptr();
            *buffer_len = body.len() as u32;
            return true;
        }
    }
    
    *buffer = ptr::null();
    *buffer_len = 0;
    false
}

unsafe extern "C" fn amqp_setup(
    de: *mut DetectEngineCtx,
    s: *mut Signature,
    _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_AMQP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_AMQP_BUFFER_ID) < 0 {
        return -1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn SCDetectAMQPRegister() {
    let kw = SigTableElmtStickyBuffer {
        name: String::from("amqp"),
        desc: String::from("sticky buffer to match on AMQP frame data"),
        url: String::from("/rules/amqp-keywords.html#amqp"),
        setup: amqp_setup,
    };
    let _g_amqp_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_AMQP_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"amqp\0".as_ptr() as *const libc::c_char,
        b"AMQP frame data\0".as_ptr() as *const libc::c_char,
        ALPROTO_AMQP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(amqp_tx_get_frame_data),
    );
}
