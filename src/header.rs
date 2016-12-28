// Copyright 2016 Jonathan Anderson <jonathan.anderson@mun.ca>
//
// This software was developed by BAE Systems, the University of Cambridge
// Computer Laboratory, and Memorial University under DARPA/AFRL contract
// FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
// (TC) research program.
//
// Licensed under the Apache License, Version 2.0,
// <LICENSE-APACHE or http://apache.org/licenses/LICENSE-2.0>
// or the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;
extern crate nix;

use std::ffi::CStr;
use std::fmt;
use std::mem::transmute;
use ::Error;

const MAXCOMLEN: usize = 19;


/// Safe wrapper around C `struct ktr_header`
#[derive(Clone, Debug)]
pub struct Header {
    pub length: usize,
    pub record_type: RecordType,
    pub pid: u32,
    pub command: String,
    pub timestamp: nix::sys::time::TimeVal,
    pub tid: usize,
}

#[repr(C)]
struct RawHeader {
    ktr_len: u32,
    ktr_type: u16,
    ktr_pid: u32,
    ktr_comm: [i8; MAXCOMLEN + 1],
    ktr_time: libc::timeval,
    ktr_tid: libc::intptr_t,
}

impl Header {
    pub fn parse(buffer: &[u8;56]) -> Result<Header, Error> {
        let raw = unsafe { transmute::<&[u8; 56],&RawHeader>(&buffer)};

        let command = unsafe { CStr::from_ptr(&raw.ktr_comm as *const i8) }
            .to_str()
            .or(Err(Error::msg("invalid 'command' in ktrace record header")))
            ;

        Ok(Header{
            length: raw.ktr_len as usize,
            record_type: try![RecordType::from_u16(raw.ktr_type)],
            pid: raw.ktr_pid as u32,
            command: try![command].to_string(),
            timestamp: nix::sys::time::TimeVal{
                tv_sec: raw.ktr_time.tv_sec,
                tv_usec: raw.ktr_time.tv_usec,
            },
            tid: raw.ktr_tid as usize,
        })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write![f, "{} (PID {}, TID {}, command {}, len {})",
               self.record_type, self.pid, self.tid, self.command, self.length]
    }
}


/// Types of ktrace records that a Header can describe
#[derive(Clone, Debug)]
pub enum RecordType {
    SystemCall = 1,
    SystemCallReturn,
    Namei,
    GenericIO,
    Signal,
    ContextSwitch,
    UserData,
    Struct,
    Sysctl,
    ProcessCreation,
    ProcessDestruction,
    CapabilityFailure,
    PageFault,
    PageFaultEnd,
}

impl RecordType {
    pub fn from_u16(val: u16) -> Result<RecordType, Error> {
        // TODO: use enum_primitive or somesuch
        match val {
            1 => Ok(RecordType::SystemCall),
            2 => Ok(RecordType::SystemCallReturn),
            3 => Ok(RecordType::Namei),
            4 => Ok(RecordType::GenericIO),
            5 => Ok(RecordType::Signal),
            6 => Ok(RecordType::ContextSwitch),
            7 => Ok(RecordType::UserData),
            8 => Ok(RecordType::Struct),
            9 => Ok(RecordType::Sysctl),
            10 => Ok(RecordType::ProcessCreation),
            11 => Ok(RecordType::ProcessDestruction),
            12 => Ok(RecordType::CapabilityFailure),
            13 => Ok(RecordType::PageFault),
            14 => Ok(RecordType::PageFaultEnd),
            _ => Err(Error::bad_value("ktr_type", val.to_string())),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let name = match self {
            &RecordType::SystemCall => "SystemCall",
            &RecordType::SystemCallReturn => "SystemCallReturn",
            &RecordType::Namei => "Namei",
            &RecordType::GenericIO => "GenericIO",
            &RecordType::Signal => "Signal",
            &RecordType::ContextSwitch => "ContextSwitch",
            &RecordType::UserData => "UserData",
            &RecordType::Struct => "Struct",
            &RecordType::Sysctl => "Sysctl",
            &RecordType::ProcessCreation => "ProcessCreation",
            &RecordType::ProcessDestruction => "ProcessDestruction",
            &RecordType::CapabilityFailure => "CapabilityFailure",
            &RecordType::PageFault => "PageFault",
            &RecordType::PageFaultEnd => "PageFaultEnd",
        };

        write![f, "{}", name]
    }
}
