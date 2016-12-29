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

use byteorder::{ByteOrder,NativeEndian};
use std::fmt;
use ::{Error,RecordType,Result};


#[derive(Clone,Debug)]
pub enum Record {
    /// At least one record was dropped.
    Drop,

    /// KTR_SYSCALL - system call record
    SystemCall {
        /// syscall number
        number: u16,

        /// user arguments
        args: Vec<u64>,
    },

    /// KTR_SYSRET - return from system call record
    SystemCallReturn {
        code: u16,
        eosys: u16,
        error: u32,
        retval: u64,
    },

    /// KTR_NAMEI - namei record
    Namei(String),

    /// KTR_GENIO - trace generic process I/O
    GenericIO {
        fd: i32,
        rw: IODir,
        data: Vec<u8>,
    },

    /// KTR_PSIG - trace processed signal
    Signal {
        signo: i32,
        handler: *const SignalHandler,
        code: i32,
        mask: Vec<u32>,
    },

    /// KTR_CSW - trace context switches
    ContextSwitch {
        out: bool,
        user: bool,
        message: String,
    },

    /// KTR_USER - data coming from userland
    UserData(Vec<u8>),

    /// KTR_STRUCT - misc. structs
    Struct {
        name: String,
        content: Vec<u8>,
    },

    /// KTR_SYSCTL - name of a sysctl MIB
    Sysctl(String),

    /// KTR_PROCCTOR - trace process creation (multiple ABI support)
    ProcessCreation { flags: u32 },

    /// KTR_PROCDTOR - trace process destruction (multiple ABI support)
    ProcessDestruction,

    /// KTR_CAPFAIL - trace capability check failure
    CapabilityFailure(capfail::CapFail),

    /// KTR_FAULT - page fault record
    PageFault {
        virtual_address: u64,
        fault_type: u32,
    },

    /// KTR_FAULTEND - end of page fault record
    PageFaultEnd {
        result: u32,
    },
}

/// Directions that I/O can take place in
#[derive(Clone,Debug)]
pub enum IODir {
    Read,
    Write,
}

/// Opaque representation of a C signal handler
pub enum SignalHandler {}

impl Record {
    pub fn parse<E>(data: &[u8], t: &RecordType) -> Result<Record>
        where E : ByteOrder
    {
        match t {
            &RecordType::SystemCall => {
                if data.len() < 4 {
                    return Err(Error::bad_value(
                            "2*u16", format!["{} B: {:?}", data.len(), data]));
                }

                let code = E::read_u16(&data[0..2]);
                let num_args = E::read_u16(&data[2..4]);

                // There is padding before the arguments begin
                let arg_data = &data[8..];

                if arg_data.len() != 8 * num_args as usize {
                    return Err(Error::bad_value(
                            format!["{} 8B arguments", num_args],
                            format!["{} B: {:?}", arg_data.len(), &arg_data]));
                }

                let args = arg_data.chunks(8)
                                   .map(|chunk| E::read_u64(chunk))
                                   .collect::<Vec<_>>()
                                   ;

                Ok(Record::SystemCall {
                    number: code,
                    args: args,
                })
            },

            &RecordType::SystemCallReturn => {
                if data.len() != 16 {
                    return Err(Error::bad_value(
                            "16 B", format!["{} B: {:?}", data.len(), data]));
                }

                Ok(Record::SystemCallReturn {
                    code: E::read_u16(&data[0..2]),
                    eosys: E::read_u16(&data[2..4]),
                    error: E::read_u32(&data[4..8]),
                    retval: E::read_u64(&data[8..16]),
                })
            },

            &RecordType::Namei => {
                String::from_utf8(data.to_vec())
                       .map(Record::Namei)
                       .map_err(Error::UTF8)
            },

            &RecordType::GenericIO => {
                if data.len() < 8 {
                    return Err(Error::bad_value(
                            "2*int", format!["{} B: {:?}", data.len(), data]));
                }

                Ok(Record::GenericIO{
                    fd: E::read_i32(&data[0..4]),
                    rw: match E::read_u32(&data[4..8]) {
                        0 => IODir::Read,
                        1 => IODir::Write,
                        x => return Err(Error::bad_value("uio_rw",
                                                         format!["{}", x]))
                    },
                    data: data[8..].to_vec(),
                })
            },

            &RecordType::Signal => {
                if data.len() < 20 {
                    return Err(Error::bad_value(
                        "2*int + sig_t + sigset_t + padding",
                        format!["{} B: {:?}", data.len(), data]
                    ));
                }

                Ok(Record::Signal {
                    signo: E::read_i32(&data[0..4]),
                    handler: E::read_u64(&data[8..16]) as *const SignalHandler,
                    code: E::read_i32(&data[16..20]),
                    mask: data[20..].chunks(4)
                                    .map(|chunk| E::read_u32(chunk))
                                    .collect::<Vec<_>>(),
                })
            },

            &RecordType::ContextSwitch => {
                Ok(Record::ContextSwitch {
                    out: (E::read_u32(&data[0..4]) != 0),
                    user: (E::read_u32(&data[4..8]) != 0),
                    message: try! {
                        String::from_utf8(data[8..].to_vec())
                               .map_err(Error::UTF8)
                    },
                })
            },

            &RecordType::UserData => {
                Ok(Record::UserData(data.to_vec()))
            },

            &RecordType::Struct => {
                let nul = try! {
                    data.iter()
                        .position(|x| *x == 0)
                        .ok_or(Error::msg("no NULL byte in struct name"))
                };

                Ok(Record::Struct {
                    name: try! {
                        String::from_utf8(data[..nul].to_vec())
                               .map_err(Error::UTF8)
                    },
                    content: data[nul..].to_vec(),
                })
            },

            &RecordType::Sysctl => {
                if data.len() == 0 {
                    return Err(Error::bad_value("sysctl MIB", "empty string"));
                }

                String::from_utf8(data.to_vec())
                       .map(Record::Sysctl)
                       .map_err(Error::UTF8)
            },

            &RecordType::ProcessCreation => {
                if data.len() != 4 {
                    Err(Error::bad_value(
                            "u32", format!["{} B: {:?}", data.len(), data]))
                } else {
                    Ok(Record::ProcessCreation {
                        flags: NativeEndian::read_u32(data)
                    })
                }
            },

            &RecordType::ProcessDestruction => {
                if data.len() != 0 {
                    return Err(Error::bad_value(
                        "no data for process destruction",
                        format!["{:?}", data]
                    ));
                }

                Ok(Record::ProcessDestruction)
            },

            &RecordType::CapabilityFailure => {
                let failure = capfail::CapFail::parse::<E>(data);
                failure.map(Record::CapabilityFailure)
            },

            &RecordType::PageFault => {
                if data.len() < 12 {
                    return Err(Error::bad_value(
                        "vm_offset_t + int",
                        format!["{} B: {:?}", data.len(), data]
                    ));
                }

                Ok(Record::PageFault {
                    virtual_address: E::read_u64(&data[0..8]),
                    fault_type: E::read_u32(&data[8..12]),
                })
            },

            &RecordType::PageFaultEnd => {
                if data.len() != 4 {
                    return Err(Error::bad_value("int",
                        format!["{} B: {:?}", data.len(), data]
                    ));
                }

                Ok(Record::PageFaultEnd {
                    result: E::read_u32(data),
                })
            },
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Record::Drop => {
                write![f, "<record(s) dropped>"]
            },

            &Record::SystemCall{number, ref args} => {
                write![f, "CALL  {}({})",
                    syscalls::name(number as usize)
                             .unwrap_or(format!["<<bad syscall: {}>>", number]),
                    args.iter()
                        .map(|x| format!["0x{:x}", x])
                        .collect::<Vec<_>>()
                        .join(", ")
                ]
            },

            &Record::SystemCallReturn{code, retval, ..} => {
                write![f, "RET   {} 0x{:x}",
                    syscalls::name(code as usize)
                             .unwrap_or(format!["<<bad syscall: {}>>", code]),
                    retval
                ]
            },

            &Record::Namei(ref name) => {
                write![f, "NAMI  \"{}\"", name]
            },

            &Record::GenericIO{ref fd, ref rw, ref data} => {
                write![f, "GENIO {} {:?}: {}B: {:?} [...]",
                    fd, rw, data.len(),
                    data[..8].iter()
                              .map(|x| format!["{:02x}", x])
                              .collect::<Vec<_>>()
                              .join(" ")
                ]
            },

            &Record::Signal{signo, handler, code, ..} => {
                write![f, "{} caught handler=0x{:x} mask=?? code={}",
                    signo, handler as u64, code]
            },

            &Record::ContextSwitch{out, user, ref message} => {
                write![f, "CSW   {} {} \"{}\"",
                    if out { "stop" } else { "resume" },
                    if user { "user" } else { "kernel" },
                    message
                ]
            },

            &Record::UserData(ref data) => {
                write![f, "USER  {:?}", data]
            },

            &Record::Struct{ref name, ..} => {
                write![f, "STRU  struct {} {{ ... }}", name]
            },

            &Record::Sysctl(ref name) => {
                write![f, "SCTL  \"{}\"", name]
            },

            &Record::ProcessCreation{ref flags} => {
                write![f, "PROCC 0x{:x}", flags]
            },

            &Record::ProcessDestruction => {
                write![f, "PDEST"]
            },

            &Record::CapabilityFailure(ref fail) => {
                write![f, "CAP   {}", fail]
            },

            &Record::PageFault{virtual_address, fault_type} => {
                write![f, "PFLT  0x{:x} {}", virtual_address, fault_type]
            },

            &Record::PageFaultEnd{result} => {
                write![f, "PRET  {}", result]
            },
        }
    }
}

mod capfail;
mod syscalls;
