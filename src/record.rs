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
use ::{Error,RecordType};


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

    Signal,
    ContextSwitch,
    UserData,
    Struct,
    Sysctl,

    /// KTR_PROCCTOR - trace process creation (multiple ABI support)
    ProcessCreation { flags: u32 },

    ProcessDestruction,
    CapabilityFailure,
    PageFault,
    PageFaultEnd,
}

/// Directions that I/O can take place in
#[derive(Clone,Debug)]
pub enum IODir {
    Read,
    Write,
}

impl Record {
    pub fn parse<E>(data: &[u8], t: &RecordType) -> Result<Record, Error>
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

                // TODO: find a more idiomatic way of doing this, probably
                //       with some sort of iterator adapter
                let mut args = Vec::new();
                for i in 0..num_args {
                    let start = 8 * i as usize;
                    args.push(E::read_u64(&arg_data[start..start+8]));
                }

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

            /*
            &RecordType::Signal => {
            },
            &RecordType::ContextSwitch => {
            },
            &RecordType::UserData => {
            },
            &RecordType::Struct => {
            },
            &RecordType::Sysctl => {
            },
            */
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
            /*
            &RecordType::ProcessDestruction => {
            },
            &RecordType::CapabilityFailure => {
            },
            &RecordType::PageFault => {
            },
            &RecordType::PageFaultEnd => {
            },
            */
            _ => Err(Error::msg(
                format!["Unknown data of type {}: {:?}", t, data]))
        }
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Record::Drop => {
                write![f, "<record(s) dropped>"]
            },

            &Record::SystemCall{ref number, ref args} => {
                write![f, "CALL  {}, {} args: {:?}",
                    number, args.len(), &args]
            },

            &Record::SystemCallReturn{ref code, ref retval, ..} => {
                write![f, "RET   {} {}", code, retval]
            },

            &Record::Namei(ref name) => {
                write![f, "NAMI  \"{}\"", name]
            },

            &Record::GenericIO{ref fd, ref rw, ref data} => {
                write![f, "GENIO {} {:?}: {} B {:?}",
                    fd, rw, data.len(), &data[..20]]
            },

            /*
            &Record::Signal => {
            },
            &Record::ContextSwitch => {
            },
            &Record::UserData => {
            },
            &Record::Struct => {
            },
            &Record::Sysctl => {
            },
            */
            &Record::ProcessCreation{ref flags} => {
                write![f, "PROCC 0x{:x}", flags]
            },

            /*
            &Record::ProcessDestruction => {
            },
            &Record::CapabilityFailure => {
            },
            &Record::PageFault => {
            },
            &Record::PageFaultEnd => {
            },
            */

            _ => write![f, "unhandled record type"],
        }
    }
}
