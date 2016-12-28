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

use std::fmt;


#[derive(Clone,Debug)]
pub enum Record {
    /// At least one record was dropped.
    Drop,

    SystemCall {
        number: u16,
        args: Vec<u64>,
    },

    SystemCallReturn,
    Namei,
    GenericIO,
    Signal,
    ContextSwitch,
    UserData,
    Struct,
    Sysctl,
    ProcessDestruction,
    CapabilityFailure,
    PageFault,
    PageFaultEnd,
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Record::SystemCall{ref number, ref args} => {
                write![f, "syscall {}, {} args", number, args.len()]
            },

            _ => Ok(()),
        }
    }
}
