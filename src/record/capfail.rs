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

extern crate bit_vec;

use self::bit_vec::BitVec;
use byteorder::ByteOrder;
use std::fmt;
use ::{Error,Result};


#[derive(Clone,Debug)]
pub enum CapFail {
    /// insufficient capabilities in cap_check()
    NotCapable { needed: CapabilityRights, held: CapabilityRights },

    /// attempt to increase capabilities
    Increase,

    /// disallowed system call
    Syscall,

    /// disallowed VFS lookup
    Lookup,
}

/// Rights that are (or can be) associated with a capability
#[derive(Clone,Debug)]
pub struct CapabilityRights {
    version: usize,
    masks: Vec<BitVec>,
}


impl CapFail {
    pub fn parse<E>(data: &[u8]) -> Result<CapFail>
        where E : ByteOrder
    {
        if data.len() < 20 {
            return Err(Error::bad_value(
                "enum ktr_cap_fail_type + two cap_rights_t",
                format!["{} B: {:?}", data.len(), data]
            ));
        }

        match E::read_u32(&data[0..4]) {
            0 => {
                // CAPFAIL_NOTCAPABLE
                let cap_data = &data[8..];  // pad for alignment
                if !(cap_data.len() % 16 == 0) {
                    return Err(Error::bad_value(
                        "two cap_rights_t",
                        format!["{} B: {:?}", cap_data.len(), cap_data]
                    ));
                }

                let cap_rights_size = cap_data.len() / 2;
                let cap_rights_version = cap_data.len() / 8 - 2;

                let held = CapabilityRights {
                    version: cap_rights_version,
                    masks: cap_data[0..cap_rights_size]
                                   .chunks(8)
                                   .map(BitVec::from_bytes)
                                   .collect()
                };

                let needed = CapabilityRights {
                    version: cap_rights_version,
                    masks: cap_data[cap_rights_size..]
                                   .chunks(8)
                                   .map(BitVec::from_bytes)
                                   .collect()
                };

                Ok(CapFail::NotCapable{held: held, needed: needed})
            },
            1 => Ok(CapFail::Increase),  // CAPFAIL_INCREASE
            2 => Ok(CapFail::Syscall),   // CAPFAIL_SYSCALL
            3 => Ok(CapFail::Lookup),    // CAPFAIL_LOOKUP
            x => Err(Error::bad_value(
                "ktr_cap_fail_type (integer 0-3)", x.to_string()))
        }
    }
}


impl fmt::Display for CapFail {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CapFail::NotCapable{ref needed, ref held} => {
                write![f, "operation requires {}, descriptor holds {}",
                        needed, held]
            },
            &CapFail::Increase => write![f, "increase"],
            &CapFail::Syscall => write![f, "not permitted in capability mode"],
            &CapFail::Lookup => write![f, "restricted VFS lookup"],
        }
    }
}

impl CapabilityRights {
    pub fn parse<E>(data: &[u8], version: usize) -> Result<CapabilityRights>
        where E : ByteOrder
    {
        if data.len() % 8 != 0 {
            return Err(Error::bad_value(
                "cap_rights_t", format!["{}B: {:?}", data.len(), data]));
        }

        Ok(CapabilityRights {
            version: version,
            masks: data.chunks(8)
                       .map(BitVec::from_bytes)
                       .collect()
        })
    }
}


impl fmt::Display for CapabilityRights {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write![f, "<{}>", {
            self.masks
                .iter()
                .map(|x| format!["{:?}", x])
                .collect::<Vec<_>>()
                .join(", ")
        }]
    }
}
