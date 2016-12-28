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

extern crate byteorder;

mod error;
mod header;
mod record;

pub use error::*;
pub use header::*;
pub use record::*;

use std::io;
use std::io::ErrorKind::UnexpectedEof;

type Result<T> = std::result::Result<T, self::Error>;


pub fn parse<E>(mut r: &mut io::Read) -> Result<Vec<(Header,Result<Record>)>>
    where E: byteorder::ByteOrder
{
    let mut v = Vec::new();

    loop {
        let mut data = [0; 56];
        match r.read_exact(&mut data) {
            Err(ref e) if e.kind() == UnexpectedEof => {
                break;
            },

            Err(e) => { return Err(Error::IO(e)); },
            Ok(()) => {},
        };

        let header = try![Header::parse(&data)];

        let mut data = vec![0; header.length];
        try![r.read_exact(&mut data).map_err(Error::IO)];
        let record = Record::parse::<E>(&data, &header.record_type);

        v.push((header, record));
    }

    Ok(v)
}
