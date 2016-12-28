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

mod error;
mod header;
mod record;

pub use error::*;
pub use header::*;
pub use record::*;

use std::io;


pub fn parse(mut input: &mut io::Read) -> Result<Vec<(Header,Record)>, Error> {
    let mut v = Vec::new();

    loop {
        let header = match Header::parse(&mut input) {
            Err(Error::IO(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            },

            h => try![h],
        };

        let mut data = vec![0; header.length];
        try![input.read_exact(&mut data).map_err(Error::IO)];

        v.push((header, Record::PageFault));  // TODO: parse record data!
    }

    Ok(v)
}
