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
extern crate clap;
extern crate ktrace;

use byteorder::NativeEndian;
use ktrace::Error;
use std::fs::File;


fn main() {
    let version = option_env!["CARGO_PKG_VERSION"].unwrap_or("unknown");

    let args = clap::App::new("ktrace")
                             .version(version)
                             .arg(clap::Arg::with_name("INPUT")
                                  .help("Binary ktrace dump file")
                                  .required(true))
                             .get_matches();

    let parsed = args.value_of("INPUT")
        .ok_or(Error::msg("missing required argument"))
        .and_then(|name| File::open(name).map_err(Error::IO))
        .and_then(|mut file| ktrace::parse::<NativeEndian>(&mut file))
        ;

    match parsed {
        Err(e) => {
            println!["Error: {}", e];
            std::process::exit(1);
        },

        Ok(records) => {
            println!["Parsed {} records:", records.len()];
            for (header, record) in records.into_iter() {
                print!["{:6} {:8}", header.pid, header.command];

                match record {
                    Ok(ref rec) => println!["{}", rec],
                    Err(ref e) => println!["<error: {}>", e],
                };
            }
        },
    }
}
