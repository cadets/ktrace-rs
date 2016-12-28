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

use ::std::{fmt,io,string};


pub enum Error {
    BadValue{ expected: String, got: String },
    IO(io::Error),
    Message(String),
    UTF8(string::FromUtf8Error),
}

impl Error {
    pub fn bad_value<S1, S2>(expected: S1, got: S2) -> Error
        where S1: Into<String>, S2: Into<String>
    {
        Error::BadValue{
            expected: expected.into(),
            got: got.into(),
        }
    }

    pub fn msg<Str>(s: Str) -> Error
        where Str: Into<String>
    {
        Error::Message(s.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Error::BadValue{ref expected, ref got} => {
                write![f, "bad value: expected {}, got {}", expected, got]
            },

            &Error::IO(ref e) => {
                write![f, "I/O error: {}", e]
            },

            &Error::Message(ref message) => {
                write![f, "{}", message]
            },

            &Error::UTF8(ref e) => {
                write![f, "UTF8 error: {}", e]
            },
        }
    }
}
