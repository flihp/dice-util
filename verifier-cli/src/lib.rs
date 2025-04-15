// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod sprot;

use anyhow::Result;
use attest_data::{Attestation, Log, Nonce};
use clap::ValueEnum;
use std::fmt;
use x509_cert::PkiPath;

pub trait Attester {
    fn get_measurement_log(&self) -> Result<Log>;
    fn get_certificates(&self) -> Result<PkiPath>;
    fn attest(&self, nonce: &Nonce) -> Result<Attestation>;
}

/// An enum of the possible routes to the `Attest` task.
#[derive(Clone, Debug, ValueEnum)]
pub enum Interface {
    Rot,
    Sprot,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Interface::Rot => write!(f, "Attest"),
            Interface::Sprot => write!(f, "SpRot"),
        }
    }
}

/// An enum of the possible certificate encodings.
#[derive(Clone, Debug, ValueEnum)]
pub enum Encoding {
    Der,
    Pem,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Encoding::Der => write!(f, "der"),
            Encoding::Pem => write!(f, "pem"),
        }
    }
}
