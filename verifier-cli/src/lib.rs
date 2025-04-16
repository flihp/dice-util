// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod sprot;
use sprot::AttestHiffy;

#[cfg(feature = "ipcc")]
pub mod ipcc;
#[cfg(feature = "ipcc")]
use ipcc::Ipcc;

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

impl dyn Attester {
    pub fn new(interface: Interface) -> Result<Box<dyn Attester>> {
        match interface {
            #[cfg(feature = "ipcc")]
            Interface::Ipcc => Ok(Box::new(Ipcc::new()?)),
            Interface::Rot | Interface::Sprot => {
                Ok(Box::new(AttestHiffy::new(interface)))
            }
        }
    }
}
// TODO: Create factory type that creates an `Attester` from an instance of
// the  `Interface` enum.
/// An enum of the possible routes to the `Attest` task.
#[derive(Clone, Debug, ValueEnum)]
pub enum Interface {
    #[cfg(feature = "ipcc")]
    Ipcc,
    Rot,
    Sprot,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "ipcc")]
            Interface::Ipcc => write!(f, "Ipcc"),
            Interface::Rot => write!(f, "Attest"),
            Interface::Sprot => write!(f, "SpRot"),
        }
    }
}
