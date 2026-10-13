// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use sha2::{Digest, Sha256};
use std::{error, fmt};
use x509_cert::der::Encode;

pub struct HeliosAttestation {
    attestation: helios_rot::Attestation,
    cert_chain: Vec<Vec<u8>>,
}

pub struct OxideAttestation {
    attestation: oxide_rot::Attestation,
    cert_chain: Vec<Vec<u8>>,
    log: oxide_rot::Log,
}

pub struct PlatformAttestation {
    helios: HeliosAttestation,
    oxide: OxideAttestation,
}

#[async_trait::async_trait]
pub trait PlatformAttester {
    type Error: error::Error + fmt::Debug + Send + Sync + 'static;

    async fn attest(
        &self,
        // TODO: using nonce type from attest_data for convenience / compatibility
        qdata: &oxide_rot::Nonce,
    ) -> Result<PlatformAttestation, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformRotError<T: helios_rot::HeliosRot + fmt::Debug> {
    #[error("HeliosOsRot")]
    HeliosRot(#[source] <T as helios_rot::HeliosRot>::Error),
    #[error("OxideRot")]
    OxideRot(#[from] oxide_rot::AttestError),
    #[error("DerEncode")]
    DerEncode(#[from] x509_cert::der::Error),
    #[error("HeliosNonce")]
    HeliosNonce(#[from] helios_rot::NonceError),
    #[error("OxideNonce")]
    OxideNonce(#[from] oxide_rot::NonceError),
}

pub struct PlatformRot<H, O>
where
    H: helios_rot::HeliosRot + fmt::Debug + Sync,
    O: oxide_rot::Attest + Sync,
{
    helios_rot: H,
    oxide_rot: O,
}

impl<H, O> PlatformRot<H, O>
where
    H: helios_rot::HeliosRot + fmt::Debug + Sync,
    O: oxide_rot::Attest + Sync,
{
    pub fn new(helios_rot: H, oxide_rot: O) -> Self {
        Self {
            helios_rot,
            oxide_rot,
        }
    }
}

#[async_trait::async_trait]
impl<H, O> PlatformAttester for PlatformRot<H, O>
where
    H: helios_rot::HeliosRot + fmt::Debug + Sync + 'static,
    O: oxide_rot::Attest + Sync,
{
    type Error = PlatformRotError<H>;

    async fn attest(
        &self,
        qdata: &oxide_rot::Nonce,
    ) -> Result<PlatformAttestation, Self::Error> {
        // get attestation from helios rot
        let helios_certs = self
            .helios_rot
            .get_certificates()
            .await
            .map_err(Self::Error::HeliosRot)?;
        let mut cert_chain = Vec::new();
        for cert in helios_certs {
            cert_chain.push(cert.to_der()?)
        }

        // create helios_rot::Nonce from oxide_rot::Nonce
        let helios_qdata = match qdata {
            oxide_rot::Nonce::N32(n) => {
                // this creates 48 bytes of qualifying data from 32 bytes + 16
                // bytes of 0-padding
                let mut new_nonce = [0u8; 48];
                new_nonce.copy_from_slice(n.as_ref());
                //TODO: `Nonce` should have a `from`
                helios_rot::Nonce::try_from(new_nonce.as_ref())?
            }
        };
        let attestation = self
            .helios_rot
            .attest(&helios_qdata)
            .await
            .map_err(Self::Error::HeliosRot)?;
        let helios = HeliosAttestation {
            attestation,
            cert_chain,
        };

        let oxide_certs = self
            .oxide_rot
            .get_certificates()
            .await
            .map_err(Self::Error::OxideRot)?;
        let mut cert_chain = Vec::new();
        for cert in oxide_certs {
            cert_chain.push(cert.to_der()?)
        }

        let log = self
            .oxide_rot
            .get_measurement_log()
            .await
            .map_err(Self::Error::OxideRot)?;

        // bind attestation from helios rot to attestation from oxide rot by
        // passing the oxide rot qualifying data defined as:
        // `qdata1 = sha256(qdata0 | attestation)`
        // where `qdata0` is the qualifying data passed into this function
        let mut oxide_qdata = Sha256::new();
        oxide_qdata.update(qdata.as_ref());
        match helios.attestation {
            helios_rot::Attestation::P384(s) => oxide_qdata.update(s.as_ref()),
        }
        let qdata = oxide_rot::Nonce::try_from(oxide_qdata.finalize().as_ref())?;

        let attestation = self
            .oxide_rot
            .attest(&qdata)
            .await
            .map_err(Self::Error::OxideRot)?;
        let oxide = OxideAttestation {
            attestation,
            cert_chain,
            log,
        };

        Ok(PlatformAttestation { helios, oxide })
    }
}
