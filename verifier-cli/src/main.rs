// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use attest_data::{Attestation, Log, Measurement, Nonce, Sha3_256Digest};
use clap::{Parser, Subcommand};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{asn1::OctetString, Decode, DecodeValue, Header, Sequence, SliceReader};
use dice_verifier::PkiPathSignatureVerifier;
use env_logger::Builder;
use hubpack::SerializedSize;
use log::{info, warn, LevelFilter};
use pem_rfc7468::LineEnding;
use sha3::Sha3_256;
use std::{
    collections::HashSet,
    fmt::Debug,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use x509_cert::{
    der::{DecodePem, EncodePem},
    Certificate, PkiPath,
};

use verifier_cli::sprot::{AttestHiffy, AttestRot};
use verifier_cli::{Attester, Interface, MeasurementCorpus};

// this doesn't belong here ... maybe `attest-data`?
const DICE_TCB_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

/// Execute HIF operations exposed by the RoT Attest task.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Interface used for communication with the Attest task.
    #[clap(value_enum, long, env, default_value_t = Interface::Rot)]
    interface: Interface,

    /// Attest task command to execute.
    #[command(subcommand)]
    command: AttestCommand,

    /// verbosity
    #[clap(long, env)]
    verbose: bool,
}

/// An enum of the HIF operations supported by the `Attest` interface.
#[derive(Debug, Subcommand)]
enum AttestCommand {
    /// Get an attestation, this is a signature over the serialized measurement log and the
    /// provided nonce: `sha3_256(log | nonce)`.
    Attest {
        /// Path to file holding the nonce
        #[clap(env)]
        nonce: PathBuf,
    },
    /// Get the full cert chain from the RoT encoded per RFC 6066 (PKI path)
    CertChain,
    /// get the length of the certificate at the provided index.
    /// Get the log of measurements recorded by the RoT.
    Log,
    /// Report a measurement to the `Attest` task for recording in the
    /// measurement log.
    Record {
        /// Path to file holding the digest to record
        #[clap(env)]
        digest: PathBuf,
    },
    Verify {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(
            long,
            env = "VERIFIER_CLI_CA_CERT",
            conflicts_with = "self_signed"
        )]
        ca_cert: Option<PathBuf>,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,

        /// Caller provided directory where artifacts are stored. If this
        /// option is provided it will be used by this tool to store
        /// artifacts retrieved from the RoT as part of the attestation
        /// process. If omitted a temp directory will be used instead.
        #[clap(long, env = "VERIFIER_CLI_WORK_DIR")]
        work_dir: Option<PathBuf>,
    },
    /// Verify signature over Attestation
    VerifyAttestation {
        /// Path to file holding the alias cert
        #[clap(long, env)]
        alias_cert: PathBuf,

        /// Path to file holding the attestation
        #[clap(env)]
        attestation: PathBuf,

        /// Path to file holding the log
        #[clap(long, env)]
        log: PathBuf,

        /// Path to file holding the nonce
        #[clap(long, env)]
        nonce: PathBuf,
    },
    /// Walk the PkiPath formatted certificate chain verifying each link.
    VerifyCertChain {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(long, env, conflicts_with = "self_signed")]
        ca_cert: Option<PathBuf>,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,

        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,
    },
    /// Verify the measurements from the log and cert chain against the
    /// provided measurement corpus.
    VerifyMeasurements {
        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,

        /// Path to file holding the log
        #[clap(env)]
        log: PathBuf,

        /// Path to file holding the reference measurement corpus
        #[clap(env)]
        corpus: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };
    builder.filter(None, level).init();

    let attest = AttestHiffy::new(args.interface);

    match args.command {
        AttestCommand::Attest { nonce } => {
            let nonce = fs::read(nonce)?;
            let nonce = Nonce::try_from(nonce)?;
            let attestation = Attester::attest(&attest, &nonce)?;

            // serialize attestation to json & write to file
            let mut attestation = serde_json::to_string(&attestation)?;
            attestation.push('\n');

            io::stdout().write_all(attestation.as_bytes())?;
            io::stdout().flush()?;
        }
        AttestCommand::CertChain => {
            let cert_chain = attest.get_certificates()?;
            for cert in cert_chain {
                let cert = cert.to_pem(LineEnding::default())?;

                io::stdout().write_all(cert.as_bytes())?;
            }
            io::stdout().flush()?;
        }
        AttestCommand::Log => {
            let log = attest.get_measurement_log()?;
            let mut log = serde_json::to_string(&log)?;
            log.push('\n');

            io::stdout().write_all(log.as_bytes())?;
            io::stdout().flush()?;
        }
        AttestCommand::Record { digest } => {
            let digest = fs::read(digest)?;
            attest.record(&digest)?;
        }
        AttestCommand::Verify {
            ca_cert,
            self_signed,
            work_dir,
        } => {
            // Use the directory provided by the caller to hold intermediate
            // files, or fall back to a temp dir.
            match work_dir {
                Some(w) => verify(&attest, &ca_cert, self_signed, w)?,
                None => {
                    let work_dir = tempfile::tempdir()?;
                    verify(&attest, &ca_cert, self_signed, work_dir)?
                }
            };
        }
        AttestCommand::VerifyAttestation {
            alias_cert,
            attestation,
            log,
            nonce,
        } => {
            verify_attestation(&alias_cert, &attestation, &log, &nonce)?;
        }
        AttestCommand::VerifyCertChain {
            cert_chain,
            ca_cert,
            self_signed,
        } => {
            verify_cert_chain(&ca_cert, &cert_chain, self_signed)?;
        }
        AttestCommand::VerifyMeasurements {
            cert_chain,
            log,
            corpus,
        } => {
            verify_measurements(&cert_chain, &log, &corpus)?;
        }
    }

    Ok(())
}

// DICE Attestation Architecture §6.1.1:
// FWID ::== SEQUENCE {
#[derive(Debug, Sequence)]
pub struct Fwid {
    // hashAlg OBJECT IDENTIFIER,
    hash_algorithm: ObjectIdentifier,
    // digest OCTET STRING
    digest: OctetString,
}

// DICE Attestation Architecture §6.1.1:
// DiceTcbInfo ::== SEQUENCE {
#[derive(Debug, Sequence)]
pub struct DiceTcbInfo {
    // fwids [6] IMPLICIT FWIDLIST OPTIONAL,
    // where FWIDLIST ::== SEQUENCE SIZE (1..MAX) OF FWID
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    fwids: Option<Vec<Fwid>>,
}

trait FromFwid {
    fn from_fwid(fwid: &Fwid) -> Result<Self> where Self: Sized;
}

impl FromFwid for Measurement {
    fn from_fwid(fwid: &Fwid) -> Result<Self> {
        // map from fwid.hash_algorithm ObjectIdentifier to Measurement enum
        if fwid.hash_algorithm == Sha3_256::OID {
            // pull the associated data from fwid.digest OctetString
            let digest = fwid.digest.as_bytes();
            let digest = Sha3_256Digest::try_from(digest)?;

            Ok(Measurement::Sha3_256(digest))
        } else {
            Err(anyhow!("Unsupported Measurement digest: Sha3_256"))
        }
    }
}

// Check that the measurments in `cert_chain` and `log` are all present in
// the `corpus`. If an unexpected measurement is encountered it is returned
// to the caller in an error.
// NOTE: Before the output from this function can be trusted we must:
// - verify the provided cert chain against a trust anchor
// - verify an attestation from the platform using the provided log
// - verify the integrity of the corpus against a trust anchor
fn verify_measurements<P: AsRef<Path>>(
    cert_chain: P,
    log: P,
    corpus: P,
) -> Result<()> {
    // deserialize MeasurementCorpus
    let corpus = fs::read_to_string(corpus)?;
    let corpus: MeasurementCorpus = serde_json::from_str(&corpus)?;

    // deserialize PkiPath
    let cert_chain = fs::read(cert_chain)?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)?;

    let mut fwids: HashSet<Measurement> = HashSet::new();
    for cert in cert_chain {
        if let Some(extensions) = cert.tbs_certificate.extensions {
            for ext in extensions {
                if ext.extn_id == DICE_TCB_INFO {
                    if !ext.critical {
                        warn!("DiceTcbInfo extension is non-critical");
                    }

                    let mut reader = SliceReader::new(ext.extn_value.as_bytes())?;
                    let header = Header::decode(&mut reader)
                        .context("decode Extension header")?;

                    let tcb_info = DiceTcbInfo::decode_value(&mut reader, header)?;
                    if let Some(ref fwid_vec) = tcb_info.fwids {
                        for fwid in fwid_vec {
                            fwids.insert(Measurement::from_fwid(&fwid)?);
                        }
                    }
                }
            }
        }
    }
    let fwids = fwids;

    for fwid in &fwids {
        println!("fwid: {fwid}");
    }

    // verify that fwids is a subset of corpus
    if fwids.is_subset(&corpus) {
        todo!("Fwids is a subset of Corpus");
    } else {
        todo!("Fwids is NOT a subset of Corpus");
    }

    // deserialize Log
    let log = fs::read_to_string(log)?;
    let log: Log = serde_json::from_str(&log)?;
}

fn verify<P: AsRef<Path>>(
    attest: &dyn Attester,
    ca_cert: &Option<PathBuf>,
    self_signed: bool,
    work_dir: P,
) -> Result<()> {
    // generate nonce from RNG
    info!("getting Nonce from platform RNG");
    let nonce = Nonce::from_platform_rng()?;

    // write nonce to temp dir
    let nonce_path = work_dir.as_ref().join("nonce.bin");
    info!("writing nonce to: {}", nonce_path.display());
    fs::write(&nonce_path, nonce)?;

    // get attestation
    info!("getting attestation");
    let attestation = attest.attest(&nonce)?;
    // serialize attestation to json & write to file
    let mut attestation = serde_json::to_string(&attestation)?;
    attestation.push('\n');
    let attestation_path = work_dir.as_ref().join("attest.json");
    info!("writing attestation to: {}", attestation_path.display());
    fs::write(&attestation_path, &attestation)?;

    // get log
    info!("getting measurement log");
    let log = attest.get_measurement_log()?;
    let mut log = serde_json::to_string(&log)?;
    log.push('\n');
    let log_path = work_dir.as_ref().join("log.json");
    info!("writing measurement log to: {}", log_path.display());
    fs::write(&log_path, &log)?;

    // get cert chain
    info!("getting cert chain");
    let cert_chain_path = work_dir.as_ref().join("cert-chain.pem");
    let mut cert_chain = File::create(&cert_chain_path)?;
    let alias_cert_path = work_dir.as_ref().join("alias.pem");
    let certs = attest.get_certificates()?;
    // the first cert in the chain / the leaf cert is the one
    // used to sign attestations
    info!("writing alias cert to: {}", alias_cert_path.display());
    let pem = certs[0].to_pem(LineEnding::default())?;
    fs::write(&alias_cert_path, pem)?;

    for (index, cert) in certs.iter().enumerate() {
        info!("writing cert[{}] to: {}", index, cert_chain_path.display());
        let pem = cert.to_pem(LineEnding::default())?;
        cert_chain.write_all(pem.as_bytes())?;
    }

    verify_attestation(
        &alias_cert_path,
        &attestation_path,
        &log_path,
        &nonce_path,
    )?;
    info!("attestation verified");
    verify_cert_chain(ca_cert, &cert_chain_path, self_signed)?;
    info!("cert chain verified");
    Ok(())
}

fn verify_attestation(
    alias_cert: &PathBuf,
    attestation: &PathBuf,
    log: &PathBuf,
    nonce: &PathBuf,
) -> Result<()> {
    info!("verifying attestation");
    let attestation = fs::read_to_string(attestation)?;
    let attestation: Attestation = serde_json::from_str(&attestation)?;

    // deserialize Log from json & serialize to hubpacked bytes
    let log = fs::read_to_string(log)?;
    let log: Log = serde_json::from_str(&log)?;
    let mut buf = vec![0u8; Log::MAX_SIZE];
    hubpack::serialize(&mut buf, &log)
        .map_err(|_| anyhow!("failed to serialize Log"))?;
    let log = buf;

    let nonce = fs::read(nonce)?;
    let nonce = Nonce::try_from(nonce)?;

    let alias = fs::read(alias_cert)?;
    let alias = Certificate::from_pem(&alias)?;

    dice_verifier::verify_attestation(&alias, &attestation, &log, &nonce)
}

fn verify_cert_chain(
    ca_cert: &Option<PathBuf>,
    cert_chain: &PathBuf,
    self_signed: bool,
) -> Result<()> {
    info!("veryfying cert chain");
    if !self_signed && ca_cert.is_none() {
        return Err(anyhow!("`ca-cert` or `self-signed` is required"));
    }

    let cert_chain = fs::read(cert_chain)?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)?;

    let root = match ca_cert {
        Some(r) => {
            let root = fs::read(r)?;
            Some(Certificate::from_pem(root)?)
        }
        None => {
            warn!("allowing self-signed cert chain");
            None
        }
    };

    let verifier = PkiPathSignatureVerifier::new(root)?;
    verifier.verify(&cert_chain)
}
