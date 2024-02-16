// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use const_oid::{
    AssociatedOid,
    db::{rfc4519, rfc8410::ID_ED_25519},
};
use ed25519_dalek::{
    Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use std::{
    fmt::Debug,
    fs::File,
    io::{self, Read},
    path::PathBuf,
    str,
};
use x509_cert::der::Tagged;
use x509_cert::{
    der::{DecodePem, Encode, Tag},
    request::{CertReq, Version},
    Certificate,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Interface used for communication with the Attest task.
    #[clap(long, env)]
    csr: Option<PathBuf>,

    // these are required ... should be positional
    /// cert for signing key
    #[clap(env)]
    signer_cert: PathBuf,
}

const COUNTRY: &str = "US";
const ORGANIZATION: &str = "Oxide Computer Company";

fn check_signature(csr: &CertReq) -> Result<()> {
    // check signature over CSR:
    // - get public key from CertReqInfo
    let spki = &csr.info.public_key;
    if spki.algorithm.oid != ID_ED_25519 {
        return Err(anyhow!(
            "wrong algorithm OID from CSR SPKI: {}",
            spki.algorithm.oid
        ));
    }
    let verifying_key: [u8; PUBLIC_KEY_LENGTH] = spki
        .subject_public_key
        .as_bytes()
        .context("Failed to get public key as bytes")?
        .try_into()
        .context("Failed to convert public key from CSR to sized array")?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key)?;

    // - get signature from CertReq
    let signature: [u8; SIGNATURE_LENGTH] = csr
        .signature
        .as_bytes()
        .context("Failed to get signature as bytes")?
        .try_into()
        .context("Failed to convert signatyre from CSR to sized array")?;
    let signature = Signature::from_bytes(&signature);

    // - use this to check signature over the CertReqInfo
    let req_info = csr.info.to_der()?;
    verifying_key
        .verify(&req_info, &signature)
        .context("Failed to verify signature over CSR")
}

fn check_subject(csr: &CertReq) -> Result<()> {
    // csr.info.subject is a 'Name'. This is is an alias for an `RdnSequence`.
    // An `RdnSequence` is a NewType wrapping a
    // `Vec<RelativeDistinguishedName>`. A `RelativeDistinguishedName` is a
    // NewType wrapping a `SetOfVec<AttributeTypeAndValue>`. All of this is to
    // say that we typcially think of the RDN as the tuple `(attribute, value)`
    // when it's actually a sequence of this tuple. In practice this sequence
    // is always a sequence of 1.
    for rdn in csr.info.subject.0.iter() {
        for (i, atv) in rdn.0.iter().enumerate() {
            if i != 0 {
                return Err(anyhow!(
                    "RDN has more than one (attribute, value)"
                ));
            }
            match atv.oid {
                rfc4519::COUNTRY_NAME => {
                    // 2.5.4.6 is defined as a `PrintableString` which is a
                    // subset of utf8
                    let tag = atv.value.tag();
                    if tag != Tag::PrintableString {
                        return Err(anyhow!(
                            "Subject has invalid tag for `Country`: {}",
                            tag
                        ));
                    }
                    let country = str::from_utf8(atv.value.value()).context(
                        "Failed to decode `Country` value as UTF8 string",
                    )?;
                    if country != COUNTRY {
                        return Err(anyhow!(format!(
                            "Subject contains invalid `country`: {}",
                            country
                        )));
                    }
                }
                rfc4519::ORGANIZATION_NAME => {
                    // 2.5.4.10 is defined as a `UTF8String`
                    let tag = atv.value.tag();
                    if tag != Tag::Utf8String {
                        return Err(anyhow!(
                            "Subject has invalid tag for `Organization`: {}",
                            tag
                        ));
                    }
                    let org = str::from_utf8(atv.value.value()).context(
                        "Failed to decode `Organization` value as UTF8 string",
                    )?;
                    if org != ORGANIZATION {
                        return Err(anyhow!(format!(
                            "Subject contains invalid `organization`: {}",
                            org
                        )));
                    }
                }
                rfc4519::COMMON_NAME => {
                    // 2.5.4.3 is defined as a `UTF8String`
                    let tag = atv.value.tag();
                    if tag != Tag::Utf8String {
                        return Err(anyhow!(
                            "Subject has invalid tag for `CommonName`: {}",
                            tag
                        ));
                    }
                    let cn = str::from_utf8(atv.value.value()).context(
                        "Failed to decode `CommonName` value as UTF8 string",
                    )?;
                    dice_mfg_msgs::validate_pdv2(cn).with_context(|| {
                        format!(
                            "Subject `CommonName` is not valid PDV2 string: {}",
                            cn
                        )
                    })?;
                }
                _ => return Err(anyhow!("Unexpected oid in RDN")),
            }
        }
    }

    Ok(())
}

fn check_csr(csr: &CertReq) -> Result<()> {
    check_signature(csr)?;
    // - version field must be 1
    // NOTE: only a single version number is valid so I think the CSR will
    // fail to parse if the version isn't 1 ... but we check anyway
    if csr.info.version != Version::V1 {
        return Err(anyhow!("CSR version is not 1"));
    };

    check_subject(csr)?;

    // alternatively we could evaluate the attributes for validity & copy them
    // like we do the subject
    let len = csr.info.attributes.len();
    if len != 0 {
        return Err(anyhow!("Expected CSR to have no extensions, got {}", len));
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // if args.csr file not provided use stdin
    let mut reader: Box<dyn Read> = match args.csr {
        Some(i) => Box::new(File::open(i)?),
        None => Box::new(io::stdin()),
    };

    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf)?;
    let buf = buf;

    let csr = CertReq::from_pem(buf)?;

    println!("csr: {:?}", csr);

    check_csr(&csr)?;

    // read cert
    let mut cert = File::open(args.signer_cert)?;
    let mut buf = Vec::new();
    let _ = cert.read_to_end(&mut buf)?;
    let buf = buf;

    let signer_cert = Certificate::from_pem(buf)?;
    println!("signer_cert: {:?}", signer_cert);

    // cert 'issuer' = get from cert for signing key
    let issuer = signer_cert.tbs_certificate.subject;
    println!("issuer: {:?}", issuer);

    // if cert has a subject public key identifier extension copy it (how?)
    // else get public key from the signer_cert and hash it manually
    let mut authority_key_identifier = None;
    if let Some(exts) = signer_cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == x509_cert::ext::pkix::SubjectKeyIdentifier::OID {
                authority_key_identifier = Some(ext)
            }
        }
    }
    // no more mut
    let authority_key_identifier = authority_key_identifier;
    println!("authority_key_identifier: {:?}", authority_key_identifier);

    //let authority_key_identifier = for ext in signer_cert.tbs_certificate.extensions

    // cert 'subject' = csr.info.subject
    // cert 'subject_public_key_info' (aka spki) = csr.info.public_key
    // extensions
    //
    // X509v3 Subject Key Identifier: 
    //     73:9C:9D:2E:FE:E2:69:3A:5A:50:AA:A7:27:5A:13:41:0F:88:16:74
    // cert 'subject_key_identifier' = sha1(csr.info.public_key.subject_public_key
    //
    // X509v3 Authority Key Identifier: 
    //     70:D7:A7:C5:2B:17:1C:0C:82:9F:E7:DC:04:05:3A:2D:F7:36:4E:94
    // cert 'authority_key_identifier' = get from cert for signing key
    //
    // X509v3 Basic Constraints: critical
    //     CA:TRUE
    // let basic = pub struct BasicConstraints {
    //     ca: true
    //     path_len_constraint: None,
    // }
    // let ext = x509_cert::ext::Extension {
    //     extn_id: x509_cert::ext::pkix::BasicConstraints::OID,
    //     critical: true,
    //     extn_value: x509_cert::der::asn1::OctetString::new(basic.to_der())?,
    // }
    //
    // then add `ext` to a Vec<x509_cert::ext::Extension>
    //
    // X509v3 Key Usage: critical
    //     Certificate Sign, CRL Sign
    // X509v3 Certificate Policies: critical
    //     Policy: 1.3.6.1.4.1.57551.1.3
    //     Policy: 2.23.133.5.4.100.6
    //     Policy: 2.23.133.5.4.100.8
    //     Policy: 2.23.133.5.4.100.12
    // policy
    // cert extensions = manually create
    //
    // then set `tbs_cert.extensions to Some(ext)

    Ok(())
}
