// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use const_oid::{
    db::{
        rfc4519,
        rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1},
        rfc8410::ID_ED_25519,
    },
    AssociatedOid,
};
use ed25519_dalek::{
    Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use getrandom::getrandom;
use std::{
    fmt::Debug,
    fs::File,
    io::{self, Read},
    path::PathBuf,
    str,
};
use x509_cert::{
    certificate::{self, Certificate},
    der::{asn1::OctetString, DecodePem, Encode, Tag, Tagged},
    ext::{pkix::BasicConstraints, Extension},
    request::{self, CertReq},
    spki::{AlgorithmIdentifierOwned, ObjectIdentifier},
};

#[derive(Clone, Debug, ValueEnum)]
enum Hash {
    Sha384,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Interface used for communication with the Attest task.
    #[clap(long, env)]
    csr: Option<PathBuf>,

    /// Hash function
    #[clap(value_enum, long, env)]
    hash: Option<Hash>,

    /// Cert for signing key
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
    if csr.info.version != request::Version::V1 {
        return Err(anyhow!("CSR version is not 1"));
    };

    check_subject(csr)?;

    // Alternatively we could evaluate the attributes for validity & copy them
    // like we do the subject. This is what a "normal" CA would do but since
    // we only care about creating one type of cert we can keep things simple.
    let len = csr.info.attributes.len();
    if len != 0 {
        return Err(anyhow!("Expected CSR to have no extensions, got {}", len));
    }

    Ok(())
}

fn get_sig_alg(
    signer_cert: &Certificate,
    hash: Option<Hash>,
) -> Result<AlgorithmIdentifierOwned> {
    let signer_key_type = &signer_cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm;
    match &signer_key_type.oid {
        &ID_EC_PUBLIC_KEY => {
            match &signer_key_type.parameters {
                Some(p) => {
                    if p.tag() != Tag::ObjectIdentifier {
                        return Err(anyhow!(
                            "unexpected tag for ID_EC_PUBLIC_KEY: {:?}",
                            p.tag()
                        ));
                    }

                    let oid: ObjectIdentifier = p.decode_as()?;
                    if oid != SECP_384_R_1 {
                        return Err(anyhow!(
                            "unsupported params for ID_EC_PUBLIC_KEY: {:?}",
                            oid
                        ));
                    }
                    // from the signer's cert we've determined that the key is a p384 / secp384r1 key
                    match hash {
                        // return AlgorithmIdentifier `ecdsa-with-SHA384`
                        Some(Hash::Sha384) => Ok(AlgorithmIdentifierOwned {
                            oid: ECDSA_WITH_SHA_384,
                            parameters: None,
                        }),
                        _ => return Err(anyhow!("ECC keys require a hash function for signing but non provided, seek `--help`")),
                    }
                }
                None => {
                    return Err(anyhow!(
                        "ID_EC_PUBLIC_KEY missing required params"
                    ))
                }
            }
        }
        _ => {
            todo!("unsupported signing key: {:?}", signer_key_type);
        }
    }
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

    println!("csr: {:#?}", csr);

    check_csr(&csr)?;

    // read cert
    let mut cert = File::open(args.signer_cert)?;
    let mut buf = Vec::new();
    let _ = cert.read_to_end(&mut buf)?;
    let buf = buf;

    let signer_cert = Certificate::from_pem(buf)?;
    println!("signer_cert: {:#?}", signer_cert);

    // CREATE CERT
    // pull data from:
    // - csr
    // - issuer cert
    // - calculate / generate ourselves
    //
    // fields:
    // - signature_algorithm: algorithm used to sign the tbs_certificate value
    //   this value will depend on the type of the key and the hash algorithm
    //   used when signing

    // NOTE: gotta do the `signature` last because ... we sign the final
    // tbsCertificate (serialized as DER)
    // - signature: sign(tbs_certificate) w/ alg appropriate for the signing key
    //   this value can be derived from:
    //   - the spki public key algorithm from the cert for the signing key & a
    //   selected hash function
    //   - the private key & a selected hash function
    //
    // - tbsCertificate:
    //   - version: 0x3
    let version = certificate::Version::V3;

    //   - serial number: random value, ensure uniqueness eventually
    let mut serial_number = [0u8; 20];
    getrandom(&mut serial_number)?;
    // NOTE: ensure leading bit in value is clear (see:
    // https://rfd.shared.oxide.computer/rfd/0387#_tbscertificate)
    let serial_number = serial_number;

    //   - signature algorithm
    //   tbsCertificate.signature and the outher signature_algorithm must be
    //   equal per 4.1.1.2
    let sig_alg = get_sig_alg(&signer_cert, args.hash)?;
    println!("signature / signature_algorithm: {:#?}", sig_alg);

    //   - 'issuer' = get from cert for signing key
    let issuer = signer_cert.tbs_certificate.subject;
    println!("issuer: {:#?}", issuer);

    // cert 'subject' = csr.info.subject
    let subject = csr.info.subject;
    println!("subject: {:#}", subject);

    // cert 'subject_public_key_info' (aka spki) = csr.info.public_key
    let spki = &csr.info.public_key;
    println!("subject_public_key_info: {:#?}", spki);

    // extensions
    let mut extensions = Vec::new();

    // X509v3 Authority Key Identifier:
    //     70:D7:A7:C5:2B:17:1C:0C:82:9F:E7:DC:04:05:3A:2D:F7:36:4E:94
    // cert 'authority_key_identifier' = subject key identifier from cert for signing key
    // get the Authority Key Identifier / 2.5.29.35 from the cert for the
    // signing key
    // NOTE: we can (and should) generate this same value from the signers public key
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
    println!("authority_key_identifier: {:#?}", authority_key_identifier);

    if let Some(e) = authority_key_identifier {
        extensions.push(e);
    } else {
        return Err(anyhow!("Cert for signing key is missing Authority Key Identifier extension"));
    }

    // X509v3 Subject Key Identifier:
    //     73:9C:9D:2E:FE:E2:69:3A:5A:50:AA:A7:27:5A:13:41:0F:88:16:74
    // cert 'subject_key_identifier' = sha1(csr.info.public_key.subject_public_key
    let csr_pub = csr.info.public_key.subject_public_key;

    // X509v3 Basic Constraints: critical
    //     CA:TRUE
    let basic_constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };

    let ext = Extension {
        extn_id: BasicConstraints::OID,
        critical: true,
        extn_value: OctetString::new(basic_constraints.to_der()?)?,
    };
    println!("basic_constraints: {:#?}", basic_constraints);
    extensions.push(ext);

    // X509v3 Key Usage: critical
    //     Certificate Sign, CRL Sign

    // X509v3 Certificate Policies: critical
    //     Policy: 1.3.6.1.4.1.57551.1.3
    //     Policy: 2.23.133.5.4.100.6
    //     Policy: 2.23.133.5.4.100.8
    //     Policy: 2.23.133.5.4.100.12
    // policy

    // encode tbsCertificate as DER
    // generate signature over DER encoded tbsCertificate
    // create final certificate structure

    Ok(())
}
