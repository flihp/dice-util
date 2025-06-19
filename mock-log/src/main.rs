use attest_data::{Log, Sha3_256Digest};
use clap::Parser;
use hubpack::SerializedSize;
use miette::{IntoDiagnostic, Result, miette};
use std::{fs, io::{self, Write}, path::PathBuf};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// path to KDL file describing the CoRIM
    kdl: PathBuf,
}

#[derive(knuffel::Decode, Debug)]
struct Document {
    #[knuffel(children)]
    pub measurements: Vec<Measurement>,
}

#[derive(knuffel::Decode, Debug)]
struct Measurement {
    #[knuffel(child, unwrap(argument))]
    pub algorithm: String,

    #[knuffel(child, unwrap(argument))]
    pub digest: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let kdl = fs::read_to_string(&args.kdl).into_diagnostic()?;
    let doc: Document = knuffel::parse(&args.kdl.to_string_lossy(), &kdl)?;

    let mut log = Log::default();
    for measurement in doc.measurements {
        let measurement = if measurement.algorithm == "sha3-256" {
            let digest = hex::decode(measurement.digest)
                .into_diagnostic()
                .map_err(|e| miette!("decode digest hex: {e}"))?;
            let digest = Sha3_256Digest::try_from(digest).into_diagnostic()?;
            attest_data::Measurement::Sha3_256(digest)
        } else {
            return Err(miette!(
                "unsupported digest algorithm: {}",
                measurement.algorithm
            ));
        };

        log.push(measurement);
    }

    let mut out = vec![0u8; Log::MAX_SIZE];
    let size = hubpack::serialize(&mut out, &log).into_diagnostic()?;

    Ok(io::stdout().write_all(&out[..size]).into_diagnostic()?)
}
