// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use camino::Utf8PathBuf;
use miette::{IntoDiagnostic, Result, WrapErr};

use std::env;

fn main() -> Result<()> {
    // output directory where we put:
    // generated test inputs
    let out = Utf8PathBuf::from(
        env::var("OUT_DIR")
            .into_diagnostic()
            .wrap_err("Could not get OUT_DIR")?,
    );

    let config_path = "test-pki.kdl";
    let doc = pki_playground::config::load_and_validate(config_path.as_ref())
        .wrap_err(format!(
        "Loading config from \"{}\" failed",
        config_path
    ))?;

    let behavior = pki_playground::OutputFileExistsBehavior::Skip;

    doc.write_key_pairs(out.clone(), behavior)?;
    doc.write_certificates(out.clone(), behavior)?;
    doc.write_certificate_lists(out.clone(), behavior)?;

    Ok(())
}
