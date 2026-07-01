// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use anyhow::{anyhow, Context};

fn main() -> Result<()> {
    // output directory where we put:
    // generated test inputs
    let mut out =
        PathBuf::from(env::var("OUT_DIR").context("Could not get OUT_DIR")?);

    let config_path = "config.kdl";
    let doc = pki_playground::config::load_and_validate(&config_path)
        .wrap_err(format!("Loading config from \"{}\" failed", config_path))?;

    doc.write_key_pairs(out, action_opts.output_exists)?;
    doc.write_certificates(out, action_opts.output_exists)
    doc.write_certificate_lists(out, action_opts.output_exists)?;
}
