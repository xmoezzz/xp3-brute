//! PBD encoder facade.

use crate::decoder::pbd::encode_pbd_json_file;
use crate::Result;
use std::path::Path;

pub fn rebuild_pbd_from_json(input_json: &Path, output_pbd: &Path) -> Result<()> {
    encode_pbd_json_file(input_json, output_pbd)
        .map_err(|err| crate::Error::format(format!("PBD encode failed: {err}")))
}
