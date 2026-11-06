#![forbid(unsafe_code)]
use anyhow::{Result, bail};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 || args[0] != "seal-crowdsec-key" {
        bail!("usage: openwaf-security seal-crowdsec-key INPUT OUTPUT MASTER_KEY");
    }
    openwaf_security::seal(args[1].as_ref(), args[2].as_ref(), args[3].as_ref())
}
