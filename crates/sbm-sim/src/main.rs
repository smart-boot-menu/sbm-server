use sbm_sim::{Device, Mode};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "enroll" => enroll(&mut args).await,
        "once" => once(&mut args).await,
        "run" => run(&mut args).await,
        "recovery" => recovery(&mut args).await,
        "identity" => identity(&mut args),
        _ => {
            usage();
            return ExitCode::from(2);
        }
    };
    if let Err(err) = result {
        eprintln!("sbm-sim: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

async fn enroll(args: &mut impl Iterator<Item = String>) -> Result<(), sbm_sim::SimError> {
    let flags = flags(args);
    let mut device = Device::fresh(flag(&flags, "hostname")?.unwrap_or("sbm-sim"));
    let ca_pem = std::fs::read_to_string(
        flag(&flags, "ca-pem")?
            .ok_or_else(|| sbm_sim::SimError("--ca-pem is required".to_string()))?,
    )
    .map_err(|err| sbm_sim::SimError(err.to_string()))?;
    let response = device
        .enroll(
            flag(&flags, "server")?
                .ok_or_else(|| sbm_sim::SimError("--server is required".to_string()))?,
            flag(&flags, "token")?
                .ok_or_else(|| sbm_sim::SimError("--token is required".to_string()))?,
            &ca_pem,
            flag(&flags, "fingerprint")?
                .ok_or_else(|| sbm_sim::SimError("--fingerprint is required".to_string()))?,
        )
        .await?;
    let path = state_path(&flags)?;
    device.save(&path)?;
    println!(
        "enrolled {} (simulated, no hardware reboot)",
        response.device_id
    );
    Ok(())
}

async fn once(args: &mut impl Iterator<Item = String>) -> Result<(), sbm_sim::SimError> {
    let flags = flags(args);
    let mut device = Device::load(&state_path(&flags)?)?;
    let mode = Mode::parse(flag(&flags, "mode")?.unwrap_or("uefi"))?;
    let report = device.sync_once(mode).await?;
    device.save(&state_path(&flags)?)?;
    println!(
        "executed {} command(s), rejected {} (simulated, no machine rebooted)",
        report.executed.len(),
        report.rejected.len()
    );
    Ok(())
}

async fn run(args: &mut impl Iterator<Item = String>) -> Result<(), sbm_sim::SimError> {
    let flags = flags(args);
    let path = state_path(&flags)?;
    let mode = Mode::parse(flag(&flags, "mode")?.unwrap_or("uefi"))?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            result = async {
                let mut device = Device::load(&path)?;
                let report = device.sync_once(mode).await?;
                device.save(&path)?;
                if !report.executed.is_empty() || !report.rejected.is_empty() {
                    println!(
                        "executed {} rejected {} (simulated, no machine rebooted)",
                        report.executed.len(),
                        report.rejected.len()
                    );
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok::<(), sbm_sim::SimError>(())
            } => result?,
        }
    }
}

fn identity(args: &mut impl Iterator<Item = String>) -> Result<(), sbm_sim::SimError> {
    let flags = flags(args);
    let device = Device::load(&state_path(&flags)?)?;
    print!("{}", device.identity_pem());
    Ok(())
}

async fn recovery(args: &mut impl Iterator<Item = String>) -> Result<(), sbm_sim::SimError> {
    let flags = flags(args);
    let device = Device::load(&state_path(&flags)?)?;
    let session = flag(&flags, "session")?
        .ok_or_else(|| sbm_sim::SimError("--session is required".to_string()))?
        .to_string();
    let kind = flag(&flags, "kind")?.unwrap_or("vnc").to_string();
    println!("dialing recovery session {session} ({kind}). This is not a hardware console.");
    device.recovery(&session, &kind).await
}

fn state_path(flags: &[(String, String)]) -> Result<PathBuf, sbm_sim::SimError> {
    flag(flags, "state")?
        .map(PathBuf::from)
        .ok_or_else(|| sbm_sim::SimError("--state is required".to_string()))
}

fn flag<'a>(
    flags: &'a [(String, String)],
    name: &str,
) -> Result<Option<&'a str>, sbm_sim::SimError> {
    let mut found = None;
    for (key, value) in flags {
        if key == name {
            found = Some(value.as_str());
        }
    }
    Ok(found)
}

fn flags(args: &mut impl Iterator<Item = String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let raw: Vec<String> = args.collect();
    let mut index = 0;
    while index < raw.len() {
        if let Some(name) = raw[index].strip_prefix("--") {
            let value = raw.get(index + 1).cloned().unwrap_or_default();
            out.push((name.to_string(), value));
            index += 2;
        } else {
            index += 1;
        }
    }
    out
}

fn usage() {
    eprintln!(
        "sbm-sim enroll --server URL --token TOKEN --ca-pem FILE --fingerprint sha256:... --hostname NAME --state FILE\n\
         sbm-sim once --state FILE [--mode uefi|core]\n\
         sbm-sim run --state FILE [--mode uefi|core]\n\
         sbm-sim recovery --state FILE --session ID [--kind vnc|terminal]\n\
         sbm-sim identity --state FILE\n\
         \n\
         This client is simulated. It never reboots the machine it runs on."
    );
}
