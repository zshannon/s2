use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    result::Result,
};

use clap::Subcommand;
use s2_pki_auth::*;
use serde::{Deserialize, Serialize};

use crate::{
    config::{self, AuthMethod, CliConfig, CredentialStore, StoredCredentialReference},
    credential_store::{self, CredentialKind},
    error::CliError,
};
#[derive(Subcommand, Debug)]
pub enum PkiCommand {
    /// Generate a P-256 key; write the private key in a new mode-0600 file.
    Keygen {
        #[arg(long)]
        private_key_file: PathBuf,
        #[arg(long)]
        public_key_file: Option<PathBuf>,
    },
    /// Issue an issuer-signed grant to a client public key.
    Issue {
        #[arg(long)]
        issuer_key_file: PathBuf,
        #[arg(long)]
        client_key: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        scope_file: PathBuf,
        #[arg(long)]
        expires_at: i64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a delegation with the current holder's key; omit client-key to restrict the same
    /// holder.
    Delegate {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        grant_file: PathBuf,
        #[arg(long)]
        client_key: Option<String>,
        #[arg(long)]
        scope_file: Option<PathBuf>,
        #[arg(long)]
        expires_at: Option<i64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify and inspect a grant's native Datalog blocks and delegation metadata.
    Inspect {
        #[arg(long)]
        grant_file: PathBuf,
    },
    /// Store a matching private key and grant and select exclusive PKI mode.
    Set {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        grant_file: PathBuf,
        #[arg(long)]
        insecure_storage: bool,
    },
    /// Remove the stored PKI credential.
    Remove,
    /// Revoke a grant and its descendants through the configured PKI server.
    Revoke {
        #[arg(long)]
        grant_file: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantFile {
    issuer: ClientPublicKey,
    grant: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    key: String,
    issuer: ClientPublicKey,
    grant: String,
}
fn err(e: impl std::fmt::Display) -> CliError {
    CliError::Pki(e.to_string())
}
fn key(path: &Path) -> Result<ClientKey, CliError> {
    ClientKey::from_base58(fs::read_to_string(path).map_err(err)?.trim()).map_err(err)
}
fn grant(path: &Path) -> Result<Grant, CliError> {
    let document: GrantFile = serde_json::from_slice(&fs::read(path).map_err(err)?).map_err(err)?;
    Grant::from_base64(&document.grant, document.issuer).map_err(err)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)
}
fn write_grant(path: &Path, grant: &Grant) -> Result<(), CliError> {
    write_new(
        path,
        &serde_json::to_vec_pretty(&GrantFile {
            issuer: grant.issuer().clone(),
            grant: grant.to_base64(),
        })
        .map_err(err)?,
    )
}
fn scope(path: &Path) -> Result<GrantScope, CliError> {
    serde_json::from_slice(&fs::read(path).map_err(err)?).map_err(err)
}
pub fn load(config: &CliConfig) -> Result<PkiCredentials, String> {
    let reference = config
        .pki
        .as_ref()
        .ok_or("PKI credentials are not configured")?;
    let bytes = credential_store::load(
        CredentialKind::Pki,
        &reference.credential_id,
        reference.credential_store,
    )
    .map_err(|e| e.to_string())?;
    let bundle: Bundle = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let key = ClientKey::from_base58(&bundle.key).map_err(|e| e.to_string())?;
    let grant = Grant::from_base64(&bundle.grant, bundle.issuer).map_err(|e| e.to_string())?;
    PkiCredentials::new(key, grant).map_err(|e| e.to_string())
}
pub fn validate_destination(
    credentials: &PkiCredentials,
    config: &CliConfig,
) -> Result<(), String> {
    let (account, basin) = crate::login::effective_endpoints(config);
    for endpoint in [account, basin] {
        let uri: reqwest::Url = endpoint.parse().map_err(|_| "Invalid PKI endpoint")?;
        if uri.origin().ascii_serialization() != credentials.audience() {
            return Err("PKI credential audience does not match the configured endpoints".into());
        }
    }
    if config.ssl_no_verify == Some(true) {
        return Err("PKI streaming requires verified TLS; disable ssl_no_verify".into());
    }
    Ok(())
}
pub async fn run(command: &PkiCommand) -> Result<(), CliError> {
    match command {
        PkiCommand::Keygen {
            private_key_file,
            public_key_file,
        } => {
            let key = ClientKey::generate();
            write_new(private_key_file, key.to_base58().as_bytes())?;
            if let Some(path) = public_key_file {
                write_new(path, key.public_key().to_base58().as_bytes())?
            } else {
                println!("{}", key.public_key().to_base58())
            }
        }
        PkiCommand::Issue {
            issuer_key_file,
            client_key,
            audience,
            scope_file,
            expires_at,
            out,
        } => {
            let grant = issue_grant(
                &key(issuer_key_file)?,
                &ClientPublicKey::from_base58(client_key).map_err(err)?,
                audience,
                &scope(scope_file)?,
                *expires_at,
            )
            .map_err(err)?;
            write_grant(out, &grant)?
        }
        PkiCommand::Delegate {
            key_file,
            grant_file,
            client_key,
            scope_file,
            expires_at,
            out,
        } => {
            let parent = grant(grant_file)?;
            let key = key(key_file)?;
            let verified = verify_biscuit(
                &parent,
                &TrustedIssuers::new(vec![parent.issuer().clone()]),
                "",
            )
            .map_err(err)?;
            let client = client_key
                .as_ref()
                .map(|k| ClientPublicKey::from_base58(k))
                .transpose()
                .map_err(err)?
                .unwrap_or_else(|| key.public_key());
            let scope = scope_file
                .as_ref()
                .map(|p| scope(p))
                .transpose()?
                .unwrap_or_else(|| verified.scope().clone());
            write_grant(
                out,
                &delegate_grant(
                    &parent,
                    &key,
                    &client,
                    &scope,
                    expires_at.unwrap_or(verified.expires_at()),
                )
                .map_err(err)?,
            )?
        }
        PkiCommand::Inspect { grant_file } => {
            let grant = grant(grant_file)?;
            let verified = verify_biscuit(
                &grant,
                &TrustedIssuers::new(vec![grant.issuer().clone()]),
                "",
            )
            .map_err(err)?;
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"issuer":grant.issuer(),"client":verified.client_public_key(),"audience":verified.audience(),"expires_at":verified.expires_at(),"scope":verified.scope(),"blocks":verified.revocation_identifiers().len(),"datalog_blocks":verified.datalog_blocks().map_err(err)?})).map_err(err)?)
        }
        PkiCommand::Set {
            key_file,
            grant_file,
            insecure_storage,
        } => {
            let key = key(key_file)?;
            let grant = grant(grant_file)?;
            let credentials = PkiCredentials::new(key.clone(), grant.clone()).map_err(err)?;
            let _lock = config::acquire_config_lock().await?;
            let mut config = config::load_config_file()?;
            let previous = config.pki.clone();
            let id = uuid::Uuid::new_v4().to_string();
            let store = if *insecure_storage {
                CredentialStore::File
            } else {
                CredentialStore::Keyring
            };
            let bytes = serde_json::to_vec(&Bundle {
                key: key.to_base58(),
                issuer: grant.issuer().clone(),
                grant: grant.to_base64(),
            })
            .map_err(err)?;
            credential_store::save(CredentialKind::Pki, &id, store, &bytes).map_err(err)?;
            config.pki = Some(StoredCredentialReference {
                credential_id: id.clone(),
                credential_store: store,
            });
            config.auth_method = Some(AuthMethod::Pki);
            config.account_endpoint = Some(credentials.audience().into());
            config.basin_endpoint = Some(credentials.audience().into());
            config.ssl_no_verify = Some(false);
            if let Err(e) = config::save_cli_config(&config) {
                let _ = credential_store::delete(CredentialKind::Pki, &id, store);
                return Err(e.into());
            }
            if let Some(previous) = previous {
                credential_store::delete(
                    CredentialKind::Pki,
                    &previous.credential_id,
                    previous.credential_store,
                )
                .map_err(err)?
            }
            eprintln!("PKI credentials saved and selected");
        }
        PkiCommand::Remove => {
            let _lock = config::acquire_config_lock().await?;
            let mut config = config::load_config_file()?;
            let previous = config.pki.take();
            if config.auth_method == Some(AuthMethod::Pki) {
                config.auth_method = None
            }
            config::save_cli_config(&config)?;
            if let Some(previous) = previous {
                credential_store::delete(
                    CredentialKind::Pki,
                    &previous.credential_id,
                    previous.credential_store,
                )
                .map_err(err)?
            }
        }
        PkiCommand::Revoke { grant_file } => {
            let target = grant(grant_file)?;
            let (config, credential) = crate::login::resolve_access_token().await?;
            credential.validate_destination(&config)?;
            let s2 = s2_sdk::S2::new(credential.configure_sdk(config::sdk_config(
                &config,
                credential.initial_sdk_config(),
                crate::update::user_agent(),
            )?))
            .map_err(err)?;
            s2.revoke_pki_grant(&target).await.map_err(err)?;
            eprintln!("Grant and descendants revoked");
        }
    }
    Ok(())
}
