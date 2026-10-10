use s2_common::{
    basin::{BasinInfo, BasinName, ListBasinsRequest},
    config::{BasinConfig, BasinReconfiguration},
    resources::{Page, ProvisionMode, ProvisionResult, RequestToken},
    stream::StreamNameStartAfter,
};
use s2_storage::bash::Bash;
use slatedb::{
    IsolationLevel,
    config::{DurabilityLevel, ScanOptions},
};
use time::OffsetDateTime;

use super::{
    Backend,
    bgtasks::BgtaskTrigger,
    store::{db_txn_commit_durable, db_txn_get, db_txn_get_with},
};
use crate::backend::{
    error::{
        BasinAlreadyExistsError, BasinDeletionPendingError, BasinNotFoundError, DeleteBasinError,
        GetBasinConfigError, ListBasinsError, ProvisionBasinError, ReconfigureBasinError,
    },
    kv,
};

impl Backend {
    pub async fn list_basins(
        &self,
        request: ListBasinsRequest,
    ) -> Result<Page<BasinInfo>, ListBasinsError> {
        let mut authorization = self
            .pki
            .as_ref()
            .map(|identity| {
                identity.collection_authorizer(
                    s2_common::access::Operation::ListBasins,
                    None,
                    OffsetDateTime::now_utc().unix_timestamp(),
                )
            })
            .transpose()
            .map_err(super::error::StorageError::from)?;
        let ListBasinsRequest {
            prefix,
            start_after,
            limit,
        } = request;

        let key_range = kv::basin_meta::ser_key_range(&prefix, &start_after);
        let key_range = if let Some(auth) = &authorization {
            super::pki::intersect_list_range(key_range, auth.resource_scope(), |value| {
                let prefix = value.parse::<s2_common::basin::BasinNamePrefix>().ok()?;
                Some(
                    kv::basin_meta::ser_key_prefix(&prefix)
                        ..kv::basin_meta::ser_key_prefix_end(&prefix),
                )
            })
        } else {
            key_range
        };
        if key_range.is_empty() {
            return Ok(Page::new_empty());
        }

        let scan_opts = ScanOptions {
            durability_filter: DurabilityLevel::Remote,
            ..Default::default()
        };
        let mut it = self.db.scan_with_options(key_range, &scan_opts).await?;

        let mut basins = Vec::with_capacity(limit.as_usize());
        let mut has_more = false;
        while let Some(kv) = it.next().await? {
            let basin = kv::basin_meta::deser_key(kv.key)?;
            assert!(basin.as_ref() > start_after.as_ref());
            assert!(basin.as_ref() >= prefix.as_ref());
            if let Some(auth) = &mut authorization
                && !auth
                    .authorize_candidate(basin.as_ref(), OffsetDateTime::now_utc().unix_timestamp())
                    .map_err(super::error::StorageError::from)?
            {
                continue;
            }
            if basins.len() == limit.as_usize() {
                has_more = true;
                break;
            }
            let meta = kv::basin_meta::deser_value(kv.value)?;
            basins.push(BasinInfo {
                name: basin,
                location: None,
                created_at: meta.created_at,
                deleted_at: meta.deleted_at,
            });
        }
        if let Some(auth) = &authorization {
            auth.check_active(OffsetDateTime::now_utc().unix_timestamp())
                .map_err(super::error::StorageError::from)?;
        }
        Ok(Page::new(basins, has_more))
    }

    /// Any outcome asserting the basin exists — `Created`, `Updated`, `Noop`,
    /// or `BasinAlreadyExists` — is readable at `DurabilityLevel::Remote`.
    pub async fn provision_basin(
        &self,
        basin: BasinName,
        config: BasinConfig,
        mode: ProvisionMode,
    ) -> Result<ProvisionResult<BasinInfo>, ProvisionBasinError> {
        let meta_key = kv::basin_meta::ser_key(&basin);

        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        // A transaction can see metadata that has not been flushed yet.
        let (existing_meta, existing_seq) = db_txn_get_with(&txn, &meta_key, |entry| {
            Ok((kv::basin_meta::deser_value(entry.value)?, entry.seq))
        })
        .await?
        .unzip();
        let permission = if existing_meta.is_some() && matches!(mode, ProvisionMode::Ensure) {
            s2_common::access::Operation::ReconfigureBasin
        } else {
            s2_common::access::Operation::CreateBasin
        };
        self.authorize(permission, Some(basin.as_ref()), None)?;
        if let Some(existing_meta) = &existing_meta
            && existing_meta.deleted_at.is_some()
        {
            return Err(BasinDeletionPendingError { basin }.into());
        }

        let outcome = match (existing_meta, mode) {
            (Some(existing), ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                let result = if new_creation_idempotency_key.is_some()
                    && existing.creation_idempotency_key == new_creation_idempotency_key
                {
                    Ok(ProvisionResult::Noop(BasinInfo {
                        name: basin,
                        location: None,
                        created_at: existing.created_at,
                        deleted_at: None,
                    }))
                } else {
                    Err(BasinAlreadyExistsError { basin }.into())
                };
                drop(txn);
                self.await_durable_seq(existing_seq.expect("existing meta was read"))
                    .await?;
                return result;
            }
            (Some(existing), ProvisionMode::Ensure) => {
                let meta = kv::basin_meta::BasinMeta {
                    config,
                    created_at: existing.created_at,
                    deleted_at: None,
                    creation_idempotency_key: existing.creation_idempotency_key,
                };
                if existing.config == meta.config {
                    ProvisionResult::Noop(meta)
                } else {
                    ProvisionResult::Updated(meta)
                }
            }
            (None, ProvisionMode::CreateOnly { request_token }) => {
                let new_creation_idempotency_key = request_token
                    .as_ref()
                    .map(|req_token| creation_idempotency_key(req_token, &config));
                ProvisionResult::Created(kv::basin_meta::BasinMeta {
                    config,
                    created_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                    creation_idempotency_key: new_creation_idempotency_key,
                })
            }
            (None, ProvisionMode::Ensure) => ProvisionResult::Created(kv::basin_meta::BasinMeta {
                config,
                created_at: OffsetDateTime::now_utc(),
                deleted_at: None,
                creation_idempotency_key: None,
            }),
        };

        if matches!(&outcome, ProvisionResult::Noop(_)) {
            drop(txn);
            self.await_durable_seq(existing_seq.expect("noop implies existing meta"))
                .await?;
        } else {
            let meta = outcome.inner();
            txn.put(&meta_key, kv::basin_meta::ser_value(meta))?;

            db_txn_commit_durable(txn).await?;
        }

        Ok(outcome.map(|meta| BasinInfo {
            name: basin,
            location: None,
            created_at: meta.created_at,
            deleted_at: None,
        }))
    }

    pub async fn get_basin_config(
        &self,
        basin: BasinName,
    ) -> Result<BasinConfig, GetBasinConfigError> {
        self.authorize(
            s2_common::access::Operation::GetBasinConfig,
            Some(basin.as_ref()),
            None,
        )?;
        self.basin_config_internal(basin).await
    }

    pub(super) async fn basin_config_internal(
        &self,
        basin: BasinName,
    ) -> Result<BasinConfig, GetBasinConfigError> {
        let Some(meta) = self
            .db_get(kv::basin_meta::ser_key(&basin), kv::basin_meta::deser_value)
            .await?
        else {
            return Err(BasinNotFoundError { basin }.into());
        };
        Ok(meta.config)
    }

    pub async fn reconfigure_basin(
        &self,
        basin: BasinName,
        reconfig: BasinReconfiguration,
    ) -> Result<BasinConfig, ReconfigureBasinError> {
        self.authorize(
            s2_common::access::Operation::ReconfigureBasin,
            Some(basin.as_ref()),
            None,
        )?;
        let meta_key = kv::basin_meta::ser_key(&basin);

        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;

        let Some(mut meta) = db_txn_get(&txn, &meta_key, kv::basin_meta::deser_value).await? else {
            return Err(BasinNotFoundError { basin }.into());
        };

        if meta.deleted_at.is_some() {
            return Err(BasinDeletionPendingError { basin }.into());
        }

        meta.config = meta.config.reconfigure(reconfig);

        txn.put(&meta_key, kv::basin_meta::ser_value(&meta))?;

        db_txn_commit_durable(txn).await?;

        Ok(meta.config)
    }

    pub async fn delete_basin(&self, basin: BasinName) -> Result<(), DeleteBasinError> {
        self.authorize(
            s2_common::access::Operation::DeleteBasin,
            Some(basin.as_ref()),
            None,
        )?;
        let txn = self.db.begin(IsolationLevel::SerializableSnapshot).await?;
        let meta_key = kv::basin_meta::ser_key(&basin);
        let Some((mut meta, seq)) = db_txn_get_with(&txn, &meta_key, |entry| {
            Ok((kv::basin_meta::deser_value(entry.value)?, entry.seq))
        })
        .await?
        else {
            return Err(BasinNotFoundError { basin }.into());
        };
        if meta.deleted_at.is_none() {
            meta.deleted_at = Some(OffsetDateTime::now_utc());
            txn.put(&meta_key, kv::basin_meta::ser_value(&meta))?;
            txn.put(
                kv::basin_deletion_pending::ser_key(&basin),
                kv::basin_deletion_pending::ser_value(&StreamNameStartAfter::default()),
            )?;
            db_txn_commit_durable(txn).await?;
        } else {
            // A retry may observe the marker before the first delete has flushed.
            drop(txn);
            self.await_durable_seq(seq).await?;
        }
        self.bgtask_trigger(BgtaskTrigger::BasinDeletion);
        Ok(())
    }
}

fn creation_idempotency_key(req_token: &RequestToken, config: &BasinConfig) -> Bash {
    Bash::length_prefixed(&[
        req_token.as_bytes(),
        &serde_json::to_vec(&s2_api::v1::config::BasinConfig::from(config.clone()))
            .expect("serializable"),
    ])
}
