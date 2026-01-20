// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::{Error, Result};
use manager::IamCache;
use rustfs_ecstore::store::ECStore;
use std::sync::{Arc, OnceLock};
use std::any::Any;
use store::{Store, object::ObjectStore};
use sys::IamSys;
use tracing::{error, info, instrument};

pub mod cache;
pub mod error;
pub mod manager;
pub mod store;
pub mod sys;
pub mod utils;

static IAM_SYS: OnceLock<Arc<IamSys<ObjectStore>>> = OnceLock::new();

// Generic IAM system that works with any Store implementation
static IAM_SYS_GENERIC: OnceLock<Arc<dyn Any + Send + Sync>> = OnceLock::new();

/// Initialize IAM with any Store implementation
///
/// This function allows using SQLite, PostgreSQL, or custom storage backends
/// without modifying the IAM system code.
///
/// # Example
///
/// ```no_run
/// use rustfs_iam::init_iam_with_store;
/// use storage_sqlite::SqliteIamStore;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let conn_mgr = storage_sqlite::ConnectionManager::new("/path/to/iam.db")?;
/// let store = SqliteIamStore::new(conn_mgr);
/// init_iam_with_store(store).await?;
/// # Ok(())
/// # }
/// ```
pub async fn init_iam_with_store<S: Store + Send + Sync + 'static>(
    store: S,
) -> Result<()> {
    if IAM_SYS_GENERIC.get().is_some() {
        info!("IAM system already initialized, skipping.");
        return Ok(());
    }

    info!("Starting IAM system initialization with generic store...");

    let cache_manager = IamCache::new(store).await;
    let iam_instance = Arc::new(IamSys::new(cache_manager));

    if IAM_SYS_GENERIC.set(iam_instance).is_err() {
        error!("Critical: Race condition detected during IAM initialization!");
        return Err(Error::IamSysAlreadyInitialized);
    }

    info!("IAM system initialization completed successfully.");
    Ok(())
}

/// Get IAM system instance (type-safe for specific Store type)
///
/// This function retrieves the global IAM system instance initialized with
/// `init_iam_with_store()`. The type parameter `S` must match the Store type
/// used during initialization.
///
/// # Example
///
/// ```no_run
/// use rustfs_iam::get_iam_sys;
/// use storage_sqlite::SqliteIamStore;
///
/// let iam_sys = get_iam_sys::<SqliteIamStore>()?;
/// # Ok::<(), rustfs_iam::error::Error>(())
/// ```
pub fn get_iam_sys<S: Store + 'static>() -> Result<Arc<IamSys<S>>> {
    IAM_SYS_GENERIC.get()
        .and_then(|any| any.downcast_ref::<Arc<IamSys<S>>>())
        .map(Arc::clone)
        .ok_or(Error::IamSysNotInitialized)
}

#[instrument(skip(ecstore))]
pub async fn init_iam_sys(ecstore: Arc<ECStore>) -> Result<()> {
    if IAM_SYS.get().is_some() {
        info!("IAM system already initialized, skipping.");
        return Ok(());
    }

    info!("Starting IAM system initialization sequence...");

    // 1. Create the persistent storage adapter
    let storage_adapter = ObjectStore::new(ecstore);

    // 2. Create the cache manager.
    // The `new` method now performs a blocking initial load from disk.
    let cache_manager = IamCache::new(storage_adapter).await;

    // 3. Construct the system interface
    let iam_instance = Arc::new(IamSys::new(cache_manager));

    // 4. Securely set the global singleton
    if IAM_SYS.set(iam_instance).is_err() {
        error!("Critical: Race condition detected during IAM initialization!");
        return Err(Error::IamSysAlreadyInitialized);
    }

    info!("IAM system initialization completed successfully.");
    Ok(())
}

#[inline]
pub fn get() -> Result<Arc<IamSys<ObjectStore>>> {
    let sys = IAM_SYS.get().map(Arc::clone).ok_or(Error::IamSysNotInitialized)?;

    // Double-check the internal readiness state. The OnceLock is only set
    // after initialization and data loading complete, so this is a defensive
    // guard to ensure callers never operate on a partially initialized system.
    if !sys.is_ready() {
        return Err(Error::IamSysNotInitialized);
    }

    Ok(sys)
}

pub fn get_global_iam_sys() -> Option<Arc<IamSys<ObjectStore>>> {
    IAM_SYS.get().cloned()
}
