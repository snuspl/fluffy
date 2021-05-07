// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Open Ethereum.

// Open Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Open Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Open Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use std::fs;
use std::io::{Read, Write, Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};
use std::fmt::{Display, Formatter, Error as FmtError};
use super::migration_rocksdb::{Manager as MigrationManager, Config as MigrationConfig, ChangeColumns, VacuumAccountsBloom};
use super::kvdb_rocksdb::{CompactionProfile, DatabaseConfig};
use ethcore::client::DatabaseCompactionProfile;
use ethcore_db::NUM_COLUMNS;
use types::errors::EthcoreError;

use super::helpers;
use super::blooms::migrate_blooms;

/// The migration from v10 to v11.
/// Adds a column for node info.
pub const TO_V11: ChangeColumns = ChangeColumns {
	pre_columns: 6,
	post_columns: 7,
	version: 11,
};

/// The migration from v11 to v12.
/// Adds a column for light chain storage.
pub const TO_V12: ChangeColumns = ChangeColumns {
	pre_columns: 7,
	post_columns: 8,
	version: 12,
};

/// The migration from v12 to v14.
/// Adds a column for private transactions state storage.
pub const TO_V14: ChangeColumns = ChangeColumns {
	pre_columns: 8,
	post_columns: 9,
	version: 14,
};

/// The migration from v14 to v15.
/// Removes all entries from the COL_ACCOUNTS_BLOOM column
/// NOTE: column 5 is still there, but has no data.
pub const TO_V15: VacuumAccountsBloom = VacuumAccountsBloom {
	column_to_vacuum: 5,
	columns: NUM_COLUMNS,
	version: 15,
};

/// Database is assumed to be at default version, when no version file is found.
const DEFAULT_VERSION: u32 = 5;
/// Current version of database models.
const CURRENT_VERSION: u32 = 15;
/// A version of database at which blooms-db was introduced for header and trace blooms.
const BLOOMS_DB_VERSION: u32 = 13;
/// Defines how many items are migrated to the new version of database at once.
const BATCH_SIZE: usize = 1024;
/// Version file name.
const VERSION_FILE_NAME: &'static str = "db_version";

/// Migration related erorrs.
#[derive(Debug)]
pub enum Error {
	/// Returned when current version cannot be read or guessed.
	UnknownDatabaseVersion,
	/// Existing DB is newer than the known one.
	FutureDBVersion,
	/// Migration is not possible.
	MigrationImpossible,
	/// Blooms-db migration error.
	BloomsDB(EthcoreError),
	/// Migration was completed succesfully,
	/// but there was a problem with io.
	Io(IoError),
}

impl Display for Error {
	fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
		let out = match *self {
			Error::UnknownDatabaseVersion => "Current database version cannot be read".into(),
			Error::FutureDBVersion => "Database was created with newer client version. Upgrade your client or delete DB and resync.".into(),
			Error::MigrationImpossible => format!("Database migration to version {} is not possible.", CURRENT_VERSION),
			Error::BloomsDB(ref err) => format!("blooms-db migration error: {}", err),
			Error::Io(ref err) => format!("Unexpected io error on DB migration: {}.", err),
		};

		write!(f, "{}", out)
	}
}

impl From<IoError> for Error {
	fn from(err: IoError) -> Self {
		Error::Io(err)
	}
}

/// Returns the version file path.
fn version_file_path(path: &Path) -> PathBuf {
	let mut file_path = path.to_owned();
	file_path.push(VERSION_FILE_NAME);
	file_path
}

/// Reads current database version from the file at given path.
/// If the file does not exist returns `DEFAULT_VERSION`.
fn current_version(path: &Path) -> Result<u32, Error> {
	match fs::File::open(version_file_path(path)) {
		Err(ref err) if err.kind() == ErrorKind::NotFound => Ok(DEFAULT_VERSION),
		Err(_) => Err(Error::UnknownDatabaseVersion),
		Ok(mut file) => {
			let mut s = String::new();
			file.read_to_string(&mut s).map_err(|_| Error::UnknownDatabaseVersion)?;
			u32::from_str_radix(&s, 10).map_err(|_| Error::UnknownDatabaseVersion)
		},
	}
}

/// Writes current database version to the file.
/// Creates a new file if the version file does not exist yet.
fn update_version(path: &Path) -> Result<(), Error> {
	fs::create_dir_all(path)?;
	let mut file = fs::File::create(version_file_path(path))?;
	file.write_all(format!("{}", CURRENT_VERSION).as_bytes())?;
	Ok(())
}

/// Consolidated database path
fn consolidated_database_path(path: &Path) -> PathBuf {
	let mut state_path = path.to_owned();
	state_path.push("db");
	state_path
}

/// Database backup
fn backup_database_path(path: &Path) -> PathBuf {
	let mut backup_path = path.to_owned();
	backup_path.pop();
	backup_path.push("temp_backup");
	backup_path
}

/// Default migration settings.
pub fn default_migration_settings(compaction_profile: &CompactionProfile) -> MigrationConfig {
	MigrationConfig {
		batch_size: BATCH_SIZE,
		compaction_profile: *compaction_profile,
	}
}

/// Migrations on the consolidated database.
fn consolidated_database_migrations(compaction_profile: &CompactionProfile) -> Result<MigrationManager, Error> {
	let mut manager = MigrationManager::new(default_migration_settings(compaction_profile));
	manager.add_migration(TO_V11).map_err(|_| Error::MigrationImpossible)?;
	manager.add_migration(TO_V12).map_err(|_| Error::MigrationImpossible)?;
	manager.add_migration(TO_V14).map_err(|_| Error::MigrationImpossible)?;
	manager.add_migration(TO_V15).map_err(|_| Error::MigrationImpossible)?;
	Ok(manager)
}

/// Migrates database at given position with given migration rules.
fn migrate_database(version: u32, db_path: &Path, mut migrations: MigrationManager) -> Result<(), Error> {
	// check if migration is needed
	if !migrations.is_needed(version) {
		return Ok(())
	}

	let backup_path = backup_database_path(&db_path);
	// remove the backup dir if it exists
	let _ = fs::remove_dir_all(&backup_path);

	// migrate old database to the new one
	let temp_path = migrations.execute(&db_path, version)?;

	// completely in-place migration leads to the paths being equal.
	// in that case, no need to shuffle directories.
	if temp_path == db_path {
		trace!(target: "migrate", "In-place migration ran; leaving old database in place.");
		return Ok(())
	}

	// create backup
	fs::rename(&db_path, &backup_path)?;

	// replace the old database with the new one
	if let Err(err) = fs::rename(&temp_path, &db_path) {
		// if something went wrong, bring back backup
		fs::rename(&backup_path, &db_path)?;
		return Err(err.into());
	}

	// remove backup
	fs::remove_dir_all(&backup_path).map_err(Into::into)
}

fn exists(path: &Path) -> bool {
	fs::metadata(path).is_ok()
}

/// Migrates the database.
pub fn migrate(path: &Path, compaction_profile: &DatabaseCompactionProfile) -> Result<(), Error> {
	let compaction_profile = helpers::compaction_profile(&compaction_profile, path);

	// read version file.
	let version = current_version(path)?;

	// migrate the databases.
	// main db directory may already exists, so let's check if we have blocks dir
	if version > CURRENT_VERSION {
		return Err(Error::FutureDBVersion);
	}

	// We are in the latest version, yay!
	if version == CURRENT_VERSION {
		return Ok(())
	}

	let db_path = consolidated_database_path(path);

	// Further migrations
	if version < CURRENT_VERSION && exists(&db_path) {
		info!(target: "migration", "Migrating database from version {} to {}", version, CURRENT_VERSION);
		migrate_database(version, &db_path, consolidated_database_migrations(&compaction_profile)?)?;

		if version < BLOOMS_DB_VERSION {
			info!(target: "migration", "Migrating blooms to blooms-db...");
			let db_config = DatabaseConfig {
				max_open_files: 64,
				compaction: compaction_profile,
				columns: ethcore_db::NUM_COLUMNS,
				..Default::default()
			};

			migrate_blooms(&db_path, &db_config).map_err(Error::BloomsDB)?;
		}

		info!(target: "migration", "Migration finished");
	}

	// update version file.
	update_version(path)
}
