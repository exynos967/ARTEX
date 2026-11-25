package db

// PostgreSQL advisory lock keys used across ARTEX packages.
// Every advisory lock key in the codebase MUST be registered here so two
// subsystems never accidentally share the same key space.
const (
	// LockSchemaMigration serializes startup DDL / builtin seeding and
	// coordinates long multi-table archive/export transactions with schema updates.
	LockSchemaMigration int64 = 7337741001

	// LockTestSuite is historically reserved for cross-package test-suite
	// coordination (see company_lock_test.go and finding_traffic_archive_test.go).
	LockTestSuite int64 = 7337741002

	// LockCompanyScopeMutation serializes global company scope rule mutations
	// and attribution recomputations (exclusive) against concurrent asset upserts
	// (shared).
	LockCompanyScopeMutation int64 = 7337741003

	// LockFindingEvidence serializes finding evidence writes, archive/restore,
	// and filesystem evidence GC.
	LockFindingEvidence int64 = 7337741004

	// LockResourceLibrary serializes resource library quota/access/CAS mutations.
	LockResourceLibrary int64 = 7337741010

	// LockResourceGC coordinates resource library publication/mutation (shared)
	// against blob/staging garbage collection sweeps (exclusive try-lock).
	LockResourceGC int64 = 7337741011

	// LockRecordExport serializes task record export capacity and queue state
	// checks (used in db/record_exports.go).
	LockRecordExport int64 = 7337741012

	// LockTrafficSchemaInit serializes artex_traffic schema initialization and
	// one-time search index backfills in traffic/postgres.go.
	LockTrafficSchemaInit int64 = 7337741021

	// LockTrafficSQLiteMigrate serializes one-time legacy SQLite traffic index
	// import in traffic/migrate.go.
	LockTrafficSQLiteMigrate int64 = 7337741022

	// LockFindingRetestSeed serializes one-time retester agent seeding in
	// server/finding_retests.go.
	LockFindingRetestSeed int64 = 7337741023
)
