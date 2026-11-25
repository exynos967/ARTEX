package db

import "testing"

func TestAdvisoryLockRegistryUnique(t *testing.T) {
	locks := []struct {
		name string
		key  int64
	}{
		{"LockSchemaMigration", LockSchemaMigration},
		{"LockTestSuite", LockTestSuite},
		{"LockCompanyScopeMutation", LockCompanyScopeMutation},
		{"LockFindingEvidence", LockFindingEvidence},
		{"LockResourceLibrary", LockResourceLibrary},
		{"LockResourceGC", LockResourceGC},
		{"LockRecordExport", LockRecordExport},
		{"LockTrafficSchemaInit", LockTrafficSchemaInit},
		{"LockTrafficSQLiteMigrate", LockTrafficSQLiteMigrate},
		{"LockFindingRetestSeed", LockFindingRetestSeed},
	}

	seen := make(map[int64]string, len(locks))
	for _, entry := range locks {
		if entry.key <= 0 {
			t.Fatalf("%s has non-positive lock key %d", entry.name, entry.key)
		}
		if prev, dup := seen[entry.key]; dup {
			t.Fatalf("advisory lock collision: %s and %s both use key %d", prev, entry.name, entry.key)
		}
		seen[entry.key] = entry.name
	}

	if schemaMigrationLockKey != LockSchemaMigration {
		t.Fatalf("schemaMigrationLockKey=%d want %d", schemaMigrationLockKey, LockSchemaMigration)
	}
	if companyScopeMutationLock != LockCompanyScopeMutation {
		t.Fatalf("companyScopeMutationLock=%d want %d", companyScopeMutationLock, LockCompanyScopeMutation)
	}
	if findingEvidenceLockKey != LockFindingEvidence {
		t.Fatalf("findingEvidenceLockKey=%d want %d", findingEvidenceLockKey, LockFindingEvidence)
	}
}
