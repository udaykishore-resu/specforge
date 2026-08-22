-- Local development bootstrap.
--
-- Creates the database the integration tests use, so `make test-integration`
-- works against the compose stack without extra setup. This runs only on first
-- initialisation of an empty data directory.

CREATE DATABASE specforge_test OWNER specforge;

COMMENT ON DATABASE specforge_test IS
  'Integration test database. Dropped and recreated freely; never holds real data.';
