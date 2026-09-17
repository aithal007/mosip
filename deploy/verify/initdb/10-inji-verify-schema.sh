#!/bin/sh
# Create the Inji Verify schema from the canonical DDL in db_scripts/inji_verify.
#
# Why not docker-compose/db-init/init.sql? On release-1.0.x that file predates the
# vp_submission.response_code* columns that the 1.0.0-alpha.1 service queries, so every
# direct_post fails with HTTP 500 ("column v1_0.response_code does not exist").
set -eu

DDL_DIR=/upstream-db-scripts/ddl
for f in verify-authorization_request_details.sql verify-presentation_definition.sql verify-vp_submission.sql verify-vc_submission.sql; do
  [ -f "$DDL_DIR/$f" ] || { echo "missing $DDL_DIR/$f" >&2; exit 1; }
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE SCHEMA IF NOT EXISTS verify;
ALTER DATABASE "$POSTGRES_DB" SET search_path TO verify,pg_catalog,public;
SET search_path TO verify;
\i $DDL_DIR/verify-authorization_request_details.sql
\i $DDL_DIR/verify-presentation_definition.sql
\i $DDL_DIR/verify-vp_submission.sql
\i $DDL_DIR/verify-vc_submission.sql
SQL
