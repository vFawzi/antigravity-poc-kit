-- Fleet AGY versions: the latest version picture each device reported (agy-mdm AGY_VERSIONS events, written by the
-- version management on every change), plus its last version-management problem. One row per device.
WITH v AS (
  SELECT project, vm, os, ts,
    REGEXP_EXTRACT(raw, r'\bcli=(\S*)') AS cli,
    REGEXP_EXTRACT(raw, r'\bcli_target=(\S*)') AS cli_target,
    REGEXP_EXTRACT(raw, r'\bdesktop=(\S*)') AS desktop,
    REGEXP_EXTRACT(raw, r'\bdesktop_target=(\S*)') AS desktop_target,
    REGEXP_EXTRACT(raw, r'\bpolicy=(\S*)') AS policy,
    REGEXP_EXTRACT(raw, r'\bpackage=(\S*)') AS package
  FROM `${views}.v_endpoint_events`
  WHERE layer = 'mdm' AND event = 'AGY_VERSIONS'
  QUALIFY ROW_NUMBER() OVER (PARTITION BY project, vm ORDER BY ts DESC) = 1
),
p AS (
  SELECT project, vm, ts AS problem_at, event AS problem, SUBSTR(raw, 1, 300) AS problem_detail
  FROM `${views}.v_endpoint_events`
  WHERE layer = 'mdm' AND REGEXP_CONTAINS(event, r'^AGY_(CLI|DESKTOP|VERSION)_(UPGRADE_FAILED|UNMANAGED_CHANGE|NO_TARGET|SYNC_ERROR)$')
  QUALIFY ROW_NUMBER() OVER (PARTITION BY project, vm ORDER BY ts DESC) = 1
)
SELECT v.project, v.vm, v.os, v.ts AS reported_at, v.package, v.policy,
  NULLIF(v.cli, '') AS cli, NULLIF(v.cli_target, '') AS cli_target,
  NULLIF(v.desktop, '') AS desktop, NULLIF(v.desktop_target, '') AS desktop_target,
  (v.cli != v.cli_target OR IFNULL(v.desktop, '') != IFNULL(v.desktop_target, '')) AS upgrade_pending,
  p.problem_at, p.problem, p.problem_detail
FROM v LEFT JOIN p USING (project, vm)
