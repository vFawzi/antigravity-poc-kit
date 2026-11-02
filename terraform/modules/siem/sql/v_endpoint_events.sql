-- Normalised endpoint security events (Linux: agy-hook / agy-mdm / agy-launch via syslog, nftables kernel log,
-- AppArmor audit; Windows: Event Log via Ops Agent). One row per event, same columns for every OS.
WITH base AS (
  SELECT
    timestamp AS ts,
    JSON_VALUE(resource.labels.project_id) AS project,
    IF(resource.type = 'generic_node', JSON_VALUE(resource.labels.node_id),  -- devices outside Google Cloud: full certificate CN, never shortened
      SPLIT(COALESCE(JSON_VALUE(labels, '$."compute.googleapis.com/resource_name"'), JSON_VALUE(resource.labels.instance_id)), '.')[SAFE_OFFSET(0)]) AS vm,
    log_id,
    COALESCE(JSON_VALUE(json_payload.message), JSON_VALUE(json_payload.Message), text_payload) AS msg,
    json_payload
  FROM ${logs}
  WHERE resource.type IN ('gce_instance', 'generic_node')
    AND log_id IN ('agy_syslog', 'agy_kernel', 'agy_audit', 'agy_xrdp', 'agy_winevt')
),
syslog AS (
  SELECT ts, project, vm, 'linux' AS os,
    REGEXP_EXTRACT(msg, r'^\S+ \S+ ([\w.-]+)(?:\[\d+\])?: ') AS prog,
    REGEXP_EXTRACT(msg, r'^\S+ \S+ [\w.-]+(?:\[\d+\])?: (.*)$') AS body
  FROM base WHERE log_id = 'agy_syslog'
),
win AS (
  SELECT ts, project, vm, 'windows' AS os,
    LOWER(COALESCE(JSON_VALUE(json_payload.SourceName), JSON_VALUE(json_payload.ProviderName))) AS prog,
    msg AS body,
    SAFE_CAST(JSON_VALUE(json_payload.EventID) AS INT64) AS event_id,
    JSON_VALUE(json_payload.Channel) AS channel
  FROM base WHERE log_id = 'agy_winevt'
)
-- hook decisions (both OSes: the hook writes the same JSON)
SELECT ts, project, vm, os, 'hook' AS layer,
  JSON_VALUE(SAFE.PARSE_JSON(body), '$.event') AS event,
  JSON_VALUE(SAFE.PARSE_JSON(body), '$.user') AS user,
  JSON_VALUE(SAFE.PARSE_JSON(body), '$.tool') AS tool,
  COALESCE(JSON_VALUE(SAFE.PARSE_JSON(body), '$.reason'), CONCAT('model=', JSON_VALUE(SAFE.PARSE_JSON(body), '$.model'))) AS reason,
  JSON_VALUE(SAFE.PARSE_JSON(body), '$.target') AS target,
  NULLIF(JSON_VALUE(SAFE.PARSE_JSON(body), '$.conversation'), '') AS conversation_id,
  body AS raw
FROM (SELECT ts, project, vm, os, prog, body FROM syslog UNION ALL SELECT ts, project, vm, os, prog, body FROM win)
WHERE prog = 'agy-hook'
UNION ALL
-- policy / MDM events (drift, sign-in window, enrolment) and client launches
SELECT ts, project, vm, os, IF(prog IN ('agy-launch', 'agy-shim'), 'launch', 'mdm') AS layer,
  COALESCE(REGEXP_EXTRACT(body, r'\b([A-Z][A-Z0-9_-]{5,})\b'), IF(prog = 'agy-launch', 'LAUNCH', 'INFO')) AS event,
  REGEXP_EXTRACT(body, r'user=(\S+)') AS user, REGEXP_EXTRACT(body, r'app=(\S+)') AS tool,
  NULL AS reason, NULL AS target, NULL AS conversation_id, body AS raw
FROM (SELECT ts, project, vm, os, prog, body FROM syslog UNION ALL SELECT ts, project, vm, os, prog, body FROM win)
WHERE prog IN ('agy-mdm', 'agy-launch', 'agy-shim')
UNION ALL
-- network blocks (nftables): AGY-EGRESS-BLOCK / AGY-NET-BLOCK / AGY-MAIL-BLOCK / AGY-METADATA-BLOCK / AGY-RATE-LIMIT / AGY-SIGNIN-WINDOW
SELECT ts, project, vm, 'linux', 'network',
  REGEXP_EXTRACT(msg, r'(AGY-[A-Z-]+)') AS event, NULL AS user, 'tcp' AS tool,
  CONCAT('dst ', IFNULL(REGEXP_EXTRACT(msg, r'DST=(\S+)'), '?'), ':', IFNULL(REGEXP_EXTRACT(msg, r'DPT=(\d+)'), '?')) AS reason,
  REGEXP_EXTRACT(msg, r'DST=(\S+)') AS target, NULL, msg
FROM base WHERE log_id = 'agy_kernel' AND REGEXP_CONTAINS(msg, r'AGY-[A-Z-]+')
UNION ALL
-- AppArmor (agent confinement)
SELECT ts, project, vm, 'linux', 'apparmor', 'APPARMOR_DENIED',
  REGEXP_EXTRACT(msg, r'FSUID="([^"]+)"'), REGEXP_EXTRACT(msg, r'comm="([^"]+)"'),
  CONCAT(IFNULL(REGEXP_EXTRACT(msg, r'operation="([^"]+)"'), ''), ' ', IFNULL(REGEXP_EXTRACT(msg, r'requested_mask="([^"]+)"'), ''),
         ' profile=', IFNULL(REGEXP_EXTRACT(msg, r'profile="([^"]+)"'), '')),
  REGEXP_EXTRACT(msg, r'name="([^"]+)"'), NULL, msg
FROM base WHERE log_id = 'agy_audit' AND msg LIKE '%apparmor="DENIED"%'
UNION ALL
-- Windows platform controls by channel (event IDs overlap between channels: Sysmon 1/3/11 vs Security / AppLocker):
-- AppLocker 8003/8004/8006/8007, WDAC 3076/3077, firewall drop 5152/5157, Sysmon 1/3/11, process 4688, PowerShell 4104
SELECT ts, project, vm, 'windows',
  CASE WHEN STARTS_WITH(channel, 'Microsoft-Windows-AppLocker/') THEN 'applocker'
       WHEN channel = 'Microsoft-Windows-CodeIntegrity/Operational' THEN 'wdac'
       WHEN channel = 'Microsoft-Windows-Sysmon/Operational' THEN 'sysmon'
       WHEN channel = 'Microsoft-Windows-PowerShell/Operational' THEN 'powershell'
       WHEN event_id IN (5152, 5157) OR STARTS_WITH(channel, 'Microsoft-Windows-Windows Firewall') THEN 'firewall'
       ELSE 'process' END,
  CONCAT('WINEVT_', CAST(event_id AS STRING)), REGEXP_EXTRACT(body, r'(?i)account name:\s*(\S+)'), channel,
  SUBSTR(body, 1, 300), REGEXP_EXTRACT(body, r'(?i)(?:application name|file name|path):\s*(\S+)'), NULL, body
FROM win WHERE prog NOT IN ('agy-hook', 'agy-mdm', 'agy-launch', 'agy-shim') AND event_id IS NOT NULL
