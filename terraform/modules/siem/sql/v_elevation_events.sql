-- Elevation events on the workstations (last 30 days): every way a process gained admin / root on behalf of a person,
-- plus refusals of elevated agent sessions. in_agent_tree = the process runs below Antigravity / agy (Windows,
-- Sysmon lineage) - an elevation there is never expected (the agent must not elevate; D14).
WITH base AS (
  SELECT
    timestamp AS ts,
    JSON_VALUE(resource.labels.project_id) AS project,
    IF(resource.type = 'generic_node', JSON_VALUE(resource.labels.node_id),  -- devices outside Google Cloud: full certificate CN, never shortened
      SPLIT(COALESCE(JSON_VALUE(labels, '$."compute.googleapis.com/resource_name"'), JSON_VALUE(resource.labels.instance_id)), '.')[SAFE_OFFSET(0)]) AS vm,
    log_id,
    COALESCE(JSON_VALUE(json_payload.message), JSON_VALUE(json_payload.Message), text_payload) AS msg,
    JSON_VALUE(json_payload.Channel) AS channel,
    SAFE_CAST(JSON_VALUE(json_payload.EventID) AS INT64) AS event_id
  FROM ${logs}
  WHERE resource.type IN ('gce_instance', 'generic_node') AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
    AND log_id IN ('agy_winevt', 'agy_syslog', 'agy_audit')
),
ev AS (
  -- Windows: Sysmon process creation at High / System integrity, by a person (service accounts excluded)
  SELECT ts, project, vm, 'windows' AS os, 'sysmon_high_integrity' AS source,
    REGEXP_EXTRACT(msg, r'(?m)^User: ([^\r\n]+)') AS user,
    REGEXP_EXTRACT(msg, r'(?m)^Image: ([^\r\n]+)') AS process,
    REGEXP_EXTRACT(msg, r'(?m)^CommandLine: ([^\r\n]*)') AS command,
    REGEXP_EXTRACT(msg, r'(?m)^ProcessGuid: (\{[^}]+\})') AS guid,
    REGEXP_EXTRACT(msg, r'(?m)^IntegrityLevel: ([^\r\n]+)') AS detail
  FROM base
  WHERE log_id = 'agy_winevt' AND channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1
    AND REGEXP_CONTAINS(msg, r'(?m)^IntegrityLevel: (High|System)')
    AND NOT REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(msg, r'(?m)^User: ([^\r\n]+)'), ''),
                            r'(?i)^NT AUTHORITY\\|^VIRTUAL USERS\\|\\(DWM|UMFD)-\d+$|^Font Driver Host\\|^Window Manager\\')
  UNION ALL
  -- Windows: Security 4688 with a full (elevated) token
  SELECT ts, project, vm, 'windows', 'security_4688_elevated',
    REGEXP_EXTRACT(msg, r'(?is)Creator Subject:.*?Account Name:\s*(\S+)'),
    REGEXP_EXTRACT(msg, r'(?i)New Process Name:\s*([^\r\n]+)'),
    REGEXP_EXTRACT(msg, r'(?i)Process Command Line:\s*([^\r\n]*)'), NULL, 'TokenElevationTypeFull'
  FROM base
  WHERE log_id = 'agy_winevt' AND channel = 'Security' AND event_id = 4688
    AND REGEXP_CONTAINS(msg, r'(?i)Token Elevation Type:\s*(%%1937|TokenElevationTypeFull)')
    AND NOT REGEXP_CONTAINS(msg, r'(?is)Creator Subject:.*?Account Name:\s*(\S+\$|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)\s')
  UNION ALL
  -- Linux: programs run as root on behalf of a logged-in user (auditd key agy_priv)
  SELECT ts, project, vm, 'linux', 'auditd_agy_priv',
    COALESCE(REGEXP_EXTRACT(msg, r'AUID="([^"]+)"'), REGEXP_EXTRACT(msg, r'\bauid=(\d+)')),
    REGEXP_EXTRACT(msg, r'\bexe="([^"]+)"'), REGEXP_EXTRACT(msg, r'\bcomm="([^"]+)"'), NULL, 'euid=0'
  FROM base WHERE log_id = 'agy_audit' AND REGEXP_CONTAINS(msg, r'key="agy_priv"')
  UNION ALL
  -- Linux: sudo (the only rule is agy-pkg) and agy-pkg itself
  SELECT ts, project, vm, 'linux', IF(REGEXP_CONTAINS(msg, r' agy-pkg(\[\d+\])?: '), 'agy_pkg', 'sudo'),
    COALESCE(REGEXP_EXTRACT(msg, r'user=(\S+)'), REGEXP_EXTRACT(msg, r' sudo(?:\[\d+\])?:\s+(\S+) :')),
    IF(REGEXP_CONTAINS(msg, r' agy-pkg(\[\d+\])?: '), '/usr/local/sbin/agy-pkg', 'sudo'),
    COALESCE(REGEXP_EXTRACT(msg, r'COMMAND=(.*)$'), REGEXP_EXTRACT(msg, r'packages=(.*)$')), NULL,
    COALESCE(REGEXP_EXTRACT(msg, r' agy-pkg(?:\[\d+\])?: (\S+)'), IF(REGEXP_CONTAINS(msg, r'NOT in sudoers|incorrect password|command not allowed'), 'DENIED', 'ALLOWED'))
  FROM base WHERE log_id = 'agy_syslog' AND REGEXP_CONTAINS(msg, r' (agy-pkg|sudo)(\[\d+\])?: ')
  UNION ALL
  -- refused agent sessions (hook ELEVATED_SESSION, launcher / shim refusals)
  SELECT ts, project, vm, os, CONCAT(layer, '_refused'), user, tool, target, NULL, IFNULL(reason, event)
  FROM `${views}.v_endpoint_events`
  WHERE ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
    AND ((layer = 'hook' AND event = 'ELEVATED_SESSION')
      OR (layer = 'launch' AND REGEXP_CONTAINS(IFNULL(raw, ''), r'reason=(elevated_session|admin_account)')))
)
SELECT ev.*, t.guid IS NOT NULL AS in_agent_tree, t.root_image AS agent_root
FROM ev
LEFT JOIN (SELECT vm, guid, ANY_VALUE(root_image) AS root_image FROM `${views}.v_agent_process_tree` GROUP BY vm, guid) t
  ON t.vm = ev.vm AND t.guid = ev.guid
