-- AGY SIEM detections over the last scheduling window (+5 min overlap). One row per rule hit.
WITH e AS (SELECT * FROM `${views}.v_endpoint_events` WHERE ts >= TIMESTAMP_SUB(@run_time, INTERVAL 20 MINUTE) AND ts < @run_time),
     g AS (SELECT * FROM `${views}.v_gateway_events` WHERE ts >= TIMESTAMP_SUB(@run_time, INTERVAL 20 MINUTE) AND ts < @run_time),
     -- processes started under the agent in the window, minus the corporate hook's own children (cmd -> python -> whoami)
     t AS (SELECT * FROM `${views}.v_agent_process_tree`
           WHERE ts >= TIMESTAMP_SUB(@run_time, INTERVAL 20 MINUTE) AND ts < @run_time
             AND NOT REGEXP_CONTAINS(IFNULL(command_line, ''), r'(?i)\\ProgramData\\Antigravity\\hooks\\|^whoami /groups /fo csv'))
SELECT @run_time AS detected_at, 'D1_REPEATED_HOOK_DENY' AS rule, 'medium' AS severity, project, vm, user,
  COUNT(*) AS count, MIN(ts) AS first_seen, MAX(ts) AS last_seen, ANY_VALUE(CONCAT(reason, ' | ', IFNULL(target, ''))) AS sample
FROM e WHERE layer = 'hook' AND event = 'DENY' GROUP BY project, vm, user HAVING COUNT(*) >= ${probe_threshold}
UNION ALL
SELECT @run_time, 'D2_PROTECTED_PATH_ATTEMPT', 'high', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(CONCAT(layer, ': ', IFNULL(target, '')))
FROM e WHERE (layer = 'hook' AND reason LIKE '%protected%') OR (layer = 'apparmor' AND REGEXP_CONTAINS(IFNULL(target, ''), r'^/(secure-admin|root|etc/(shadow|sudoers|antigravity))'))
GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D3_TAMPER_OR_DRIFT', 'high', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(raw)
FROM e WHERE layer = 'mdm' AND REGEXP_CONTAINS(event, r'DRIFT|TAMPER|BYPASS') GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D4_SIGNIN_WINDOW_OPENED', 'info', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(raw)
FROM e WHERE layer = 'mdm' AND event = 'SIGNIN-WINDOW' GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D5_MODEL_OFF_POLICY_OR_CONTAINMENT', 'medium', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(CONCAT(event, ' ', IFNULL(model, '')))
FROM g WHERE event IN ('MODEL_OFF_POLICY', 'CONTAINMENT_APPLIED', 'CONTAINMENT_FAILED', 'STOLEN_TOKEN_SUSPECTED') GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D6_EGRESS_BLOCK_BURST', 'medium', project, vm, CAST(NULL AS STRING), COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(reason)
FROM e WHERE layer IN ('network', 'firewall') AND event IN ('AGY-EGRESS-BLOCK', 'AGY-NET-BLOCK', 'AGY-MAIL-BLOCK', 'AGY-METADATA-BLOCK', 'WINEVT_5152', 'WINEVT_5157')
GROUP BY project, vm HAVING COUNT(*) >= 50
UNION ALL
SELECT @run_time, 'D7_PROMPT_BLOCKED', 'medium', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(CONCAT(category, ' incident=', incident))
FROM g WHERE event = 'PROMPT_BLOCKED' GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D8_SANDBOX_UNAVAILABLE_ADMIN_ENFORCED', 'medium', project, vm, CAST(NULL AS STRING), COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(raw)
FROM e WHERE (layer = 'mdm' AND event IN ('SANDBOX_UNAVAILABLE_ADMIN_ENFORCED', 'SANDBOX_FAILURE_OBSERVED'))
   OR (layer = 'hook' AND event = 'SANDBOX_FAILURE')
GROUP BY project, vm
UNION ALL
SELECT @run_time, 'D9_AGENT_CREDENTIAL_ACCESS', 'high', CAST(NULL AS STRING), vm, ANY_VALUE(user), COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(command_line)
FROM t WHERE REGEXP_CONTAINS(LOWER(IFNULL(command_line, '')),
  r'\\\.ssh\\|\\appdata\\roaming\\gcloud|credentials\.db|application_default_credentials|\.git-credentials|\\microsoft\\(credentials|protect)\\|\\\.aws\\|\\\.kube\\|\bcmdkey\b|\bvaultcmd\b')
GROUP BY vm
UNION ALL
SELECT @run_time, 'D10_AGENT_CLOUD_CLI_WITHOUT_AGENT_SA', 'medium', CAST(NULL AS STRING), vm, ANY_VALUE(user), COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(command_line)
FROM t WHERE REGEXP_CONTAINS(LOWER(IFNULL(command_line, '')), r'\b(gcloud|bq|gsutil)(\.cmd|\.py)?\b')
  AND NOT REGEXP_CONTAINS(LOWER(command_line), r'impersonate')
GROUP BY vm
UNION ALL
SELECT @run_time, 'D11_BUILD_OUTPUT_EGRESS', 'medium', project, vm, ANY_VALUE(REGEXP_EXTRACT(raw, r'(?m)^User: ([^\r\n]+)')), COUNT(*), MIN(ts), MAX(ts),
  ANY_VALUE(CONCAT(REGEXP_EXTRACT(raw, r'(?m)^Image: ([^\r\n]+)'), ' -> ', IFNULL(REGEXP_EXTRACT(raw, r'(?m)^DestinationIp: ([^\r\n]+)'), '?')))
FROM e WHERE layer = 'sysmon' AND event = 'WINEVT_3'
  AND REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(raw, r'(?m)^Image: ([^\r\n]+)'), ''), r'(?i)^[a-z]:\\build\\|\\node_modules\\')
  AND NOT REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(raw, r'(?m)^DestinationIp: ([^\r\n]+)'), ''), r'^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|fe80:)')
GROUP BY project, vm
UNION ALL
SELECT @run_time, 'D12_AGENT_EXEC_CONFIG_WRITE', 'high', ANY_VALUE(e.project), e.vm, ANY_VALUE(tr.user), COUNT(*), MIN(e.ts), MAX(e.ts),
  ANY_VALUE(REGEXP_EXTRACT(e.raw, r'(?m)^TargetFilename: ([^\r\n]+)'))
FROM e JOIN `${views}.v_agent_process_tree` tr
  ON tr.vm = e.vm AND tr.guid = REGEXP_EXTRACT(e.raw, r'(?m)^ProcessGuid: (\{[^}]+\})')
WHERE e.layer = 'sysmon' AND e.event = 'WINEVT_11'
  -- the app's own runtime folder (agent writes there are denied by the hook's config-folder rule)
  AND NOT REGEXP_CONTAINS(LOWER(IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^TargetFilename: ([^\r\n]+)'), '')), r'\\\.gemini\\antigravity\\')
  AND REGEXP_CONTAINS(LOWER(IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^TargetFilename: ([^\r\n]+)'), '')),
    r'\\\.git\\(hooks\\|config$)|\\\.vscode\\|\\\.idea\\|nuget\.config$|\\\.npmrc$|\\directory\.build\.(props|targets)$|\\\.github\\workflows\\|\.(exe|dll)$')
GROUP BY e.vm
UNION ALL
SELECT @run_time, 'D13_REVIEW_BYPASS_ATTEMPT', 'high', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(CONCAT(layer, ': ', IFNULL(reason, raw)))
FROM e WHERE (layer = 'hook' AND (event = 'REVIEW_BYPASS_ATTEMPT' OR REGEXP_CONTAINS(IFNULL(reason, ''), r'skip human review')))
   OR (layer = 'launch' AND REGEXP_CONTAINS(IFNULL(raw, ''), r'reason=review_bypass'))
GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D14_ELEVATION_IN_AGENT_LINEAGE', 'critical', ANY_VALUE(project), vm, ANY_VALUE(user), COUNT(*), MIN(ts), MAX(ts),
  ANY_VALUE(CONCAT(source, ': ', IFNULL(process, ''), ' ', IFNULL(command, ''), ' ', IFNULL(detail, '')))
FROM `${views}.v_elevation_events`
WHERE ts >= TIMESTAMP_SUB(@run_time, INTERVAL 20 MINUTE) AND ts < @run_time AND (in_agent_tree OR source = 'hook_refused')
GROUP BY vm
UNION ALL
SELECT @run_time, 'D15_AGENT_USER_PERSISTENCE', 'high', ANY_VALUE(e.project), e.vm, ANY_VALUE(tr.user), COUNT(*), MIN(e.ts), MAX(e.ts),
  ANY_VALUE(COALESCE(REGEXP_EXTRACT(e.raw, r'(?m)^TargetObject: ([^\r\n]+)'), REGEXP_EXTRACT(e.raw, r'(?m)^TargetFilename: ([^\r\n]+)')))
FROM e JOIN `${views}.v_agent_process_tree` tr
  ON tr.vm = e.vm AND tr.guid = REGEXP_EXTRACT(e.raw, r'(?m)^ProcessGuid: (\{[^}]+\})')
WHERE e.layer = 'sysmon' AND (
    (e.event IN ('WINEVT_12', 'WINEVT_13', 'WINEVT_14')
     AND REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^TargetObject: ([^\r\n]+)'), ''), r'(?i)\\CurrentVersion\\Run(Once)?\\|\\Environment\\|\\Explorer\\(User )?Shell Folders'))
 OR (e.event = 'WINEVT_11'
     AND REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^TargetFilename: ([^\r\n]+)'), ''), r'(?i)\\Start Menu\\Programs\\Startup\\|profile\.ps1$')))
GROUP BY e.vm
UNION ALL
SELECT @run_time, 'D15_SCHEDULED_TASK_OR_RC_FILE', 'medium', project, vm, CAST(NULL AS STRING), COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(SUBSTR(raw, 1, 300))
FROM e WHERE (layer = 'process' AND event = 'WINEVT_4698' AND NOT REGEXP_CONTAINS(raw, r'(?is)Account Name:\s*(\S+\$|SYSTEM)\s'))
   OR (layer = 'apparmor' AND REGEXP_CONTAINS(IFNULL(target, ''), r'/\.(bashrc|bash_profile|profile|zshrc|zprofile|pam_environment|xprofile)$|/\.config/(autostart|systemd|environment\.d)/|/\.pki/'))
GROUP BY project, vm
UNION ALL
SELECT @run_time, 'D16_ELEVATION_ATTEMPT', 'medium', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(CONCAT(layer, ': ', IFNULL(target, IFNULL(reason, ''))))
FROM e WHERE (layer = 'hook' AND event = 'DENY'
              AND REGEXP_CONTAINS(LOWER(IFNULL(target, '')), r'-verb\s+[\x27"]?runas|\brunas\b|\bsudo\b|\brun0\b|\bpkexec\b|\bgsudo\b|\bdoas\b|shell\.application|invokeverb'))
   OR (layer = 'launch' AND REGEXP_CONTAINS(IFNULL(raw, ''), r'reason=(elevated_session|admin_account)'))
GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D16_DENIED_SUDO_OR_AGY_PKG', 'medium', ANY_VALUE(project), vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(CONCAT(source, ': ', IFNULL(command, ''), ' ', IFNULL(detail, '')))
FROM `${views}.v_elevation_events`
WHERE ts >= TIMESTAMP_SUB(@run_time, INTERVAL 20 MINUTE) AND ts < @run_time AND source IN ('sudo', 'agy_pkg') AND detail IN ('DENIED', 'FAILED')
GROUP BY vm, user
UNION ALL
SELECT @run_time, 'D17_USER_TRUSTED_ROOT_CERTIFICATE', IF(LOGICAL_OR(tr.guid IS NOT NULL), 'high', 'info'), ANY_VALUE(e.project), e.vm,
  ANY_VALUE(REGEXP_EXTRACT(e.raw, r'(?m)^User: ([^\r\n]+)')), COUNT(*), MIN(e.ts), MAX(e.ts),
  ANY_VALUE(CONCAT(IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^Image: ([^\r\n]+)'), ''), ' -> ', IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^TargetObject: ([^\r\n]+)'), '')))
FROM e LEFT JOIN (SELECT vm, guid FROM `${views}.v_agent_process_tree` GROUP BY vm, guid) tr
  ON tr.vm = e.vm AND tr.guid = REGEXP_EXTRACT(e.raw, r'(?m)^ProcessGuid: (\{[^}]+\})')
WHERE e.layer = 'sysmon' AND e.event IN ('WINEVT_12', 'WINEVT_13')
  AND REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(e.raw, r'(?m)^TargetObject: ([^\r\n]+)'), ''), r'(?i)^HKU\\[^\\]+\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\')
GROUP BY e.vm
UNION ALL
SELECT @run_time, 'D19_ROOT_EQUIVALENT_GROUP_MEMBERSHIP', 'high', project, vm, user, COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(SUBSTR(raw, 1, 300))
FROM e WHERE (layer = 'process' AND event = 'WINEVT_4732' AND REGEXP_CONTAINS(raw, r'(?i)Group Name:\s*(Administrators|Hyper-V Administrators|Remote Management Users|docker-users)\b'))
   OR (layer = 'mdm' AND event = 'PRIV_GROUP_DRIFT')
GROUP BY project, vm, user
UNION ALL
SELECT @run_time, 'D20_AGENT_OUTSIDE_PERSONA', 'high', project, vm, ANY_VALUE(COALESCE(REGEXP_EXTRACT(raw, r'(?m)^User: ([^\r\n]+)'), user)), COUNT(*), MIN(ts), MAX(ts),
  ANY_VALUE(SUBSTR(raw, 1, 300))
FROM e
WHERE (layer = 'applocker' AND event IN ('WINEVT_8004', 'WINEVT_8007') AND REGEXP_CONTAINS(raw, r'(?i)\\ANTIGRAVITY\\'))
   OR (layer = 'sysmon' AND event = 'WINEVT_1'
       AND REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(raw, r'(?m)^Image: ([^\r\n]+)'), ''), r'(?i)\\Program Files\\Antigravity\\')
       AND NOT REGEXP_CONTAINS(IFNULL(REGEXP_EXTRACT(raw, r'(?m)^User: ([^\r\n]+)'), ''), r'(?i)\\(dev|contractor)$'))
GROUP BY project, vm
UNION ALL
-- D21 AGY version drift: binary changed outside version management, upgrade failed, or the policy selects no
-- deployable (supported / pinned) release for the device - both OSes (agy-mdm events from the version management)
SELECT @run_time, 'D21_AGY_VERSION_DRIFT', IF(LOGICAL_OR(event LIKE '%UNMANAGED_CHANGE'), 'high', 'medium'),
  project, vm, CAST(NULL AS STRING), COUNT(*), MIN(ts), MAX(ts), ANY_VALUE(SUBSTR(raw, 1, 300))
FROM e
WHERE layer = 'mdm' AND REGEXP_CONTAINS(event, r'^AGY_(CLI|DESKTOP|VERSION)_(UPGRADE_FAILED|UNMANAGED_CHANGE|NO_TARGET|SYNC_ERROR)$')
GROUP BY project, vm
UNION ALL
-- D23 device silent: a device that sent telemetry heartbeats has been quiet for 24 h (shipper stopped, tampered,
-- certificate expired, or offline). Edge-triggered: fires once, in the run that crosses the 24 h mark.
SELECT @run_time, 'D23_DEVICE_SILENT_24H', 'medium', project, vm, CAST(NULL AS STRING), COUNT(*), MIN(ts), MAX(ts),
  CONCAT('last heartbeat ', CAST(MAX(ts) AS STRING))
FROM `${views}.v_endpoint_events`
WHERE layer = 'mdm' AND event = 'TELEMETRY_HEARTBEAT' AND ts >= TIMESTAMP_SUB(@run_time, INTERVAL 7 DAY)
GROUP BY project, vm
HAVING MAX(ts) < TIMESTAMP_SUB(@run_time, INTERVAL 24 HOUR) AND MAX(ts) >= TIMESTAMP_SUB(@run_time, INTERVAL 1460 MINUTE)
