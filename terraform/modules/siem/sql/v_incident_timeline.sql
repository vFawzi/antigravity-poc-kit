-- One timeline across layers: endpoint (hook / AppArmor / network / AppLocker / WDAC / MDM) and gateway / inspector.
-- Correlate on user + vm + time; conversation_id (endpoint) and incident (gateway) identify each side.
SELECT ts, project, vm, user, CONCAT('endpoint/', layer) AS source, event, os,
  COALESCE(reason, '') AS detail, target, conversation_id, CAST(NULL AS STRING) AS incident
FROM `${views}.v_endpoint_events`
UNION ALL
SELECT ts, project, vm, user, 'gateway' AS source, event, CAST(NULL AS STRING) AS os,
  CONCAT(IFNULL(category, ''), IF(model IS NULL, '', CONCAT(' model=', model))) AS detail,
  evidence_object AS target, CAST(NULL AS STRING) AS conversation_id, incident
FROM `${views}.v_gateway_events`
