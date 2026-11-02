-- Process lineage on Windows workstations (Sysmon event 1, last 24 h): every process started under the agent
-- (Antigravity Desktop, agy CLI, language server), with its depth below the agent root. Lineage breaks through
-- services / WMI / scheduled tasks are themselves suspicious (the hook DENY + Sysmon gap is a detection).
WITH RECURSIVE procs AS (
  SELECT
    timestamp AS ts,
    IF(resource.type = 'generic_node', JSON_VALUE(resource.labels.node_id),  -- devices outside Google Cloud: full certificate CN, never shortened
      SPLIT(COALESCE(JSON_VALUE(labels, '$."compute.googleapis.com/resource_name"'), JSON_VALUE(resource.labels.instance_id)), '.')[SAFE_OFFSET(0)]) AS vm,
    REGEXP_EXTRACT(JSON_VALUE(json_payload.Message), r'(?m)^ProcessGuid: (\{[^}]+\})') AS guid,
    REGEXP_EXTRACT(JSON_VALUE(json_payload.Message), r'(?m)^ParentProcessGuid: (\{[^}]+\})') AS parent_guid,
    REGEXP_EXTRACT(JSON_VALUE(json_payload.Message), r'(?m)^Image: ([^\r\n]+)') AS image,
    REGEXP_EXTRACT(JSON_VALUE(json_payload.Message), r'(?m)^CommandLine: ([^\r\n]*)') AS command_line,
    REGEXP_EXTRACT(JSON_VALUE(json_payload.Message), r'(?m)^User: ([^\r\n]+)') AS user,
    REGEXP_EXTRACT(JSON_VALUE(json_payload.Message), r'(?m)^Hashes: ([^\r\n]+)') AS hashes
  FROM ${logs}
  WHERE log_id = 'agy_winevt' AND resource.type IN ('gce_instance', 'generic_node')
    AND JSON_VALUE(json_payload.Channel) = 'Microsoft-Windows-Sysmon/Operational'
    AND JSON_VALUE(json_payload.EventID) = '1'
    AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
),
tree AS (
  SELECT vm, guid, image, command_line, user, hashes, ts, guid AS root_guid, image AS root_image, 0 AS depth
  FROM procs
  WHERE REGEXP_CONTAINS(LOWER(image), r'\\(antigravity|agy|language_server[^\\]*)\.exe$')
  UNION ALL
  SELECT p.vm, p.guid, p.image, p.command_line, p.user, p.hashes, p.ts, t.root_guid, t.root_image, t.depth + 1
  FROM procs p JOIN tree t ON p.parent_guid = t.guid AND p.vm = t.vm
  WHERE t.depth < 12
)
SELECT * FROM tree WHERE depth > 0
