-- Gateway / seat-inspector decisions (one row per event; prompt text only in de-identified form, evidence via PAM)
SELECT
  timestamp AS ts,
  JSON_VALUE(resource.labels.project_id) AS project,
  JSON_VALUE(json_payload.event) AS event,
  JSON_VALUE(json_payload.user) AS user,
  JSON_VALUE(json_payload.group) AS policy_group,
  COALESCE(JSON_VALUE(json_payload.device.instance), JSON_VALUE(json_payload.device)) AS vm,
  JSON_VALUE(json_payload.mode) AS mode,
  JSON_VALUE(json_payload.incident) AS incident,
  COALESCE(JSON_VALUE(json_payload.category), JSON_VALUE(json_payload.reason)) AS category,
  JSON_VALUE(json_payload.source) AS source,
  COALESCE(JSON_VALUE(json_payload.requested), JSON_VALUE(json_payload.model)) AS model,
  JSON_VALUE(json_payload.routed) AS routed,
  JSON_VALUE(json_payload.evidence_object) AS evidence_object,
  SUBSTR(JSON_VALUE(json_payload.prompt_deidentified), 1, 500) AS prompt_deidentified
FROM ${logs}
WHERE resource.type = 'cloud_run_revision' AND JSON_VALUE(json_payload.component) = 'agy-gateway'
