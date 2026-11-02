-- Pay-as-you-go usage per day, persona, device and model (token counts reported by Vertex AI, logged by the gateway
-- at the end of every response). est_cost_usd uses the configured list prices (indicative); the billing export
-- (labels agy_persona / agy_device) is the authoritative cost.
WITH calls AS (
  SELECT
    DATE(timestamp) AS day,
    JSON_VALUE(json_payload.group) AS policy_group,
    REGEXP_REPLACE(IFNULL(JSON_VALUE(json_payload.group), 'unknown'), r'^agy-', '') AS persona,
    COALESCE(JSON_VALUE(json_payload.device.device_id), JSON_VALUE(json_payload.device.instance)) AS device,
    JSON_VALUE(json_payload.user) AS user,
    JSON_VALUE(json_payload.method) AS method,
    IFNULL(SAFE_CAST(JSON_VALUE(json_payload.usage.promptTokenCount) AS INT64), 0) AS input_tokens,
    IFNULL(SAFE_CAST(JSON_VALUE(json_payload.usage.candidatesTokenCount) AS INT64), 0)
      + IFNULL(SAFE_CAST(JSON_VALUE(json_payload.usage.thoughtsTokenCount) AS INT64), 0) AS output_tokens,
    JSON_VALUE(json_payload.incident) AS incident
  FROM ${logs}
  WHERE resource.type = 'cloud_run_revision' AND JSON_VALUE(json_payload.component) = 'agy-gateway'
    AND JSON_VALUE(json_payload.event) = 'STREAM_DONE' AND JSON_QUERY(json_payload, '$.usage') IS NOT NULL
),
routed AS (
  SELECT JSON_VALUE(json_payload.incident) AS incident, ANY_VALUE(JSON_VALUE(json_payload.vertex_model)) AS model
  FROM ${logs}
  WHERE resource.type = 'cloud_run_revision' AND JSON_VALUE(json_payload.component) = 'agy-gateway'
    AND JSON_VALUE(json_payload.event) IN ('ROUTED', 'ROUTED_FALLBACK')
  GROUP BY incident
),
prices AS (${prices})
SELECT
  c.day, c.persona, c.policy_group, c.device, c.user, r.model,
  COUNT(*) AS calls,
  SUM(c.input_tokens) AS input_tokens,
  SUM(c.output_tokens) AS output_tokens,
  ROUND(SUM(c.input_tokens * p.input + c.output_tokens * p.output) / 1e6, 4) AS est_cost_usd
FROM calls c
LEFT JOIN routed r USING (incident)
LEFT JOIN prices p ON p.model = r.model
GROUP BY c.day, c.persona, c.policy_group, c.device, c.user, r.model
