-- Weekly block-tuning report: the most frequent blocks of the last 7 days per control, with users and machines
-- affected. Each row is either a true positive (keep, maybe detect) or a candidate exception (raise through the
-- exception process: owner, expiry, compensating control). Schedule as a BigQuery / Looker Studio email if needed.
SELECT
  layer, event,
  COALESCE(reason, REGEXP_EXTRACT(raw, r'(?i)(?:attempted to load|was prevented from running|to run)\s+(\S+)'), target, '-') AS what,
  COUNT(*) AS blocks_7d, COUNT(DISTINCT user) AS users, COUNT(DISTINCT vm) AS machines,
  MIN(ts) AS first_seen, MAX(ts) AS last_seen, ANY_VALUE(SUBSTR(raw, 1, 300)) AS sample
FROM `${views}.v_endpoint_events`
WHERE ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND ((layer = 'hook' AND event = 'DENY')
    OR (layer = 'applocker' AND event IN ('WINEVT_8004', 'WINEVT_8007'))
    OR (layer = 'wdac' AND event IN ('WINEVT_3076', 'WINEVT_3077'))
    OR (layer = 'apparmor'))
GROUP BY layer, event, what
ORDER BY blocks_7d DESC
LIMIT 200
