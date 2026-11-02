-- WDAC enforce gate (per workstation, last 7 days): every Code Integrity 3076 event is a binary that ENFORCE mode
-- would block. A ring may move windows_wdac_mode from Audit to Enforce only when ready_to_enforce = TRUE (or every
-- remaining file is understood and covered by a signer / supplemental rule). Never auto-enforced.
WITH wdac AS (
  SELECT vm, ts, event,
    REGEXP_EXTRACT(raw, r'(?i)attempted to load (\S+)') AS file,
    REGEXP_EXTRACT(raw, r'(?i)process \((\S+?)\)') AS process
  FROM `${views}.v_endpoint_events`
  WHERE os = 'windows' AND layer = 'wdac' AND ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
)
SELECT
  vm,
  COUNTIF(event = 'WINEVT_3076') AS would_block_7d,
  COUNTIF(event = 'WINEVT_3077') AS blocked_7d,
  COUNT(DISTINCT IF(event = 'WINEVT_3076', file, NULL)) AS distinct_files_7d,
  ARRAY_AGG(DISTINCT IFNULL(file, '?') IGNORE NULLS LIMIT 25) AS sample_files,
  MAX(ts) AS last_event,
  COUNTIF(event = 'WINEVT_3076') = 0 AS ready_to_enforce
FROM wdac
GROUP BY vm
