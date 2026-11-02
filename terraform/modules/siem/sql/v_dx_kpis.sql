-- Developer-experience and control KPIs per workstation, user and day (rollout: weekly review; steady state: monthly).
-- Targets (Pilot-to-Production guide): < 5 hook denials + approvals per 100 agent commands; AppLocker / WDAC blocks of
-- legitimate developer tools trending to 0; every block reviewed in v_block_tuning_weekly.
SELECT
  DATE(ts) AS day, vm, IFNULL(user, '-') AS user,
  COUNTIF(layer = 'hook' AND event = 'TOOL') AS agent_tool_calls,
  COUNTIF(layer = 'hook' AND event = 'DENY') AS hook_denies,
  COUNTIF(layer = 'hook' AND event = 'ASK_VIA_CLI') AS approvals_requested,
  -- TOOL is logged after a call ran; denied calls never run: attempts = TOOL + DENY
  ROUND(100 * SAFE_DIVIDE(COUNTIF(layer = 'hook' AND event IN ('DENY', 'ASK_VIA_CLI')),
                          COUNTIF(layer = 'hook' AND event IN ('TOOL', 'DENY'))), 1) AS friction_per_100_calls,
  COUNTIF(layer = 'applocker' AND event IN ('WINEVT_8004', 'WINEVT_8007')) AS applocker_blocks,
  COUNTIF(layer = 'wdac' AND event = 'WINEVT_3076') AS wdac_would_block,
  COUNTIF(layer = 'wdac' AND event = 'WINEVT_3077') AS wdac_blocks,
  COUNTIF(layer IN ('firewall', 'network')) AS egress_drops
FROM `${views}.v_endpoint_events`
WHERE ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
GROUP BY day, vm, user
HAVING agent_tool_calls + hook_denies + applocker_blocks + wdac_would_block + wdac_blocks > 0
