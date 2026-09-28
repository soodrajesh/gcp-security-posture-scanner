# 2. Look at the results

**Dashboard** (private; your own identity is attached by the proxy):
```bash
./scripts/dashboard.sh          # then open http://localhost:8088
```

**SQL** (all queries verified against the deployed dataset):
```sql
-- what is open, worst first
SELECT severity, rule_id, evidence FROM `PROJECT.posture.v_open_findings` LIMIT 20;

-- how long has each thing been open?
SELECT rule_id, evidence, TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), first_seen, HOUR) AS hours_open
FROM `PROJECT.posture.findings` WHERE status='open' ORDER BY hours_open DESC;

-- what changed in the last scan
SELECT scan_time, source, findings_total, opened, resolved FROM `PROJECT.posture.v_scan_history` LIMIT 5;

-- the raw configuration a finding was based on
SELECT JSON_VALUE(body, '$.sourceRanges[0]') AS first_range, name
FROM `PROJECT.posture.assets` WHERE asset_type='compute.googleapis.com/Firewall' ORDER BY scan_time DESC LIMIT 5;
```

Run the scan by hand: `gcloud run jobs execute posture-scanner --region europe-west1 --wait`.
