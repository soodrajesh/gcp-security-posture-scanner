# Unit tests: `opa test policies -v`. Firewall/bucket/key/IAM shapes are copied from a real
# Cloud Asset Inventory capture; the BigQuery, Compute Instance and Cloud Run shapes follow
# the public API reference and are labelled below; BigQuery and Cloud Run IAM shapes were captured live.
package posture_test

import data.posture
import rego.v1

fw(name, ranges, allowed) := {
	"asset_type": "compute.googleapis.com/Firewall",
	"name": sprintf("//compute.googleapis.com/projects/p/global/firewalls/%s", [name]),
	"data": {"direction": "INGRESS", "disabled": false, "sourceRanges": ranges, "allowed": allowed},
}

ids(input_doc) := {f.rule_id | some f in posture.findings with input as input_doc}

empty := {"scan_time": "2026-09-28T00:00:00Z", "resources": [], "iam": []}

# ── network ──
test_ssh_from_world_flagged if {
	"GCP-NET-001" in ids(object.union(empty, {"resources": [fw("ssh", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["22"]}])]}))
}

test_rdp_in_port_range_flagged if {
	"GCP-NET-001" in ids(object.union(empty, {"resources": [fw("rdp", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["3000-4000"]}])]}))
}

test_tcp_without_ports_means_all_ports if {
	"GCP-NET-001" in ids(object.union(empty, {"resources": [fw("any-tcp", ["0.0.0.0/0"], [{"IPProtocol": "tcp"}])]}))
}

test_ssh_from_iap_range_not_flagged if {
	count(ids(object.union(empty, {"resources": [fw("iap", ["35.235.240.0/20"], [{"IPProtocol": "tcp", "ports": ["22"]}])]}))) == 0
}

test_icmp_from_world_not_flagged if {
	count(ids(object.union(empty, {"resources": [fw("icmp", ["0.0.0.0/0"], [{"IPProtocol": "icmp"}])]}))) == 0
}

test_web_ports_from_world_not_flagged if {
	count(ids(object.union(empty, {"resources": [fw("web", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["80", "443"]}])]}))) == 0
}

test_disabled_rule_not_flagged if {
	rule := object.union(fw("off", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["22"]}]), {"data": {"disabled": true}})
	count(ids(object.union(empty, {"resources": [rule]}))) == 0
}

test_egress_rule_not_flagged if {
	rule := object.union(fw("egress", ["0.0.0.0/0"], [{"IPProtocol": "tcp", "ports": ["22"]}]), {"data": {"direction": "EGRESS"}})
	count(ids(object.union(empty, {"resources": [rule]}))) == 0
}

test_allow_all_is_critical_rule if {
	found := ids(object.union(empty, {"resources": [fw("all", ["0.0.0.0/0"], [{"IPProtocol": "all"}])]}))
	"GCP-NET-002" in found
	posture.rules["GCP-NET-002"].severity == "CRITICAL"
}

test_default_network_flagged if {
	net := {"asset_type": "compute.googleapis.com/Network", "name": "//compute.googleapis.com/projects/p/global/networks/default", "data": {"name": "default"}}
	"GCP-NET-003" in ids(object.union(empty, {"resources": [net]}))
}

test_custom_network_not_flagged if {
	net := {"asset_type": "compute.googleapis.com/Network", "name": "//x/networks/prod", "data": {"name": "prod"}}
	count(ids(object.union(empty, {"resources": [net]}))) == 0
}

# ── storage ──
bucket(name, ubla, pap) := {
	"asset_type": "storage.googleapis.com/Bucket",
	"name": sprintf("//storage.googleapis.com/%s", [name]),
	"data": {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": ubla}, "publicAccessPrevention": pap}},
}

test_bucket_without_ubla_flagged if {
	"GCP-STO-001" in ids(object.union(empty, {"resources": [bucket("b", false, "enforced")]}))
}

test_hardened_bucket_clean if {
	count(ids(object.union(empty, {"resources": [bucket("b", true, "enforced")]}))) == 0
}

test_pap_inherited_is_low_finding if {
	found := ids(object.union(empty, {"resources": [bucket("b", true, "inherited")]}))
	found == {"GCP-STO-003"}
	posture.rules["GCP-STO-003"].severity == "LOW"
}

test_public_bucket_flagged if {
	pol := {"asset_type": "storage.googleapis.com/Bucket", "name": "//storage.googleapis.com/b", "policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}
	"GCP-STO-002" in ids(object.union(empty, {"iam": [pol]}))
}

test_private_bucket_iam_clean if {
	pol := {"asset_type": "storage.googleapis.com/Bucket", "name": "//storage.googleapis.com/b", "policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["user:a@b.c"]}]}}
	count(ids(object.union(empty, {"iam": [pol]}))) == 0
}

# ── bigquery / compute / run ──
test_bq_all_authenticated_users_flagged if {
	pol := {"asset_type": "bigquery.googleapis.com/Dataset", "name": "//bigquery.googleapis.com/projects/p/datasets/d", "policy": {"bindings": [{"role": "roles/bigquery.dataViewer", "members": ["allAuthenticatedUsers"]}]}}
	"GCP-BQ-001" in ids(object.union(empty, {"iam": [pol]}))
}

test_bq_owner_group_clean if {
	pol := {"asset_type": "bigquery.googleapis.com/Dataset", "name": "//bigquery.googleapis.com/projects/p/datasets/d", "policy": {"bindings": [{"role": "roles/bigquery.dataOwner", "members": ["projectOwner:p"]}]}}
	count(ids(object.union(empty, {"iam": [pol]}))) == 0
}

test_vm_external_ip_and_default_sa_flagged if {
	vm := {"asset_type": "compute.googleapis.com/Instance", "name": "//compute.googleapis.com/projects/p/zones/z/instances/vm", "data": {"networkInterfaces": [{"accessConfigs": [{"natIP": "1.2.3.4"}]}], "serviceAccounts": [{"email": "123-compute@developer.gserviceaccount.com"}]}}
	ids(object.union(empty, {"resources": [vm]})) == {"GCP-CE-001", "GCP-CE-002"}
}

test_private_vm_with_custom_sa_clean if {
	vm := {"asset_type": "compute.googleapis.com/Instance", "name": "//x/instances/vm", "data": {"networkInterfaces": [{}], "serviceAccounts": [{"email": "app@p.iam.gserviceaccount.com"}]}}
	count(ids(object.union(empty, {"resources": [vm]}))) == 0
}

test_public_cloud_run_flagged if {
	pol := {"asset_type": "run.googleapis.com/Service", "name": "//run.googleapis.com/projects/p/locations/l/services/s", "policy": {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}}
	"GCP-RUN-001" in ids(object.union(empty, {"iam": [pol]}))
}

test_private_cloud_run_clean if {
	pol := {"asset_type": "run.googleapis.com/Service", "name": "//x/services/s", "policy": {"bindings": [{"role": "roles/run.invoker", "members": ["serviceAccount:a@p.iam.gserviceaccount.com"]}]}}
	count(ids(object.union(empty, {"iam": [pol]}))) == 0
}

# ── IAM ──
key(type, valid_after) := {
	"asset_type": "iam.googleapis.com/ServiceAccountKey",
	"name": "//iam.googleapis.com/projects/p/serviceAccounts/1/keys/k",
	"data": {"keyType": type, "validAfterTime": valid_after, "name": "projects/p/serviceAccounts/app@p.iam.gserviceaccount.com/keys/k"},
}

test_user_managed_key_flagged if {
	"GCP-IAM-001" in ids(object.union(empty, {"resources": [key("USER_MANAGED", "2026-09-27T00:00:00Z")]}))
}

test_fresh_key_not_old if {
	not "GCP-IAM-002" in ids(object.union(empty, {"resources": [key("USER_MANAGED", "2026-09-27T00:00:00Z")]}))
}

test_old_key_flagged_with_age if {
	found := [f | some f in posture.findings with input as object.union(empty, {"resources": [key("USER_MANAGED", "2026-01-01T00:00:00Z")]}); f.rule_id == "GCP-IAM-002"]
	count(found) == 1
	contains(found[0].evidence, "270 days old")
}

test_system_managed_key_ignored if {
	count(ids(object.union(empty, {"resources": [key("SYSTEM_MANAGED", "2020-01-01T00:00:00Z")]}))) == 0
}

project_iam(bindings) := {"asset_type": "cloudresourcemanager.googleapis.com/Project", "name": "//cloudresourcemanager.googleapis.com/projects/1", "policy": {"bindings": bindings, "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]}}

test_sa_editor_flagged_user_owner_not if {
	pol := project_iam([
		{"role": "roles/editor", "members": ["serviceAccount:ci@p.iam.gserviceaccount.com"]},
		{"role": "roles/owner", "members": ["user:me@example.com"]},
	])
	ids(object.union(empty, {"iam": [pol]})) == {"GCP-IAM-003"}
}

test_deleted_principal_reported_once_per_role if {
	pol := project_iam([{"role": "roles/pubsub.admin", "members": [
		"deleted:serviceAccount:gone@p.iam.gserviceaccount.com?uid=1",
		"deleted:serviceAccount:gone@p.iam.gserviceaccount.com?uid=2",
	]}])
	found := [f | some f in posture.findings with input as object.union(empty, {"iam": [pol]}); f.rule_id == "GCP-IAM-004"]
	count(found) == 1
}

test_project_wide_impersonation_flagged if {
	pol := project_iam([{"role": "roles/iam.serviceAccountTokenCreator", "members": ["serviceAccount:ci@p.iam.gserviceaccount.com"]}])
	"GCP-IAM-005" in ids(object.union(empty, {"iam": [pol]}))
}

test_impersonation_by_human_not_flagged if {
	pol := project_iam([{"role": "roles/iam.serviceAccountUser", "members": ["user:me@example.com"]}])
	count(ids(object.union(empty, {"iam": [pol]}))) == 0
}

test_missing_audit_config_flagged if {
	pol := {"asset_type": "cloudresourcemanager.googleapis.com/Project", "name": "//x/projects/1", "policy": {"bindings": []}}
	ids(object.union(empty, {"iam": [pol]})) == {"GCP-LOG-001"}
}

test_partial_audit_config_still_flagged if {
	pol := {"asset_type": "cloudresourcemanager.googleapis.com/Project", "name": "//x/projects/1", "policy": {"bindings": [], "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]}}
	"GCP-LOG-001" in ids(object.union(empty, {"iam": [pol]}))
}

# ── metadata integrity: every emitted rule_id has a rules entry ──
test_every_finding_has_rule_metadata if {
	pol := project_iam([{"role": "roles/editor", "members": ["serviceAccount:ci@p.iam.gserviceaccount.com"]}])
	found := posture.findings with input as object.union(empty, {"iam": [pol]})
	count(found) > 0
	every f in found {
		posture.rules[f.rule_id].title
	}
}
