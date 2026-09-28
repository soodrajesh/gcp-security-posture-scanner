# Cloud posture rules, evaluated against a Cloud Asset Inventory snapshot.
#
# Input shape (built by app/scanner/inventory.py):
#   input.scan_time  RFC 3339 timestamp of the scan (rules never call time.now_ns, so a run is reproducible)
#   input.resources  [{asset_type, name, data}]        -- content-type RESOURCE
#   input.iam        [{asset_type, name, policy}]      -- content-type IAM_POLICY
#
# Output: data.posture.findings, a set of {rule_id, resource, resource_type, subject, evidence}.
# Titles, severities, framework mappings and remediation text live in data.posture.rules so
# the Python side stays a thin normaliser and every rule is reviewable in one file.
package posture

import rego.v1

rules := {
	"GCP-NET-001": {
		"title": "Firewall rule exposes SSH or RDP to the internet",
		"severity": "HIGH",
		"frameworks": ["CIS GCP 3.6", "CIS GCP 3.7"],
		"remediation": "Restrict source ranges to IAP (35.235.240.0/20) or a known CIDR, and use IAP TCP forwarding for admin access.",
	},
	"GCP-NET-002": {
		"title": "Firewall rule allows all protocols/ports from the internet",
		"severity": "CRITICAL",
		"frameworks": ["CIS GCP 3.6"],
		"remediation": "Replace the allow-all rule with rules for the specific ports the workload serves.",
	},
	"GCP-NET-003": {
		"title": "The default VPC network still exists",
		"severity": "MEDIUM",
		"frameworks": ["CIS GCP 3.1"],
		"remediation": "Create purpose-built VPCs with custom subnets and delete the default network (and its permissive default-allow-* rules).",
	},
	"GCP-STO-001": {
		"title": "Bucket does not enforce uniform bucket-level access",
		"severity": "MEDIUM",
		"frameworks": ["CIS GCP 5.2"],
		"remediation": "Enable uniform bucket-level access so object ACLs cannot bypass IAM.",
	},
	"GCP-STO-002": {
		"title": "Bucket is readable by anyone on the internet",
		"severity": "CRITICAL",
		"frameworks": ["CIS GCP 5.1"],
		"remediation": "Remove allUsers/allAuthenticatedUsers bindings and enforce public access prevention.",
	},
	"GCP-STO-003": {
		"title": "Bucket does not enforce public access prevention",
		"severity": "LOW",
		"frameworks": [],
		"remediation": "Set publicAccessPrevention=enforced on buckets that should never be public.",
	},
	"GCP-IAM-001": {
		"title": "Service account has a user-managed key",
		"severity": "HIGH",
		"frameworks": ["CIS GCP 1.4"],
		"remediation": "Delete the key and use attached identities or Workload Identity Federation instead.",
	},
	"GCP-IAM-002": {
		"title": "User-managed service account key older than 90 days",
		"severity": "MEDIUM",
		"frameworks": ["CIS GCP 1.7"],
		"remediation": "Rotate or (better) delete the key.",
	},
	"GCP-IAM-003": {
		"title": "Service account holds a primitive Owner/Editor role",
		"severity": "HIGH",
		"frameworks": ["CIS GCP 1.5"],
		"remediation": "Replace roles/owner and roles/editor with the narrow predefined roles the workload needs.",
	},
	"GCP-IAM-004": {
		"title": "IAM binding references a deleted principal",
		"severity": "MEDIUM",
		"frameworks": [],
		"remediation": "Remove the stale binding. A recreated account with the same name would not inherit it, but tooling that matches by email can be fooled.",
	},
	"GCP-IAM-005": {
		"title": "Service account can impersonate or administer other service accounts project-wide",
		"severity": "HIGH",
		"frameworks": ["CIS GCP 1.6"],
		"remediation": "Grant serviceAccountUser/TokenCreator/Admin on the specific service account instead of the project.",
	},
	"GCP-LOG-001": {
		"title": "Project has no Data Access audit logging for all services",
		"severity": "MEDIUM",
		"frameworks": ["CIS GCP 2.1"],
		"remediation": "Enable ADMIN_READ, DATA_READ and DATA_WRITE audit logs for allServices in the project IAM policy.",
	},
	"GCP-RUN-001": {
		"title": "Cloud Run service is invokable by anyone on the internet",
		"severity": "MEDIUM",
		"frameworks": [],
		"remediation": "Remove the allUsers roles/run.invoker binding unless the service is intentionally public.",
	},
	"GCP-BQ-001": {
		"title": "BigQuery dataset is accessible to anyone on the internet",
		"severity": "CRITICAL",
		"frameworks": ["CIS GCP 7.1"],
		"remediation": "Remove allUsers/allAuthenticatedUsers from the dataset access list.",
	},
	"GCP-CE-001": {
		"title": "VM instance has an external IP address",
		"severity": "MEDIUM",
		"frameworks": ["CIS GCP 4.9"],
		"remediation": "Remove the access config and reach the VM through IAP or Cloud NAT.",
	},
	"GCP-CE-002": {
		"title": "VM instance runs as the default Compute Engine service account",
		"severity": "MEDIUM",
		"frameworks": ["CIS GCP 4.1"],
		"remediation": "Run the VM as a dedicated least-privilege service account.",
	},
}

public_members := {"allUsers", "allAuthenticatedUsers"}

primitive_roles := {"roles/owner", "roles/editor"}

impersonation_roles := {
	"roles/iam.serviceAccountUser",
	"roles/iam.serviceAccountTokenCreator",
	"roles/iam.serviceAccountAdmin",
	"roles/iam.serviceAccountKeyAdmin",
}

world := {"0.0.0.0/0", "::/0"}

# ── helpers ────────────────────────────────────────────────────────────────

by_type(t) := [r | some r in input.resources; r.asset_type == t]

iam_by_type(t) := [p | some p in input.iam; p.asset_type == t]

short_name(name) := last if {
	parts := split(name, "/")
	last := parts[count(parts) - 1]
}

# "22", "20-25" or absent (= every port)
port_covers(spec, port) if spec == sprintf("%d", [port])

port_covers(spec, port) if {
	contains(spec, "-")
	bounds := split(spec, "-")
	to_number(bounds[0]) <= port
	port <= to_number(bounds[1])
}

world_open(fw) if {
	fw.data.direction == "INGRESS"
	not fw.data.disabled
	some range in fw.data.sourceRanges
	range in world
}

# ── network ────────────────────────────────────────────────────────────────

findings contains f if {
	some fw in by_type("compute.googleapis.com/Firewall")
	world_open(fw)
	some allow in fw.data.allowed
	allow.IPProtocol in {"tcp", "all"}
	some port in {22, 3389}
	_admin_port_reachable(allow, port)
	f := {
		"rule_id": "GCP-NET-001",
		"resource": fw.name,
		"resource_type": fw.asset_type,
		"subject": sprintf("port %d", [port]),
		"evidence": sprintf("%s allows %s/%d from %s", [short_name(fw.name), allow.IPProtocol, port, concat(",", fw.data.sourceRanges)]),
	}
}

_admin_port_reachable(allow, _) if allow.IPProtocol == "all"

_admin_port_reachable(allow, _) if {
	allow.IPProtocol == "tcp"
	not allow.ports
}

_admin_port_reachable(allow, port) if {
	allow.IPProtocol == "tcp"
	some spec in allow.ports
	port_covers(spec, port)
}

findings contains f if {
	some fw in by_type("compute.googleapis.com/Firewall")
	world_open(fw)
	some allow in fw.data.allowed
	allow.IPProtocol == "all"
	f := {
		"rule_id": "GCP-NET-002",
		"resource": fw.name,
		"resource_type": fw.asset_type,
		"subject": "all protocols",
		"evidence": sprintf("%s allows every protocol from %s", [short_name(fw.name), concat(",", fw.data.sourceRanges)]),
	}
}

findings contains f if {
	some n in by_type("compute.googleapis.com/Network")
	n.data.name == "default"
	f := {
		"rule_id": "GCP-NET-003",
		"resource": n.name,
		"resource_type": n.asset_type,
		"subject": "",
		"evidence": "the auto-mode default network exists",
	}
}

# ── storage ────────────────────────────────────────────────────────────────

findings contains f if {
	some b in by_type("storage.googleapis.com/Bucket")
	not b.data.iamConfiguration.uniformBucketLevelAccess.enabled
	f := {
		"rule_id": "GCP-STO-001",
		"resource": b.name,
		"resource_type": b.asset_type,
		"subject": "",
		"evidence": sprintf("%s has uniform bucket-level access disabled", [short_name(b.name)]),
	}
}

findings contains f if {
	some b in by_type("storage.googleapis.com/Bucket")
	b.data.iamConfiguration.publicAccessPrevention != "enforced"
	f := {
		"rule_id": "GCP-STO-003",
		"resource": b.name,
		"resource_type": b.asset_type,
		"subject": "",
		"evidence": sprintf("%s publicAccessPrevention=%s", [short_name(b.name), b.data.iamConfiguration.publicAccessPrevention]),
	}
}

findings contains f if {
	some p in iam_by_type("storage.googleapis.com/Bucket")
	some binding in p.policy.bindings
	some member in binding.members
	member in public_members
	f := {
		"rule_id": "GCP-STO-002",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": sprintf("%s|%s", [binding.role, member]),
		"evidence": sprintf("%s is granted %s", [member, binding.role]),
	}
}

# ── BigQuery ───────────────────────────────────────────────────────────────

# The dataset ACL is NOT in the RESOURCE view of a BigQuery dataset (verified against a live
# capture); the IAM_POLICY view carries it, with legacy special groups mapped to members.
findings contains f if {
	some p in iam_by_type("bigquery.googleapis.com/Dataset")
	some binding in p.policy.bindings
	some member in binding.members
	member in public_members
	f := {
		"rule_id": "GCP-BQ-001",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": sprintf("%s|%s", [binding.role, member]),
		"evidence": sprintf("%s is granted %s on dataset %s", [member, binding.role, short_name(p.name)]),
	}
}

# ── compute ────────────────────────────────────────────────────────────────

findings contains f if {
	some vm in by_type("compute.googleapis.com/Instance")
	some nic in vm.data.networkInterfaces
	some _ in nic.accessConfigs
	f := {
		"rule_id": "GCP-CE-001",
		"resource": vm.name,
		"resource_type": vm.asset_type,
		"subject": "",
		"evidence": sprintf("%s has an external IP", [short_name(vm.name)]),
	}
}

findings contains f if {
	some vm in by_type("compute.googleapis.com/Instance")
	some sa in vm.data.serviceAccounts
	endswith(sa.email, "-compute@developer.gserviceaccount.com")
	f := {
		"rule_id": "GCP-CE-002",
		"resource": vm.name,
		"resource_type": vm.asset_type,
		"subject": "",
		"evidence": sprintf("%s runs as %s", [short_name(vm.name), sa.email]),
	}
}

# ── Cloud Run ──────────────────────────────────────────────────────────────

findings contains f if {
	some p in iam_by_type("run.googleapis.com/Service")
	some binding in p.policy.bindings
	binding.role == "roles/run.invoker"
	some member in binding.members
	member in public_members
	f := {
		"rule_id": "GCP-RUN-001",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": member,
		"evidence": sprintf("%s can invoke %s", [member, short_name(p.name)]),
	}
}

# ── IAM: service-account keys ──────────────────────────────────────────────

user_managed_keys := [k | some k in by_type("iam.googleapis.com/ServiceAccountKey"); k.data.keyType == "USER_MANAGED"]

findings contains f if {
	some k in user_managed_keys
	f := {
		"rule_id": "GCP-IAM-001",
		"resource": k.name,
		"resource_type": k.asset_type,
		"subject": "",
		"evidence": sprintf("user-managed key on %s", [_key_owner(k)]),
	}
}

findings contains f if {
	some k in user_managed_keys
	age_days := (time.parse_rfc3339_ns(input.scan_time) - time.parse_rfc3339_ns(k.data.validAfterTime)) / (((24 * 60) * 60) * 1000000000)
	age_days > 90
	f := {
		"rule_id": "GCP-IAM-002",
		"resource": k.name,
		"resource_type": k.asset_type,
		"subject": "",
		"evidence": sprintf("key on %s is %d days old", [_key_owner(k), floor(age_days)]),
	}
}

_key_owner(k) := owner if {
	# data.name = projects/<p>/serviceAccounts/<email>/keys/<id>
	parts := split(k.data.name, "/")
	owner := parts[3]
}

# ── IAM: project policy ────────────────────────────────────────────────────

project_policies := iam_by_type("cloudresourcemanager.googleapis.com/Project")

findings contains f if {
	some p in project_policies
	some binding in p.policy.bindings
	binding.role in primitive_roles
	some member in binding.members
	startswith(member, "serviceAccount:")
	f := {
		"rule_id": "GCP-IAM-003",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": sprintf("%s|%s", [binding.role, member]),
		"evidence": sprintf("%s holds %s", [trim_prefix(member, "serviceAccount:"), binding.role]),
	}
}

findings contains f if {
	some p in project_policies
	some binding in p.policy.bindings
	some member in binding.members
	startswith(member, "deleted:")
	f := {
		"rule_id": "GCP-IAM-004",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": sprintf("%s|%s", [binding.role, _deleted_principal(member)]),
		"evidence": sprintf("%s still holds %s", [_deleted_principal(member), binding.role]),
	}
}

# deleted:serviceAccount:name@proj.iam...?uid=123  ->  serviceAccount:name@proj.iam...
# (a deleted account leaves one binding per uid; report the principal once)
_deleted_principal(member) := principal if {
	principal := split(trim_prefix(member, "deleted:"), "?")[0]
}

findings contains f if {
	some p in project_policies
	some binding in p.policy.bindings
	binding.role in impersonation_roles
	some member in binding.members
	startswith(member, "serviceAccount:")
	f := {
		"rule_id": "GCP-IAM-005",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": sprintf("%s|%s", [binding.role, member]),
		"evidence": sprintf("%s holds %s on the whole project", [trim_prefix(member, "serviceAccount:"), binding.role]),
	}
}

findings contains f if {
	some p in project_policies
	not _audits_all_services(p.policy)
	f := {
		"rule_id": "GCP-LOG-001",
		"resource": p.name,
		"resource_type": p.asset_type,
		"subject": "",
		"evidence": "no auditConfig for allServices with DATA_READ and DATA_WRITE",
	}
}

_audits_all_services(policy) if {
	some cfg in policy.auditConfigs
	cfg.service == "allServices"
	types := {t.logType | some t in cfg.auditLogConfigs}
	{"DATA_READ", "DATA_WRITE"} <= types
}
