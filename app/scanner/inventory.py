"""Collect the Cloud Asset Inventory snapshot for a project, straight from the Asset API.

Two views of each asset: RESOURCE (its configuration) and IAM_POLICY (who can do what to
it). They are kept as separate lists because the Rego rules treat them differently.
"""

from __future__ import annotations

from typing import Any

from google.cloud import asset_v1
from google.protobuf import json_format

RESOURCE_TYPES = [
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "iam.googleapis.com/ServiceAccountKey",
    "run.googleapis.com/Service",
]
IAM_TYPES = [
    "cloudresourcemanager.googleapis.com/Project",
    "storage.googleapis.com/Bucket",
    "run.googleapis.com/Service",
    "bigquery.googleapis.com/Dataset",
]


def _list(
    client: asset_v1.AssetServiceClient,
    parent: str,
    content_type,
    asset_types: list[str],
) -> list[dict]:
    request = asset_v1.ListAssetsRequest(
        parent=parent,
        content_type=content_type,
        asset_types=asset_types,
        page_size=1000,
    )
    # MessageToDict on the raw proto gives the same camelCase JSON `gcloud asset list` prints,
    # which is the shape the Rego rules were written (and unit-tested) against.
    return [json_format.MessageToDict(a._pb) for a in client.list_assets(request=request)]


def collect(project_id: str) -> dict[str, Any]:
    client = asset_v1.AssetServiceClient()
    parent = f"projects/{project_id}"
    resources = _list(client, parent, asset_v1.ContentType.RESOURCE, RESOURCE_TYPES)
    iam = _list(client, parent, asset_v1.ContentType.IAM_POLICY, IAM_TYPES)
    return {
        "resources": [
            {
                "asset_type": a["assetType"],
                "name": a["name"],
                "data": a.get("resource", {}).get("data", {}),
            }
            for a in resources
        ],
        "iam": [
            {
                "asset_type": a["assetType"],
                "name": a["name"],
                "policy": a.get("iamPolicy", {}),
            }
            for a in iam
        ],
    }
