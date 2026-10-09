"""Built-in key rules, built-in detectors and the tag / shape tables the
redactor uses (the tables behind
:data:`cloudg.mcp.transforms.detectors.DEFAULT_REGISTRY`)."""

from __future__ import annotations

from cloudg.mcp.transforms.builtin_detectors import BUILTIN_DETECTORS
from cloudg.mcp.transforms.entities import KeyRule, account_entity, ref_entity

SENSITIVE_KEY_PATTERN = (
    r"(?:^|_)(?:password|passwd|pwd|passphrase|secret|secrets|client_secret|api_key|apikey|"
    r"access_key|secret_key|secret_access_key|private_key|privatekey|token|tokens|"
    r"access_token|refresh_token|id_token|session_token|auth_token|bearer|credential|"
    r"credentials|authorization|auth|cookie|cookies|connection_string|connectionstring|"
    r"conn_str|sas_token|sas|signature|user_data|userdata|primary_key|secondary_key|"
    r"account_key|shared_key|master_key|admin_password|kubeconfig|pem)(?:$|_)"
)

#: Suffixes / prefixes that make a sensitive-looking key describe metadata
#: about the secret rather than the secret itself (``password_last_used``,
#: ``kms_key_id``, ``has_password``...).
SAFE_KEY_PATTERN = (
    r"(?:_(?:id|ids|arn|arns|name|names|type|types|state|status|usage|spec|enabled|"
    r"last_used|last_used_date|last_changed|last_rotated|age|length|count|policy|policies|"
    r"rotation\w*|expir\w*|created\w*|date|time|version|versions|present|required|set|"
    r"configured|manager|managers|source|format|algorithm|kind|ref|reference|location|uri|"
    r"url|endpoint|endpoints|header|scheme|method|mode|provider|issuer|audience|ttl|"
    r"lifetime|reset_required|exists|level|size|fingerprint|thumbprint|hint)$)"
    r"|^(?:has|is|num|require|requires|allow|allows|enable|enabled|use|uses|max|min)_"
)


#: Keys that mark a dict as describing a cloud asset (``name`` / ``id`` in it
#: are then identifiers). Generic keys such as ``type`` or ``kind`` are left
#: out on purpose: policy descriptions and dataset listings use them too.
_ASSET_SIBLINGS = frozenset(
    {"asset_type", "arn", "provider", "resource_type", "account_id", "region"}
)
#: Keys of AWS Organizations structures (accounts, OUs, the organization).
_ORG_SIBLINGS = frozenset(
    {
        "parent_id",
        "ou_path",
        "feature_set",
        "management_account_id",
        "ous",
        "joined_method",
        "master_account_id",
        "organization_id",
    }
)

BUILTIN_KEY_RULES: tuple[KeyRule, ...] = (
    KeyRule(
        "sensitive_key",
        "sensitive_field",
        SENSITIVE_KEY_PATTERN,
        category="secret",
        exclude=SAFE_KEY_PATTERN,
        subtree=True,
        scalars=True,
    ),
    KeyRule(
        "account_id_key",
        "cloud_account",
        r"(?:^|_)(?:account|accounts|account_id|account_ids|owner_id|owner_account_id)"
        r"(?:_affected)?$|^accounts?_affected$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "account_map_key",
        "cloud_account",
        r"^(?:by_account(?:_pair|_region|_id)?|services_by_account(?:_region)?|"
        r"\w+_by_account|account_pairs)$",
        category="identifier",
        defer=True,
        map_keys=True,
    ),
    KeyRule(
        "org_id_key",
        "resource_ref",
        r"^(?:organization_id|organisation_id|org_id|root_id|ou_id|ou_ids|"
        r"parent_ou_id)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "subscription_key",
        "azure_subscription_id",
        r"^(?:azure_)?subscription(?:_id)?$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "tenant_key",
        "azure_tenant_id",
        r"^(?:azure_)?tenant(?:_id)?$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "gcp_project_key",
        "gcp_project_id",
        r"^(?:gcp_)?project(?:_id)?$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "gcp_project_number_key",
        "gcp_project_number",
        r"^project_number$",
        category="identifier",
        scalars=True,
        defer=True,
    ),
    KeyRule(
        "resource_name_key",
        "resource_name",
        r"^(?:resource_name|display_name|bucket_name|function_name|instance_name|"
        r"cluster_name|db_name|database_name|computer_name|vm_name|role_name|user_name|"
        r"username|group_name|key_name|table_name|queue_name|topic_name|repository_name|"
        r"asset_name|source_name|target_name|resource_names|asset_names|account_name|"
        r"ou_name|ou_path|ou_names|org_name|organization_name|subject|object)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "resource_ref_key",
        "resource_ref",
        r"^(?:ref|refs|asset_ref|asset_refs|asset_id|asset_ids|resource_id|resource_ids|"
        r"resource|asset|source|target|source_id|target_id|source_ref|target_ref|"
        r"node|node_id|nodes|from|to|start|end|via|members|neighbors|neighbours|path|"
        r"parent_id|parent|parent_ids|child_id|child_ids|children|dependency_id|"
        r"dependency_ids|dependent_id|dependent_ids|subject_id|object_id|entry|entry_id|"
        r"exit|candidate|candidates)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "dataset_key",
        "dataset_name",
        r"^(?:dataset|dataset_name|datasets|active_dataset|base|base_dataset|"
        r"target_dataset)$",
        category="identifier",
        defer=True,
    ),
    KeyRule(
        "dataset_listing_name_key",
        "dataset_name",
        r"^name$",
        category="identifier",
        requires_sibling=frozenset({"loaded_at", "compliance_results"}),
        defer=True,
    ),
    KeyRule(
        "asset_name_key",
        "resource_name",
        r"^name$",
        category="identifier",
        requires_sibling=_ASSET_SIBLINGS,
        defer=True,
    ),
    KeyRule(
        "asset_id_key",
        "resource_ref",
        r"^id$",
        category="identifier",
        requires_sibling=_ASSET_SIBLINGS | _ORG_SIBLINGS,
        defer=True,
    ),
    KeyRule(
        "org_name_key",
        "resource_name",
        r"^name$",
        category="identifier",
        requires_sibling=_ORG_SIBLINGS,
        defer=True,
    ),
    KeyRule("rag_chunk_id_key", "rag_chunk_id", r"^(?:chunk_id|chunk_ids)$", category="identifier"),
    KeyRule(
        "rag_content_key",
        "rag_content",
        r"^content$",
        category="identifier",
        requires_sibling=frozenset({"chunk_type", "chunk_id"}),
    ),
    KeyRule(
        "hostname_key",
        "hostname",
        r"^(?:hostname|host_name|dns_name|fqdn|private_dns_name|public_dns_name|"
        r"domain_name|endpoint_address)$",
        category="network",
        defer=True,
    ),
)

#: Rule entities whose real entity is chosen per value.
SHAPED_ENTITIES = {"cloud_account": account_entity, "resource_ref": ref_entity}

#: Keys that hold tag / label maps (``{"Owner": "alice"}``) or lists of
#: ``{"Key": ..., "Value": ...}`` pairs.
TAG_CONTAINER_KEYS = frozenset(
    {"tags", "labels", "tag", "resource_tags", "user_labels", "tag_set", "tag_list"}
)
#: Tag keys whose values name a person.
PERSON_TAG_PATTERN = (
    r"(?:^|_)(?:owner|owners|created_by|createdby|creator|contact|email|maintainer|author|"
    r"requester|requested_by|user|team_lead|manager)(?:$|_)"
)


__all__ = [
    "BUILTIN_DETECTORS",
    "BUILTIN_KEY_RULES",
    "PERSON_TAG_PATTERN",
    "SAFE_KEY_PATTERN",
    "SENSITIVE_KEY_PATTERN",
    "SHAPED_ENTITIES",
    "TAG_CONTAINER_KEYS",
]
