# cloudg MCP internals

A contributor's guide to `cloudg/mcp/`: what each file does, the contracts between the
pieces, how a request is dispatched, how each adapter and the native server work inside, how
to add tools and adapters, and how the test suite is organized. Read [MCP.md](MCP.md) first
for the user-facing behavior; this document assumes it.

Companion documents:

- [MCP.md](MCP.md): running, mounting and calling the layer.
- [MCP_TOOLS.md](MCP_TOOLS.md): the catalog reference.
- [MCP_PRIVACY.md](MCP_PRIVACY.md): `policy.py`, `transforms/` and the policy profiles.

Outputs quoted here were produced by running the code on the branch `feature-mcp-layer`
(cloudg 0.6.0, Python 3.13, mcp 2.3.0 unless stated otherwise).

## Contents

1. [Ground rules](#1-ground-rules)
2. [Package map](#2-package-map)
3. [Core contracts](#3-core-contracts)
4. [Inside the layer](#4-inside-the-layer)
5. [Inside the adapters](#5-inside-the-adapters)
6. [Inside the native server](#6-inside-the-native-server)
7. [server.py and cli.py](#7-serverpy-and-clipy)
8. [Adding a tool, resource, template or prompt](#8-adding-a-tool-resource-template-or-prompt)
9. [Writing a new adapter or transport](#9-writing-a-new-adapter-or-transport)
10. [Tests](#10-tests)
11. [Known quirks and open questions](#11-known-quirks-and-open-questions)

---

## 1. Ground rules

These hold across the package, and reviews check for them.

1. One path for every request. Adapters never call handlers. They call
   `CloudGMCPLayer.call_tool`, `read_resource`, `get_prompt` or `complete`, so policy,
   transforms, middleware, timeouts and audit apply the same way everywhere.
2. Framework-free core. `core.py`, `schema.py`, `context.py`, `layer.py`, `state.py`,
   `policy.py`, `transforms/` and `native/` use the standard library, pydantic and cloudg
   only. `mcp`, `fastmcp`, `starlette` and `uvicorn` are imported inside functions.
3. Wire shapes come from cloudg. Every adapter lists primitives from the layer's
   `to_wire()` dicts, so no framework re-derives a schema from a Python signature.
4. Python 3.11 compatible, typed, line length 100 (`ruff`, target py311).
5. Tests run without network access or cloud credentials. Live tools are tested with the
   engine monkeypatched.

## 2. Package map

### 2.1 Top level

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 138 | Public re-exports and three lazy helpers |
| `__main__.py` | 10 | `python -m cloudg.mcp` |
| `core.py` | 827 | Errors, enums, content types, specs, `Registry` |
| `schema.py` | 142 | JSON Schema from signatures, argument validation |
| `context.py` | 149 | `Principal`, `ToolContext` |
| `layer.py` | 754 | `CloudGMCPLayer`, `CallInfo`, dispatch |
| `state.py` | 1255 | `Dataset`, `Workspace`, loaders, diff |
| `policy.py` | 1172 | `Policy` (see MCP_PRIVACY.md) |
| `middleware.py` | 597 | Audit, metrics, cache, concurrency, retry |
| `server.py` | 632 | `serve`, `serve_async`, `create_layer_from_options`, ASGI auth |
| `cli.py` | 581 | The `cloudg mcp` click group |

`__init__.py` re-exports the names most programs need (`CloudGMCPLayer`, `CallInfo`,
`Principal`, `ToolContext`, the spec and content classes, the five error classes, `Policy`,
`available_profiles`, `Dataset`, `Workspace`, `Pipeline`, `TokenVault`,
`TransformContext`, `build_transform`) and defines `default_registry()`,
`register_into(layer, server, **kw)`, `build_server(layer, flavor)` and
`export_definitions(layer, principal)` as thin wrappers that import the adapters only when
called. Importing `cloudg.mcp` therefore never imports `mcp`.

`__main__.py` calls `cloudg.mcp.cli.main()`, which runs the click group with
`prog_name="cloudg-mcp"`; the console script `cloudg-mcp` points at the same function.

`core.py` holds everything framework-agnostic: `META_PREFIX = "cloudg/"`; the error
hierarchy (`MCPLayerError` -32603, `InvalidArgumentsError` -32602, `NotFoundError` -32602,
`AccessDeniedError` -31001, `RateLimitedError` -31029); the `Sensitivity` enum (public,
internal, confidential, restricted, ordered by `SENSITIVITY_ORDER`); the `Capability` enum
(`read_state`, `write_state`, `read_fs`, `write_fs`, `cloud_access`, `exec`, `reveal`);
`ToolAnnotations`, `ContentAnnotations` and `Icon`; the content dataclasses (`TextContent`,
`ImageContent`, `ResourceLink`, `EmbeddedResource`, `TextResourceContents`,
`BlobResourceContents`); `ToolResult`, `PromptMessage`, `PromptResult`; the four specs and
`PromptArgument`; `Registry`; and `maybe_await`. Every class that goes on the wire has a
`to_wire()` returning MCP camelCase JSON.

`schema.py` turns a handler signature into a pydantic model and from there into the tool's
`inputSchema`, and validates incoming arguments with the same model (section 3.4).

`context.py` defines `Principal` (id, roles, attributes; `Principal.local()`), the MCP log
level table `LOG_LEVELS`, and `ToolContext`, the per-request object handed to every handler.
`ToolContext` carries the progress and log callbacks the adapter supplies, the collected
resource links, a free-form `meta` dict, and the event loop serving the request so a sync
handler can report progress from its worker thread.

`layer.py` is the dispatcher. It builds the registry view, owns the policy and middleware,
renders list results per principal, and runs the four request kinds (section 4). It also
holds `DEFAULT_INSTRUCTIONS`, the text sent to clients on `initialize`.

`state.py` holds the workspace: `Dataset` with lazily built and cached indexes and
analyses, `Workspace` with named datasets, the active selection, name checks, path safety,
change listeners and the per-workspace `live_guard` (a `cloudg.resilience.LiveOperationGuard`
built from the config's `ratelimit` section on first use), file loaders with format detection (`detect_kind`, `load_dataset_file`), and
`diff_datasets`. `NoDatasetError` and `ReferenceNotFoundError` subclass `NotFoundError` so a
tool handler's "not found" becomes an error result the model can read.

`policy.py` compiles a policy document (built-in profile, file, dict or inline JSON) into
access decisions, token-bucket rate limits, an audit ring buffer and per-principal
input/output transform pipelines. The layer uses `Policy.load`, `vault`, `is_allowed`,
`check_call`, `output_pipeline`, `input_pipeline`, `describe`, `record_hidden` (a call to an
unknown or hidden primitive), `record_rejection` (an input-pipeline refusal after
`check_call` allowed the call) and, in `server.py`, `save_vault`. Everything else about it is
in [MCP_PRIVACY.md](MCP_PRIVACY.md).

`middleware.py` provides `AuditLogMiddleware`, `MetricsMiddleware` (alias
`TimingMiddleware`) with `register_metrics_resource`, `CachingMiddleware` with
`is_cacheable_tool`, `ConcurrencyLimitMiddleware` and `RetryMiddleware`.

`server.py` hosts a layer as a standalone server with any flavor and transport, refuses
option combinations a flavor cannot honor (`validate_serve_options`), builds layers from
CLI-style options, and provides `TokenAuthASGIMiddleware`, which puts the shared
`OriginHostGuard` and bearer-token auth in front of SDK and fastmcp HTTP apps (section 7).

`cli.py` is the click group behind `cloudg mcp` and `cloudg-mcp` (section 7).

### 2.2 `adapters/`

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 196 | `detect_server_kind`, `register_into`, `build_server`, re-exports |
| `_common.py` | 232 | Ownership checks, principal resolution, `ChangeFanout`, version helpers |
| `lowlevel.py` | 578 | `LowLevelBinding` for the SDK's low-level `Server`, 1.x and 2.x |
| `mcp_sdk.py` | 107 | High-level SDK servers, delegating to `lowlevel.py` |
| `fastmcp.py` | 569 | `FastMCPBinding` for standalone fastmcp 2.x to 4.x |
| `export.py` | 217 | `export_definitions` and the function-calling converters |

`__init__.py` classifies a server object and dispatches to the right `install`, and builds
fresh server objects for each flavor. `_common.py` holds what the adapters share: the
`owns_tool / owns_prompt / owns_resource / owns_template` checks that decide whether a
request belongs to cloudg or to the host, `resolve_principal` (custom resolver with fallback
to the default), `lower_headers`, `normalize_kinds` (validates `include=`),
`package_version` / `major_version`, and `ChangeFanout`, which forwards layer change events
to client sessions from any thread. `lowlevel.py` wraps the request handlers of an SDK
low-level server (section 5.2). `mcp_sdk.py` finds the low-level server inside `MCPServer`
or SDK `FastMCP` and applies `lowlevel.py` to it, and creates fresh SDK servers. `fastmcp.py`
registers fastmcp component subclasses plus a list-filtering middleware (section 5.4).
`export.py` produces wire definitions and handlers with no framework, and converts tools to
OpenAI, Anthropic and LangChain formats.

### 2.3 `native/`

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 61 | Re-exports |
| `jsonrpc.py` | 141 | Protocol constants, message classification, error helpers |
| `protocol.py` | 913 | `NativeMCPServer`, `Session`, method implementations |
| `stdio.py` | 189 | `run_stdio_async`, `protected_stdout` |
| `http.py` | 960 | `NativeHTTPServer`, `HTTPConfig`, legacy SSE |
| `auth.py` | 223 | `RequestInfo`, `TokenAuth`, `default_principal_resolver` |

`http.py` also holds `OriginHostGuard`, the DNS-rebinding check that every HTTP flavor uses.
`jsonrpc.py` defines the supported protocol versions (handshake versions 2024-11-05 to
2025-11-25, the stateless 2026-07-28), the reserved `_meta` envelope keys, the error codes,
which methods return cacheable results, and small helpers (`is_request`, `error_response`,
`dumps` producing single-line JSON). `protocol.py` is the transport-independent engine: a
transport creates a `Session` per connection and feeds it decoded messages (section 6.2).
`stdio.py` and `http.py` are the two transports. `auth.py` turns transport facts into a
`Principal` and is also used by the SDK and fastmcp adapters, which is why it lives here and
has no dependencies.

### 2.4 `catalog/`

| File | Registers |
|---|---|
| `__init__.py` | `CATEGORIES`, `default_registry()` (all modules below, privacy guarded by `ImportError`) |
| `_common.py` | Nothing; argument type aliases (`DatasetArg`, `RefArg`, `Limit`, `Cursor`), brief builders, enum parsing, cursor pagination, output-schema models |
| `workspace.py` | 8 tools (category `workspace`) |
| `inventory.py` | 11 tools |
| `graph.py` | 17 tools |
| `findings.py` | 10 tools |
| `compliance.py` | 5 tools |
| `ontology.py` | 6 tools |
| `export.py` | 3 tools |
| `live.py` | 5 tools (four collecting, plus `rate_limit_status`) and `cloudg://ratelimit`; the credential preflight and the live-guard wrapper |
| `meta.py` | 4 tools |
| `privacy.py` | 5 tools (`reveal_token` among them) and 2 resources |
| `resources.py` | 10 resources and 11 templates, with completions |
| `prompts.py` | 11 prompts |

Each module exposes `register(reg: Registry)`; the order in `_modules()` is the order tools
are listed. The tools themselves are documented in [MCP_TOOLS.md](MCP_TOOLS.md). Two helpers
from `_common.py` matter when you write tools: `paginate(items, limit, cursor, fp)` with
`fingerprint(ds, **filters)` implements the `c<offset>.<hash>` cursors, and the `*Out`
pydantic models, every field optional and `extra="allow"`, give output schemas that
projection and redaction cannot invalidate (`schema(Model)` renders one).

### 2.5 `transforms/` and `policies/`

`transforms/base.py` defines `TransformContext` (principal, spec, kind, direction, vault and
a `report` dict) and `Pipeline`, an ordered list of objects with `apply(value, ctx)`.
`detectors.py`, `redaction.py`, `vault.py`, `substitution.py`, `projection.py` and
`annotation.py` implement the transforms, and `transforms/__init__.py` maps transform type
names to factories (`build_transform`). `policies/*.yaml` are the built-in profiles: `open`,
`standard`, `strict`, `read_only`, `airgapped`, `audit` and `soc-analyst`. All of this is
covered in [MCP_PRIVACY.md](MCP_PRIVACY.md). The layer only touches `TransformContext`,
`Pipeline.apply` and the report.

## 3. Core contracts

### 3.1 Specs

All four specs inherit `_BaseSpec`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | `str` | required | Tools and prompts: wire name before the prefix. Resources: display name |
| `handler` | callable | required | Sync or async; first parameter is the `ToolContext` |
| `title` | `str or None` | `None` | Display title |
| `description` | `str` | `""` | Falls back to the handler's cleaned docstring |
| `category` | `str` | `"general"` | Used by filters, policies and `_meta` |
| `tags` | `set[str]` | empty | Policies can match on them |
| `sensitivity` | `Sensitivity` | `CONFIDENTIAL` | Prompts default to `INTERNAL` |
| `capabilities` | `set[Capability]` | `{READ_STATE}` | Drives annotations and policy capability denials |
| `meta` | `dict` | empty | Merged into the wire `_meta` after the cloudg keys |
| `icons` | `list[Icon] or None` | `None` | `Icon(src, mime_type, sizes, theme)`; prefer `data:` URIs |

`ToolSpec` adds `input_schema` (derived from the handler when `None`), `output_schema`,
`annotations: ToolAnnotations`, `transform_hints` (per-tool options for the policy's
transforms) and `timeout_seconds`. Its `__post_init__` validates the name against
`^[A-Za-z0-9_.-]{1,128}$`, copies `title` into `annotations.title` (older clients only read
the latter), derives unset hints (3.5) and builds the input schema.

`ResourceSpec` adds `uri`, `mime_type` (default `application/json`), `annotations:
ContentAnnotations` and `size`. `ResourceTemplateSpec` adds `uri_template`, `mime_type`,
`annotations` and `completions: {variable: fn(ctx, partial) -> list[str]}`, and compiles the
template to a regex. `PromptSpec` adds `arguments: list[PromptArgument]`, where
`PromptArgument(name, description="", required=False, completion=None, title=None)`.

Handlers:

| Spec | Signature | May return |
|---|---|---|
| Tool | `handler(ctx, **arguments)` | dict, list, scalar, pydantic model, dataclass, object with `to_dict()`, or `ToolResult` |
| Resource | `handler(ctx)` | `str`, `bytes`, JSON-serializable value, or a non-empty list of `TextResourceContents` / `BlobResourceContents` |
| Template | `handler(ctx, **variables)` | as resources |
| Prompt | `handler(ctx, **arguments)` | `PromptResult`, list of `PromptMessage`, or `str` |
| Completion | `fn(ctx, partial)` | iterable of values (converted with `str`) |

### 3.2 `Registry`

```python
reg = Registry()
reg.add(spec, *, replace=False)       # ValueError on duplicates unless replace=True
reg.merge(other, *, replace=False)    # add every spec of another registry
reg.find_template(uri)                # (spec, variables) or None
len(reg)                              # total number of primitives
reg.tools / reg.resources / reg.templates / reg.prompts   # dicts keyed by name / uri / template / name
```

Decorators register the decorated function and return it unchanged:

| Decorator | Parameters |
|---|---|
| `@reg.tool(name=None, *, ...)` | `title`, `description`, `category`, `tags`, `sensitivity`, `capabilities`, `read_only`, `destructive`, `idempotent`, `open_world`, `output_schema`, `transform_hints`, `timeout_seconds`, `icons` |
| `@reg.resource(uri, *, ...)` | `name`, `title`, `description`, `mime_type`, `category`, `tags`, `sensitivity`, `annotations`, `capabilities`, `icons` |
| `@reg.resource_template(uri_template, *, ...)` | as `resource`, plus `completions` |
| `@reg.prompt(name=None, *, ...)` | `title`, `description`, `arguments`, `category`, `tags`, `sensitivity`, `icons` |

`find_template` tries templates longest template string first, so
`cloudg://assets/{+ref}/neighbors` wins over `cloudg://assets/{+ref}` for
`.../neighbors` URIs.

### 3.3 Wire shapes

`ToolSpec.to_wire(name=None, *, include_output_schema=True)` for `workspace_status` under the
`open` profile:

```json
{
  "name": "workspace_status",
  "description": "Show what is loaded: every dataset (asset / edge / finding counts,\nsource, which analyses are cached), the active dataset, and the\ndirectories file tools may read and write. Call this first; if no\ndataset is loaded, use load_dataset or map_inventory.",
  "inputSchema": {"additionalProperties": false, "properties": {}, "type": "object"},
  "outputSchema": {
    "additionalProperties": true,
    "properties": {
      "active_dataset": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
      "datasets": {"items": {"additionalProperties": true, "type": "object"}, "type": "array"},
      "allowed_roots": {"anyOf": [{"items": {"type": "string"}, "type": "array"}, {"type": "null"}], "default": null},
      "output_dir": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null}
    },
    "type": "object"
  },
  "annotations": {"title": "Workspace status", "readOnlyHint": true, "destructiveHint": false,
                  "idempotentHint": true, "openWorldHint": false},
  "title": "Workspace status",
  "_meta": {"cloudg/category": "workspace", "cloudg/sensitivity": "internal",
            "cloudg/tags": ["start-here"]}
}
```

`ResourceSpec.to_wire()`:

```json
{"uri": "cloudg://workspace", "name": "workspace_resource", "mimeType": "application/json",
 "description": "Loaded datasets, the active dataset and allowed directories.",
 "title": "Workspace",
 "_meta": {"cloudg/category": "workspace", "cloudg/sensitivity": "internal"}}
```

`ResourceTemplateSpec.to_wire()`:

```json
{"uriTemplate": "cloudg://assets/{+ref}", "name": "asset_resource", "mimeType": "application/json",
 "description": "One asset of the active dataset (ref = id, ARN or unique name, URL-encoded).",
 "title": "Asset",
 "_meta": {"cloudg/category": "inventory", "cloudg/sensitivity": "confidential"}}
```

`PromptSpec.to_wire(name=None)`:

```json
{"name": "compliance_gap_analysis",
 "description": "Failing controls, responsible assets and a remediation backlog for one framework.",
 "arguments": [
   {"name": "framework", "required": true, "description": "Framework, e.g. CIS-AWS, PCI-DSS, NIST-800-53."},
   {"name": "dataset", "required": false, "description": "Dataset name; empty = active dataset."}
 ],
 "title": "Compliance gap analysis",
 "_meta": {"cloudg/category": "prompts", "cloudg/sensitivity": "confidential", "cloudg/tags": ["workflow"]}}
```

`ToolResult.to_wire()` emits `content`, `isError`, and `structuredContent` and `_meta` when
set. `ToolResult.error(message, **meta)` builds an error result. The content classes emit
`type` plus their fields, `annotations` only when non-empty and `_meta` only when set;
`ResourceLink` omits empty optional fields. Tool and prompt wire dicts always include
`description`, even when it is the empty string.

`ToolSpec.to_wire` and `PromptSpec.to_wire` validate the exposed name (after the prefix)
against the same name pattern and raise `ValueError` when it does not match.

### 3.4 Schema generation

`input_schema_for(fn)`:

1. Builds (and caches on the function as `__cloudg_mcp_args_model__`) a pydantic model from
   the signature, skipping a first parameter named `ctx` or `context` and any `*args` or
   `**kwargs`. Annotations come from `typing.get_type_hints(include_extras=True)`, so
   `Annotated[int, Field(ge=1, description=...)]` carries constraints and descriptions; when
   forward references cannot be resolved every parameter becomes `Any`. The model uses
   `extra="forbid"`.
2. Calls `model_json_schema()`, drops pydantic's generated `title` keys, and inlines local
   `$ref`s into `#/$defs/...` (several clients do not follow references). A recursive model
   keeps its `$defs`.
3. Forces `type: object`, a `properties` key and `additionalProperties: false`.

A handler with a nested model:

```python
class Window(BaseModel):
    start: str
    end: str | None = None


def changes(ctx, window: Window, kinds: list[Literal["asset", "edge"]] = ["asset"],
            limit: Annotated[int, Field(ge=1, le=100)] = 10) -> dict:
    """Changes in a window."""
```

produces:

```json
{
  "additionalProperties": false,
  "properties": {
    "window": {
      "properties": {
        "start": {"type": "string"},
        "end": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null}
      },
      "required": ["start"],
      "type": "object"
    },
    "kinds": {"default": ["asset"], "items": {"enum": ["asset", "edge"], "type": "string"}, "type": "array"},
    "limit": {"default": 10, "maximum": 100, "minimum": 1, "type": "integer"}
  },
  "required": ["window"],
  "type": "object"
}
```

`validate_arguments(fn, arguments)` validates with the same model and returns a dict of the
model's attributes:

```python
validate_arguments(changes, {"window": {"start": "2026-01-01"}, "limit": "5"})
# {'window': Window(start='2026-01-01', end=None), 'kinds': ['asset'], 'limit': 5}
```

Note that nested models arrive as model instances, not dicts, and that `"5"` was coerced to
`5`. On failure it raises `InvalidArgumentsError("Invalid arguments: loc: msg; ...")` with
`data` set to `[{"loc", "msg", "type"}, ...]`; the input values are not echoed.

`output_schema_for(Model)` renders an output schema the same way, without the forced
`additionalProperties: false`. Remember that the layer wraps non-dict results as
`{"result": value}`, so an output schema must describe the wrapper in that case, and that
the schema is withheld from principals whose output pipeline is non-empty (3.7).

### 3.5 Annotation hints

`ToolSpec._derive_hints` (core.py lines 418-439) fills every hint left as `None`:

- `readOnlyHint` is false if the capabilities include `write_state`, `write_fs` or `exec`,
  true otherwise.
- `destructiveHint` is false.
- `openWorldHint` is true when the capabilities include `cloud_access` or `exec`: such a tool
  reaches outside the loaded data.
- `idempotentHint` is true for a read-only tool without `cloud_access` or `exec`, otherwise
  left unset. Two collections a minute apart can differ, so external tools are never
  idempotent by default.

Explicit decorator arguments win. What the derivation gives, from a run over several
capability sets:

| Capabilities | Wire annotations |
|---|---|
| `read_state` | readOnly true, destructive false, idempotent true, openWorld false |
| `read_state`, `write_state` | readOnly false, destructive false, openWorld false |
| `read_state`, `write_fs` | readOnly false, destructive false, openWorld false |
| `read_fs` | readOnly true, destructive false, idempotent true, openWorld false |
| `exec` | readOnly false, destructive false, openWorld true |
| `cloud_access` | readOnly true, destructive false, openWorld true |
| `reveal` | readOnly true, destructive false, idempotent true, openWorld false |

Clients assume the worst for a missing hint (destructive, open world), which is why the
layer fills them. The annotations also feed cloudg's own behavior: `CachingMiddleware` and
`RetryMiddleware` only touch tools that are read-only and idempotent, so tools with
`cloud_access` or `exec` stay out of both unless they declare `idempotent=True`, and
`--read-only` drops tools annotated destructive.

### 3.6 URI templates

`ResourceTemplateSpec` accepts three variable forms:

| Form | Matches | Use |
|---|---|---|
| `{var}` | one path segment (`[^/?]+`) | ids without slashes |
| `{+var}` | anything (`.+`) | RFC 6570 reserved expansion; ARNs and Azure resource ids |
| `{var*}` | anything | legacy spelling of the above, still accepted |

`match(uri)` returns the variables URL-decoded; `expand(**values)` quotes `{var}` values
completely and leaves `/:@!$&'()*+,;=` unescaped in `{+var}` values; `variables` lists the
names. With the catalog's asset template:

```python
spec = layer.registry.templates["cloudg://assets/{+ref}"]
spec.expand(ref="arn:aws:ec2:us-east-1:111111111111:instance/i-0bast")
# 'cloudg://assets/arn:aws:ec2:us-east-1:111111111111:instance/i-0bast'
spec.match(_)
# {'ref': 'arn:aws:ec2:us-east-1:111111111111:instance/i-0bast'}
```

and `layer.read_resource()` on that URI returned the bastion's detail.

### 3.7 `_meta` keys and errors

All layer-written `_meta` keys go through `META_PREFIX` (`cloudg/`) in core.py and layer.py:
`category`, `sensitivity`, `tags` on definitions; `transforms`, `duration_ms`, `error_code`,
`error_data` on results. `middleware.py` and `cli.py` spell the prefix out as a literal
(`"cloudg/transforms"`, `"cloudg/cache"`, `"cloudg/retries"`, `"cloudg/category"`); keep them
in step if the prefix ever changes.

Error codes and their channels are tabulated in [MCP.md section 13](MCP.md#13-errors). The
design rule is SEP-1303: input validation and handler failures are tool execution errors
(`isError`), so the model can correct itself; only an unknown tool, resource or prompt, and
malformed requests, are protocol errors.

## 4. Inside the layer

### 4.1 Construction

`CloudGMCPLayer.__init__` (layer.py):

1. Builds `Workspace(config or CloudGConfig())` when no workspace is given.
2. Loads the policy with `Policy.load(policy)` unless a `Policy` instance was passed.
3. Takes `default_registry()` when no registry is given and runs `_filter_registry`. Without
   filters the registry object is used as is; with any filter, a new `Registry` receives the
   specs that pass. Category filters apply to every kind; tool filters only to tools.
4. Validates the prefix against `^[A-Za-z0-9_.-]{0,64}$` (`ValueError` otherwise) and stores
   it with the middleware list, timeout, output cap and identity.
5. Hooks `workspace.on_change(self.notify_change)` when the workspace has `on_change`.
   That is how dataset changes reach the adapters.

`internal_name(exposed)` strips the prefix. With a prefix set, a name without it maps to a
key that can never be in the registry, so only prefixed names resolve, in-process as well as
through the adapters. `register_into(prefix=...)` assigns `layer.prefix` directly and skips
the constructor's validation (section 11).

### 4.2 The middleware chain

```python
async def _run_chain(self, info, terminal):
    chain = terminal
    for mw in reversed(self.middleware):
        chain = _bind(mw, chain)        # async def call(info): return await mw(info, nxt)
    return await chain(info)
```

The chain is rebuilt for each call, so `layer.use(mw)` takes effect on the next request.
`middleware[0]` is outermost. The terminals are `_tool_terminal`, `_resource_terminal`,
`_prompt_terminal` and `_completion_terminal`.

### 4.3 Running handlers: loop or thread

```python
async def _invoke(self, fn, ctx, kwargs):
    self._remember_loop()                 # self._loop = asyncio.get_running_loop()
    ctx.loop = self._loop
    if asyncio.iscoroutinefunction(fn):
        return await fn(ctx, **kwargs)
    result = await asyncio.to_thread(fn, ctx, **kwargs)
    return await maybe_await(result)
```

Coroutine functions run on the loop and can be cancelled. Plain functions run in the default
thread pool executor, so CPU-heavy graph work does not block other requests, at the price
that they cannot be cancelled. A sync function that returns an awaitable has it awaited on
the loop. Resource, prompt and completion handlers go through `_invoke` as well.

`_remember_loop` is what lets the rest of the layer talk to the loop from worker threads: it
records the serving loop on the layer and on the context the first time a handler runs.

### 4.4 Timeouts

In `_tool_terminal`:

```python
timeout = spec.timeout_seconds or self.default_timeout
coro = self._invoke(spec.handler, info.context, kwargs)
raw = await (asyncio.wait_for(coro, timeout) if timeout else coro)
```

`asyncio.TimeoutError` becomes `_error_result("Tool X timed out", ..., "timeout")`. For an
async handler, `wait_for` cancels the coroutine. For a sync handler it cancels the
`to_thread` future, and the thread runs on. Resources, prompts and completions have no
timeout. A per-tool `timeout_seconds` always beats `default_timeout`, larger or smaller.

### 4.5 `notify_change` from any thread

```python
def notify_change(self, kind, uri=None):
    loop = self._loop
    if loop is not None and loop.is_running():
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not loop:
            loop.call_soon_threadsafe(self._dispatch_change, kind, uri)
            return
    self._dispatch_change(kind, uri)
```

Sync tool handlers call workspace methods in a worker thread, and the workspace fires
`notify_change` from that thread. Adapter listeners touch sessions and asyncio queues, which
are not thread-safe, so the layer hops onto the serving loop first. Before any handler has run
(`_loop` is `None`) the listeners run inline. Listener exceptions are logged at DEBUG and
swallowed. `ChangeFanout` and `NativeMCPServer` do a second hop of their own because they may
be bound to a different loop than the one the layer remembered.

### 4.6 `report_progress_sync`

`ToolContext.report_progress` is a coroutine and enforces the MCP rule that progress must
increase (it remembers the last value and drops anything not greater).
`report_progress_sync` schedules it on `ctx.loop` with
`asyncio.run_coroutine_threadsafe` and returns without waiting; when there is no callback, no
loop, or the loop is closed, it does nothing. The adapters' progress callbacks repeat the
monotonic check, so a value is never sent twice even if two code paths report it.

`ToolContext.log` maps the MCP level to a stdlib level (`notice` 25, `alert` 55, `emergency`
60), logs locally on `cloudg.mcp`, then calls the adapter's log callback. Unknown levels
become `info`. Callback failures never break the tool.

### 4.7 Where transforms are applied

`_transform(value, spec, principal, kind)` gets `policy.output_pipeline(spec, principal)`,
returns the value unchanged when the pipeline is empty, and otherwise runs it with a fresh
`TransformContext(direction="output", vault=policy.vault)`, returning `(value, report)`.
`_untransform_arguments` does the same with `input_pipeline` and `direction="input"`.

| Point | Code | Transformed |
|---|---|---|
| Tool arguments | `_tool_terminal` | input pipeline, after `check_call`, before validation; a refusal here calls `policy.record_rejection` |
| Template variables | `_resource_terminal` | input pipeline |
| Prompt arguments | `_prompt_terminal` | input pipeline, then filtered to declared argument names |
| Completion partial value and context arguments | `_completion_terminal` | input pipeline over `{"partial", "arguments"}` |
| Plain tool result | `_finalise_tool_result` | output pipeline over the structured dict; the text block is a dump of the transformed dict |
| Handler-built `ToolResult` | `_finalise_tool_result` | `structured`, every `TextContent`, every `ResourceLink`, the text of every `EmbeddedResource` holding `TextResourceContents`, and `meta` |
| `ctx.link` links | `_transform_links` | `uri`, `name`, `title`, `description` as one dict |
| Error results | `_error_result` | the message and `data` |
| Resource contents | `_resource_terminal` | `str` results, JSON results, `TextResourceContents` in a returned list; not `bytes` |
| Prompt messages | `_prompt_terminal` | `TextContent`, text `EmbeddedResource`, `ResourceLink` |
| Completion values | `_completion_terminal` | each value wrapped as `{argument_name: value}`, so key-based detectors (names, account ids) see a key, then unwrapped |
| List definitions | `tools_wire` | not transformed; `outputSchema` withheld when the output pipeline is non-empty |

Reports are merged with `_merge_report` (numbers add up, other values keep the first seen) and
stored under `_meta["cloudg/transforms"]` for tools and plain resource results. The report on
list-of-contents resource results, on prompts and on completions is discarded. An
`ImageContent`, or an `EmbeddedResource` holding a blob, in a handler-built `ToolResult` is not
transformed. When the text block of a plain result is cut, `report["truncated_chars"]` is the
number of characters removed.

### 4.8 Error results

`call_tool` wraps `_run_chain` in `except MCPLayerError` and converts the exception with
`_error_result(exc.message, spec, principal, exc.code, exc.data)`. The terminal re-raises
`MCPLayerError` and turns `asyncio.TimeoutError` and any other exception into error results
itself, logging the traceback with `logger.exception("Tool %s failed", name)`. Only
`get_tool`, which runs before the chain, can raise out of `call_tool`.

`get_tool`, `_resolve_resource` and `get_prompt` call `_record_hidden(kind, name, principal)`
before raising `NotFoundError`, which forwards to `policy.record_hidden` when the policy has
it; the policy writes a `not_found` audit entry. Failures there are logged at DEBUG and never
change the answer.

`read_resource` and `get_prompt` do not catch anything, so policy errors, handler
`NotFoundError`s and unexpected exceptions propagate to the adapter, which maps them to
JSON-RPC errors. `get_prompt` checks required arguments before building the context.

### 4.9 Completions

```python
async def complete(self, ref, argument, *, principal=None, context_arguments=None) -> dict
```

1. Find the function: for `ref/prompt`, the matching `PromptArgument.completion` (the prompt
   name goes through `internal_name`); for `ref/resource`,
   `template.completions[argument name]`, where `ref["uri"]` must be the template string
   exactly.
2. No spec, no function, or the spec not visible to the principal: return empty values
   without touching the chain.
3. Build a context with `kind="completion"`, stash the function in
   `ctx.meta["completion_fn"]`, and run the middleware chain with
   `CallInfo("completion", name, spec, {"argument", "value", "context"}, principal, ctx)`, where
   `name` is the prompt name or the template string. Audit and metrics see the call;
   `CachingMiddleware` never caches it.
4. `_completion_terminal` calls `policy.check_call(spec, principal, {"__completion__": name})`,
   which applies access and rate limits and records the decision with kind `completion`. It
   raises, and nothing catches it, so a denied or rate-limited completion becomes a protocol
   error in the adapters.
5. Reverse pseudonyms in the partial value and in the context arguments; the restored
   context arguments go to `ctx.meta["arguments"]`.
6. Run the function through `_invoke` with `partial=...`. Any exception returns empty values
   (logged at DEBUG).
7. Run the output pipeline over the values (wrapped under the argument name, 4.7), return the
   first 100 with `total` and `hasMore`.

The function computes every candidate before the cap applies, so keep completion functions
cheap or cap them yourself.

## 5. Inside the adapters

### 5.1 Detection

`detect_server_kind(server)` checks, in order: `NativeMCPServer` instance; any class in the
MRO named `FastMCP` from a module whose top package is `fastmcp`; a type whose module starts
with `mcp.server.mcpserver` or `mcp.server.fastmcp`; an instance of
`mcp.server.lowlevel.Server`; duck typing (`add_request_handler` or `request_handlers` means
low-level; `_lowlevel_server` or `_mcp_server` means high-level). `register_into` sets the
prefix first, then calls the matching `install`.

### 5.2 `lowlevel.py`: `LowLevelBinding`

The binding wraps request handlers in place. `_METHODS` lists what it handles:

| Method | 1.x request class | 2.x params class | `include` kind | Implementation |
|---|---|---|---|---|
| `tools/list` | `ListToolsRequest` | `PaginatedRequestParams` | tools | `_list_tools` |
| `tools/call` | `CallToolRequest` | `CallToolRequestParams` | tools | `_call_tool` |
| `resources/list` | `ListResourcesRequest` | `PaginatedRequestParams` | resources | `_list_resources` |
| `resources/templates/list` | `ListResourceTemplatesRequest` | `PaginatedRequestParams` | templates | `_list_templates` |
| `resources/read` | `ReadResourceRequest` | `ReadResourceRequestParams` | resources | `_read_resource` |
| `prompts/list` | `ListPromptsRequest` | `PaginatedRequestParams` | prompts | `_list_prompts` |
| `prompts/get` | `GetPromptRequest` | `GetPromptRequestParams` | prompts | `_get_prompt` |
| `completion/complete` | `CompleteRequest` | `CompleteRequestParams` | completions | `_complete` |
| `resources/subscribe` | `SubscribeRequest` | `SubscribeRequestParams` | subscriptions | `_subscribe` |
| `resources/unsubscribe` | `UnsubscribeRequest` | `UnsubscribeRequestParams` | subscriptions | `_unsubscribe` |
| `logging/setLevel` | `SetLevelRequest` | `SetLevelRequestParams` | logging | `_set_level` |

`sdk_major` is 2 when the server has `add_request_handler`, else 1.

On mcp 2.x, `_install` reads the existing entry with `server.get_request_handler(method)`,
keeps its handler as `orig` and its params type, and registers
`handler(ctx, params)`, which calls `impl(ctx, params_as_wire_dict, orig_call)` where
`orig_call` is `lambda: orig(ctx, params)` or `None`. On mcp 1.x it replaces
`server.request_handlers[RequestClass]` with `handler(req)`, which fetches
`server.request_context` (a `LookupError` means no context), calls the implementation and
wraps the result in `ServerResult`; `orig_call` unwraps the original's `.root`. Every
implementation therefore receives the context, the params as a camelCase dict, and a way to
call the host's handler.

Routing by ownership:

- `tools/call` and `prompts/get`: `owns_tool / owns_prompt` require the prefix (when set) and
  a registry entry for the stripped name. Not ours: call the host, or raise -32602
  `Unknown tool` when there is no host handler.
- `resources/read`: `owns_resource` is an exact URI match or any template match. Not ours:
  host, or -32602 / -32002 by era.
- `completion/complete`: ours when the prompt or the exact template string is ours; else the
  host, or an empty completion.
- `resources/subscribe`, `unsubscribe`, `logging/setLevel`: recorded for cloudg, then always
  passed to the host when it has a handler.

List methods call the host first (when there is a host handler) and append cloudg's entries
in `_merge`. When the host's result has a `nextCursor`, cloudg returns it untouched, so
cloudg's entries end up after the host's last page. Entries whose key (name, URI or template)
the host already has are dropped with a warning.

Errors raised to the SDK are `MCPError(code, message, data)` on 2.x and
`McpError(ErrorData(...))` on 1.x. `NotFoundError` from `read_resource` uses -32602 on
2026-07-28 requests and -32002 otherwise; `InvalidArgumentsError` maps to -32602; other layer
errors keep their own code.

Era and session bookkeeping: `_is_modern(ctx)` compares `ctx.protocol_version` with
`mcp_types.version.MODERN_PROTOCOL_VERSIONS`. `_session_key(ctx)` is the per-connection
object used for subscriptions, log levels and list-changed fan-out: on 2.x the private
`ctx.session._connection` for handshake-era requests and `None` for 2026 requests (which have
no connection to notify); on 1.x the `ServerSession` itself.

Principal: `request_info(ctx)` reads `ctx.request` (the Starlette request on HTTP) for
headers and the ASGI scope (where `TokenAuthASGIMiddleware` put the principal), asks
`mcp.server.auth.middleware.auth_context.get_access_token()` for an OAuth token, and reads
`ctx.session.client_params.client_info`. The transport is `http` when there is a request and
`stdio` otherwise.

Tool context: `_tool_context(ctx, principal)` builds a `ToolContext` whose progress callback
calls `session.report_progress(...)` on 2.x (the SDK sends nothing unless the client sent a
progress token) or `session.send_progress_notification(token, ...)` on 1.x (only with a
`progressToken` in `ctx.meta`, falling back to the old signature without `message`), and
whose log callback filters by the level set with `logging/setLevel` (default `info`) on
handshake-era sessions and calls `session.send_log_message(...)`. On 2026 requests the SDK
itself drops log notifications unless the request asked for them.

Three further patches:

- `_find_bus()` (2.x): use `MCPServer._subscriptions` when the owner has one, else the bus
  of an existing `subscriptions/listen` handler (`handler._bus`), else install
  `ListenHandler(InMemorySubscriptionBus())` when `subscriptions` is included. Change events
  are published on it as `ToolsListChanged`, `PromptsListChanged`, `ResourcesListChanged`
  and `ResourceUpdated(uri)`.
- `_patch_initialization_options()`: wraps `server.create_initialization_options` so that,
  when called without `NotificationOptions`, it advertises `listChanged` for tools,
  resources and prompts. Applied once per server (`_cloudg_init_patched`).
- `_patch_input_schema()` (2.x): wraps `server.get_tool_input_schema` so the SDK's
  `Mcp-Param-*` header validation sees cloudg's input schemas for cloudg tools.

The binding appends itself to `server.__dict__["_cloudg_bindings"]`, which keeps it (and its
`ChangeFanout`) alive as long as the server.

### 5.3 `mcp_sdk.py`

`is_sdk_highlevel_server(obj)` checks the module path; `inner_lowlevel_server(server)`
returns `server._lowlevel_server` (mcp 2.x `MCPServer`) or `server._mcp_server` (mcp 1.x
`FastMCP`) and raises `TypeError` with a pointer to `build_server` when neither exists;
`install` applies `LowLevelBinding` to the inner server with `owner=server`, which is where
`_find_bus` looks for `_subscriptions`. The host's decorated tools live in the same low-level
handlers, which is why wrapping works without touching the high-level API.
`create_lowlevel_server(layer, name=None)` builds `Server(name, version=..., instructions=...)`,
retrying without `instructions` for very old 1.x; `create_highlevel_server` builds `MCPServer`
on 2.x and `FastMCP` on 1.x.

### 5.4 `fastmcp.py`: `FastMCPBinding`

fastmcp keeps tools, resources, templates and prompts as component objects, and its own list
handlers render them. The binding defines four subclasses at install time, closing over the
binding:

| Class | Base | Override |
|---|---|---|
| `CloudGTool` | `fastmcp.tools.Tool` | `run(arguments)` calls `binding._run_tool(self.name, arguments)` |
| `CloudGResource` | `fastmcp.resources.Resource` | `read()` calls `binding._read(uri)` |
| `CloudGTemplate` | `fastmcp.resources.ResourceTemplate` | `matches(uri)` uses cloudg's regex; `create_resource` returns a `CloudGResource`; `read(arguments)` expands the template and reads |
| `CloudGPrompt` | `fastmcp.prompts.Prompt` | `render(arguments)` calls `binding._render(name, arguments)` |

`_register` instantiates one per spec with `parameters` set to the layer's `inputSchema`,
`output_schema`, annotations (as `mcp.types.ToolAnnotations`), `title` and `meta` when the
installed fastmcp's model has those fields, and tags `{"cloudg", category, *tags}`. Template
parameters are a synthetic object schema with one required string per variable. Tools and
prompts are registered under their exposed names, so set the prefix before installing (which
`register_into` does).

Tool results: fastmcp normally rebuilds the `CallToolResult` from its own `ToolResult`. To
keep cloudg's exact result (including `isError` with structured content and `_meta`), the
binding uses `ToolResult.from_mcp_result` on fastmcp 4 and, on older versions, a `ToolResult`
subclass whose `to_mcp_result()` returns the stored raw `CallToolResult`. The subclass is a
pydantic model with a private attribute where the base class is a pydantic model (fastmcp
3.4.8) and a plain subclass otherwise (2.14.7).

Resource reads return fastmcp 3/4's `ResourceResult([ResourceContent(...)])` when available,
else the first content's text or bytes. Prompt renders return fastmcp's `PromptResult` and
`Message` on newer versions and a list of SDK `PromptMessage` on fastmcp 2.

Policy filtering: fastmcp lists every registered component to everyone, so
`_install_middleware` adds a fastmcp `Middleware` subclass (`on_list_tools`,
`on_list_resources`, `on_list_resource_templates`, `on_list_prompts`) that drops cloudg
components the caller may not see and swaps in the per-principal `outputSchema`. Calls are
still enforced by the layer when the middleware is missing (fastmcp older than 2.9).

Protocol features: completions and resource subscriptions cannot be expressed as fastmcp
components, so `_install_lowlevel` applies `LowLevelBinding` with
`include={"completions", "subscriptions"}` and `list_changed=False` to `server._mcp_server`,
and the binding then shares that binding's `ChangeFanout`. Verified state per version:

| fastmcp | mcp | inner binding `sdk_major` | 2026 listen bus | result class |
|---|---|---|---|---|
| 4.0.11 | 2.3.0 | 2 | yes | none (`from_mcp_result`) |
| 3.4.8 | 1.30.0 | 1 | no | `RawToolResult` (pydantic) |
| 2.14.7 | 1.30.0 | 1 | no | `PlainRawToolResult` |

Request facts come from `fastmcp.server.dependencies.get_context()`, `get_http_request()` and
`get_access_token()`. Errors: `NotFoundError` becomes fastmcp's `NotFoundError`, other layer
errors `ToolError`, `ResourceError` or `PromptError` (`ToolError` when the installed version
has no `PromptError`).

### 5.5 `export.py`

`export_definitions(layer, principal)` snapshots the four wire lists for the principal and
returns closures over `layer`. The handlers take `(params, *, principal=None)` so a gateway
can serve many principals from one export; `tool_functions` are bound to the export's
principal. The converters read `layer.tools_wire(principal)` and reshape it; they do not
call the layer.

### 5.6 `ChangeFanout`

```python
ChangeFanout(layer, notifier, publish=None)
```

Registers a weakly referenced listener on the layer. `track(session)` records a session
(weak set) and binds the fan-out to the running loop. `on_change(kind, uri)` schedules
`_dispatch` on that loop, directly when called on it and with `run_coroutine_threadsafe`
from other threads. `_dispatch` expands `resources` with a URI into a list change plus an
update, publishes each event on the 2026 bus when `publish` is set, and calls
`notifier(session, kind, uri)` for every tracked session, sending `resource` events only to
sessions subscribed to that URI. A session whose notification raises is dropped. Sessions,
subscriptions and log levels are all held in weak containers, so closed connections
disappear on their own.

## 6. Inside the native server

### 6.1 `jsonrpc.py`

| Constant | Value |
|---|---|
| `HANDSHAKE_VERSIONS` | 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 |
| `MODERN_VERSIONS` | 2026-07-28 |
| `BATCH_VERSIONS` | 2024-11-05, 2025-03-26 |
| `DEFAULT_HTTP_VERSION` | 2025-03-26 (HTTP request without `MCP-Protocol-Version`) |
| `CACHEABLE_METHODS` | the four list methods, `resources/read`, `server/discover` |
| Envelope keys | `io.modelcontextprotocol/protocolVersion`, `.../clientInfo`, `.../clientCapabilities`, `.../logLevel`, `.../serverInfo`, `.../subscriptionId` |
| Codes | -32700, -32600, -32601, -32602, -32603, -32002, -32020, -32022 |
| `LOG_LEVELS` | debug, info, notice, warning, error, critical, alert, emergency |

`valid_id` accepts strings and integers (not booleans or null). `dumps` produces compact
single-line JSON, which stdio framing needs.

### 6.2 `protocol.py`

`NativeMCPServer(layer, *, page_size=100, principal_resolver=None, default_log_level="info",
cache_ttl_ms=0, cache_scope="private", title="cloudg")` holds what is shared across
connections: the layer, the resolver, the list page size, the 2026 cache hints, the set of
open listen streams and a weak set of handshake-era sessions for change fan-out. It registers
a weakly referenced listener on the layer and binds to the first running loop it sees.

`create_session(*, transport, send, principal, session_id, stateless_version, register)`
returns a `Session`. `send` delivers server-initiated messages; `principal` defaults to the
resolver's answer for the transport; `stateless_version` makes a pre-initialized
handshake-era session (stateless HTTP); `register=False` keeps one-shot sessions out of the
fan-out.

Session state:

| Attribute | Meaning |
|---|---|
| `era` | `None` until the first request, then `"legacy"` or `"modern"` |
| `protocol_version` | negotiated (legacy) or last seen (modern) version |
| `init_responded`, `initialized` | `initialize` answered; `notifications/initialized` received |
| `client_info`, `client_capabilities` | from `initialize` or the envelope |
| `log_level` | threshold for log notifications (legacy era) |
| `subscriptions` | URIs from `resources/subscribe` |
| `_inflight`, `_cancelled` | request id to task; ids cancelled by the client |

`handle(message, *, sink=None, principal=None)` accepts one decoded message or a list. Lists
are rejected unless the session is legacy with a batch version; allowed batches run their
items concurrently with `asyncio.gather`. For a single message `_handle_one` validates the
envelope (`jsonrpc: "2.0"`, string method, valid id, object params), ignores stray responses,
handles notifications, and sends requests to `_handle_request`.

`_handle_request` registers the current task under the request id (for cancellation), calls
`_route` to build a `_RequestCtx`, looks up the implementation in
`_METHODS[(modern, method)]`, stamps 2026 results, and returns the response. A
`JSONRPCError` becomes an error response; a `CancelledError` for an id in `_cancelled`
returns `None` (no response, as MCP requires for cancelled requests) after `uncancel()`;
anything else is logged and answered with -32603 "Internal error".

`_route` implements the era rules:

1. `initialize` on a modern session raises -32022; otherwise it is routed as legacy.
2. A request with the 2026 envelope on a legacy session raises -32600. On a new or modern
   session it needs `clientCapabilities` (-32602), a string version (-32602) and a supported
   version (-32022), then marks the session modern and records client info, capabilities and
   the per-request log level.
3. A request without the envelope on a modern session raises -32602.
4. Before `initialize` only `ping` is accepted (-32600 otherwise).

`_stamp_modern` adds `resultType: "complete"`, `ttlMs` and `cacheScope` for cacheable
methods, and `io.modelcontextprotocol/serverInfo` in `_meta`.

Method tables: common to both eras are the list methods, `tools/call`, `resources/read`,
`prompts/get` and `completion/complete`. Legacy only: `initialize`, `ping`,
`resources/subscribe`, `resources/unsubscribe`, `logging/setLevel`. Modern only:
`server/discover` and `subscriptions/listen`.

Notifications: `notifications/initialized` sets `initialized`; `notifications/cancelled`
cancels the task registered under `requestId`; everything else is ignored.

Progress and logs: `_tool_context(rc)` reads `progressToken` from the request's `_meta` and
returns a `ToolContext` whose progress callback sends `notifications/progress` (only with a
valid token and only increasing values) and whose log callback sends `notifications/message`
when the level reaches the threshold: the session's `logging/setLevel` value on the legacy
era, the request's `logLevel` on the modern era, where no level means no log notifications.
`rc.notify` writes to the request's `sink` when the transport gave one (an SSE stream) and to
the session's `send` otherwise.

Listen streams: `_m_listen` honors `toolsListChanged`, `promptsListChanged`,
`resourcesListChanged` and `resourceSubscriptions`, sends
`notifications/subscriptions/acknowledged`, then forwards events from a bounded queue
(1024 entries; overflow is dropped with a warning) until `close_listens()` puts `None` on the
queue, when it returns its final result `{"_meta": {subscriptionId}}`. Every notification
carries the listen request's id as `io.modelcontextprotocol/subscriptionId`.

Change dispatch: `_on_layer_change` hops to the server's loop when called from another
thread; `_dispatch_change` expands the event like `ChangeFanout`, feeds listen streams that
want it, and calls `_emit_change` on every registered legacy session, which sends list
changes to initialized sessions and resource updates only for subscribed URIs.

Pagination: `paginate(kind, items, cursor)` decodes the cursor (URL-safe base64 of
`{"k": kind, "o": offset}`, padding stripped), rejects a wrong kind, negative offset or
garbage with -32602 "Invalid cursor", and returns a page plus the next cursor.

### 6.3 `stdio.py`

`protected_stdout()` flushes `sys.stdout`, duplicates fd 1 twice (one copy for the protocol,
one to restore later), points fd 1 at stderr with `dup2`, sets `sys.stdout = sys.stderr`, and
yields an unbuffered binary stream on the protocol copy. On exit it restores fd 1 and
`sys.stdout`. When stdout has no file descriptor (pytest capture, some IDEs) it yields the
current stdout unchanged.

`run_stdio_async(server, *, stdin=None, stdout=None, principal=None, protect_stdout=True,
shutdown_grace=5.0)` creates one session with `Principal.local()` unless told otherwise,
starts a daemon reader thread (`readline` loop, lines handed to the loop with
`call_soon_threadsafe`; a thread works the same on POSIX pipes and Windows consoles), and a
writer task that serializes every outgoing message through one queue and writes it with
`asyncio.to_thread`. Lines that are not JSON get a -32700 response. `initialize`,
notifications and responses are processed inline, in order; other requests and batches become
tasks. At EOF the `finally` block closes listen streams, waits up to `shutdown_grace` for
pending tasks, cancels the rest, closes the session and the server, and drains the writer.

### 6.4 `http.py`

`NativeHTTPServer(server, config)` with `HTTPConfig` fields: `host`, `port`, `path`,
`enable_sse`, `sse_path` (`/sse`), `message_path` (`/messages/`), `allowed_origins`,
`allowed_hosts`, `auth`, `json_response`, `stateless`, `max_body_bytes` (4 MiB),
`session_idle_timeout` (3600 s), `max_sessions` (1000), `keepalive_interval` (15 s),
`cors_origins`, `health_path` (`/healthz`).

Request reading (`_read_request`): headers up to 64 KiB (`StreamReader` limit), repeated
headers joined with `, `, bodies by `Content-Length` or chunked encoding, both capped by
`max_body_bytes`. A connection serves requests in a loop while keep-alive holds; each read
waits at most 120 s.

`_dispatch` order: `self.guard.check(host, origin)`, then `OPTIONS`, health, bearer auth,
principal resolution (the token principal goes in as `RequestInfo.principal`, so a custom
resolver can see and replace it), then routing by path and method.

`OriginHostGuard(bind_host, allowed_origins=None, allowed_hosts=None, extra_origins=())` is the
check every flavor shares. `check(host, origin)` returns `None` or `(status, message)`:

1. Host: when `allowed_hosts` is given, or the bind is loopback (then the loopback names are
   the list), a missing `Host` or one that matches no pattern gives
   `(421, "Invalid Host header")`. Other binds skip this step.
2. Origin: absent passes. Otherwise it must match the origins (default the loopback origins,
   plus `extra_origins`, which the native server fills from `cors_origins`) or be same-origin
   (`urlsplit(origin).netloc` equal to `Host`, case-insensitive), else
   `(403, "Forbidden: invalid Origin")`.

The allow-lists are `fnmatch` patterns compared case-insensitively.

`_post`:

1. Content type, `Accept` and JSON parsing.
2. A batch containing any 2026 envelope: 400.
3. A single 2026 request: `_modern_rejection` applies the SDK's ladder, first failure wins,
   HTTP 400 with the JSON-RPC error: both envelope keys present (-32602); then
   `MCP-Protocol-Version` present and equal to the envelope version, `Mcp-Method` equal to the
   method, and for `tools/call`, `prompts/get` and `resources/read` `Mcp-Name` (decoded from
   `=?base64?...?=` when needed) equal to `name` or `uri` (-32020); then the version a string
   (-32602) and supported (-32022). A one-shot unregistered session then handles it.
4. Unsupported `MCP-Protocol-Version`: 400.
5. Stateless mode: a one-shot session, pre-initialized unless the message is `initialize`.
6. `initialize`: new session, `Mcp-Session-Id` header.
7. Otherwise look up the session (400 / 404) and check the version header against the
   negotiated version.
8. Only notifications and responses: handle, answer 202.
9. Requests: `_respond`.

`_respond` decides between JSON and SSE (see the table in MCP.md section 6.2). In SSE mode
it starts `session.handle(..., sink=queue.put)` as a task, streams queued notifications as
they come, sends a keep-alive comment when nothing arrived for `keepalive_interval`, then
flushes the queue, writes the response and the terminating chunk. If the client disconnects,
2026 requests and listen streams are cancelled; handshake-era requests keep running, since
that era lets a server finish work after the stream drops.

GET opens `_pump`, which drains the session's outbox (a bounded deque fed by the session's
`send`) as SSE and sends keep-alives; `None` in the outbox ends the stream. DELETE removes the
session and pushes `None`. A reaper task expires sessions idle longer than
`session_idle_timeout` that have no open stream. The legacy SSE transport creates a session on
`GET /sse`, emits the `endpoint` event, and POSTs to `/messages/?session_id=...` handle the
message (requests other than `initialize` concurrently) and push responses to the stream.

`start()` warns when bound to a non-loopback address without auth, binds, records
`self.bound` (port 0 gives a free port) and starts the reaper; `serve_forever()` runs until
cancelled and then `aclose()`s: listen streams closed, sessions ended, sockets closed,
connection tasks cancelled. `run_http_async(server, config)` is start plus serve.

### 6.5 `auth.py`

`TokenAuth` stores `(sha256(token), Principal)` pairs. `add(token, value)` accepts a
`Principal` (kept as given), a comma-separated role string or an iterable of roles; the last
two always get `default` added. `lookup(token)` compares the probe digest with every entry
using `hmac.compare_digest` and returns a copy of the matching principal, so callers may
mutate it. `authenticate(header)` extracts the bearer token first.

`parse_token_spec(spec)` reads `TOKEN[:ROLES[:ID]]` from the right (`spec.rsplit(":", 2)`), so
a token containing `:` needs both fields, possibly empty (`abc:def::`); `env:VAR[:ROLES[:ID]]`
takes the token from the environment. Roles always include `default`; the id defaults to
`token-` plus the first 8 hex characters of the token's SHA-256. MCP.md section 6.3 has a
table of real parses. `default_principal_resolver` is described in MCP.md section 8.8;
`anonymous_principal()` is `Principal(id="anonymous", roles={"default"})`.
`PRINCIPAL_SCOPE_KEY = "cloudg.principal"` is the ASGI scope key shared with
`TokenAuthASGIMiddleware`.

## 7. server.py and cli.py

`create_layer_from_options` loads the config (`config` or `config_path`), takes the default
registry or the one given, applies `read_only_registry` when asked, builds the middleware
stack (audit if a path is given, metrics unless `metrics=False`, concurrency if a limit is
given, cache if a TTL is given, then any extra middleware), constructs the layer, attaches
the cache to change events, registers `cloudg://metrics` when metrics are on and the URI is
free, and loads each `--dataset`. `_load_dataset` deliberately bypasses `check_path` (the
operator chose the file), using `state.load_dataset_file` and `ws.unique_name`, and raises
`FileNotFoundError` for missing paths.

`resolve_flavor` turns `auto` into `sdk` or `native`. `validate_serve_options(flavor,
transport, *, cors_origins, json_response, stateless)` resolves the flavor and raises
`ValueError` for combinations a flavor cannot honor (CORS outside the native flavor;
`--json-response` or `--stateless` with the fastmcp flavor on `sse`); the CLI calls it before
building the layer and turns the error into a usage error. `serve_async` calls it again,
then `_ensure_stderr_logging` (sets the `cloudg` logger's level; adds a flagged stderr handler
to `cloudg` only when neither root nor `cloudg` has any handler), builds token auth, logs that
tokens are ignored on stdio, and delegates through `_dispatch_serve`. Its `finally` block
calls `layer.policy.save_vault()` and logs where the vault went, so a cancelled or crashed
server still persists pseudonyms when the policy has a vault path.

- `_serve_native`: builds `NativeMCPServer`; stdio via `run_stdio_async`, HTTP via
  `NativeHTTPServer` with an `HTTPConfig` from the options (`enable_sse` for `sse`); prints
  the URL to stderr and resolves `ready`. The HTTP server builds its own `OriginHostGuard`.
- `_serve_sdk`: `build_server(layer, "lowlevel", principal_resolver=...)`. stdio: on 2.x the
  SDK's `stdio_server()`, on 1.x the same inside `protected_stdout()` with an
  `anyio.wrap_file` text wrapper. HTTP: `_security_settings()` returns
  `TransportSecuritySettings(enable_dns_rebinding_protection=False)` (or `None` before mcp
  1.10), because the SDK can only check Host and Origin together and would have to drop the
  Origin check on a non-loopback bind; on 2.x `server.streamable_http_app(...)`, on 1.x a
  `StreamableHTTPSessionManager` behind a Starlette route with a lifespan that runs it; for
  `sse`, `SseServerTransport("/messages/")` routes in front; everything wrapped in
  `TokenAuthASGIMiddleware(app, auth, _guard(host, allowed_origins, allowed_hosts))` and run
  with uvicorn (`lifespan="on"`).
- `_serve_fastmcp`: `build_server(layer, "fastmcp")`; stdio via
  `run_async(transport="stdio", show_banner=False)` (falling back for versions without
  `show_banner`); HTTP via `server.http_app(transport="http" or "sse", ...)`. For `http` it
  passes `path`, and `json_response` / `stateless_http` when set, after checking with
  `inspect.signature` that the installed fastmcp accepts them; when `http_app` takes
  `host_origin_protection` it passes `False`, since cloudg's guard runs in front. The app is
  wrapped in `TokenAuthASGIMiddleware` with the same guard and run with uvicorn.

`TokenAuthASGIMiddleware(app, auth, guard=None)` passes non-HTTP scopes through; on HTTP it
runs `guard.check(host, origin)` (421 / 403 as JSON-RPC error bodies), then the bearer check
(401 with `WWW-Authenticate`), then stores the principal under `"cloudg.principal"` in the
scope and in `scope["state"]`.

`_asgi_endpoint(fn)` wraps a raw ASGI callable in a class instance so Starlette's `Route`
treats it as an ASGI app (a plain function would be called as a request handler).

`cli.py`: `_layer_options` and `_principal_options` attach the shared options; `_build_layer`
calls `create_layer_from_options` with the root command's `CloudGConfig` (from `ctx.obj`)
unless `-c` was given on the subcommand, and turns `FileNotFoundError` / `ValueError` (an
invalid prefix included) into click errors. `serve_cmd` runs `validate_serve_options` and
checks token specs before building anything. `_load_registry` imports `MODULE:ATTR` (attribute path may be dotted; default
`default_registry`), calls it when it is callable and not a `Registry`, and checks the type.
`_stdout_console` prints tables at a fixed width of 160 columns when stdout is not a TTY, so
piped output does not wrap URIs. `client_config` and `_server_command` build the `config`
snippets. `main()` enables `logging.captureWarnings` and runs the group.

The root `cloudg` CLI (`cloudg/cli.py`) adds `mcp_group` with one `add_command` line and, when
the invoked subcommand is `mcp`, switches its Rich console to stderr before printing the
banner.

## 8. Adding a tool, resource, template or prompt

The steps, then a complete module and its tests. The example was run from outside the repo
(module and test in a scratch directory, `-p tests.mcp.conftest` to load the fixtures) and its
four tests passed.

1. Pick a category. A new category needs an entry in `catalog/__init__.py:CATEGORIES` and
   in `OWN_CATEGORIES` at the top of `tests/mcp/test_catalog_registry.py`; an existing one
   needs nothing. Prompts always use category `prompts`, whatever module defines them.
2. Write the handler with `ctx` first and every argument annotated. Use the aliases from
   `catalog/_common.py` (`DatasetArg`, `RefArg`, `Limit`, `Cursor`) so arguments are
   described the same way across the catalog. Tools in the inventory, graph, findings,
   ontology and export categories take a `dataset` argument. Give the docstring the job
   description the model will read: what it returns, when to use it, an example call. The
   registry test wants more than 40 characters and a `title`.
3. Declare honest metadata: `sensitivity` (what the output may contain), `capabilities`
   (what side effects it needs), and the hints when the derivation in 3.5 would be wrong.
   Policies act on these. The registry test requires `read_only`, `idempotent` and
   `open_world` to end up set, no write, cloud or exec capability on a read-only tool, and
   `open_world` true exactly when the tool has `cloud_access`.
4. Return compact data. Use `asset_brief` / `finding_brief` and resource URIs instead of full
   objects, paginate lists with `paginate` and `fingerprint`, and attach `ctx.link(...)` for
   detail views.
5. Fail with `InvalidArgumentsError` for bad input and `ReferenceNotFoundError` (or another
   `NotFoundError`) for misses, with suggestions in `data=`. The model gets both.
6. Add an output schema only from a model whose fields are all optional with
   `extra="allow"` (like the `*Out` models), so transforms cannot break it, and add the tool
   with sample arguments to `OUTPUT_CALLS` in `test_catalog_registry.py`; that test calls it
   on the sample estate and validates the result against the schema.
7. Template variables each need a completion function; required prompt arguments need one
   too, and every prompt argument needs a description.
8. Register the module in `catalog/__init__.py:_modules()` and write tests with the `call`
   fixture.
9. Run `tests/mcp/test_catalog_registry.py`; it checks the rules above for the whole
   catalog and validates every wire dict with the SDK's types when `mcp` is installed.

`cloudg/mcp/catalog/owners.py`:

```python
"""Ownership tools: who owns what, by the ``owner`` tag."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from cloudg.mcp.catalog._common import (
    DatasetArg,
    Limit,
    Cursor,
    asset_brief,
    fingerprint,
    paginate,
    ws_dataset,
)
from cloudg.mcp.core import (
    PromptArgument,
    PromptMessage,
    PromptResult,
    Registry,
    Sensitivity,
    TextContent,
)
from cloudg.mcp.schema import output_schema_for
from cloudg.mcp.state import ReferenceNotFoundError

CATEGORY = "ownership"


class OwnerAssetsOut(BaseModel):
    model_config = ConfigDict(extra="allow")
    owner: str | None = None
    total: int | None = None
    next_cursor: str | None = None
    items: list[dict[str, Any]] = Field(default_factory=list)


def _owners(ds: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in ds.assets:
        owner = a.tags.get("owner")
        if owner:
            counts[owner] = counts.get(owner, 0) + 1
    return counts


def register(reg: Registry) -> None:
    @reg.tool(
        title="Assets by owner",
        category=CATEGORY,
        sensitivity=Sensitivity.CONFIDENTIAL,
        read_only=True,
        idempotent=True,
        open_world=False,
        output_schema=output_schema_for(OwnerAssetsOut),
    )
    def assets_by_owner(
        ctx: Any,
        owner: Annotated[str, Field(min_length=1, description="Value of the 'owner' tag.")],
        limit: Limit = 50,
        cursor: Cursor = "",
        dataset: DatasetArg = "",
    ) -> dict:
        """Assets whose 'owner' tag equals OWNER, as compact briefs."""
        ds = ws_dataset(ctx, dataset)
        if owner not in _owners(ds):
            raise ReferenceNotFoundError(
                f"No asset is tagged owner={owner!r}.",
                data={"owners": sorted(_owners(ds))},
            )
        matches = [a for a in ds.assets if a.tags.get("owner") == owner]
        page, env = paginate(matches, limit, cursor, fingerprint(ds, owner=owner))
        ctx.link(f"cloudg://owners/{owner}", f"owner {owner}")
        return {"owner": owner, **env, "items": [asset_brief(ds, a) for a in page]}

    def complete_owner(ctx: Any, partial: str) -> list[str]:
        try:
            ds = ws_dataset(ctx)
        except Exception:
            return []
        return sorted(o for o in _owners(ds) if o.startswith(partial))

    @reg.resource_template(
        "cloudg://owners/{owner}",
        title="Owner",
        category=CATEGORY,
        sensitivity=Sensitivity.INTERNAL,
        completions={"owner": complete_owner},
    )
    def owner_resource(ctx: Any, owner: str) -> dict:
        """Asset count for one owner."""
        ds = ws_dataset(ctx)
        return {"owner": owner, "assets": _owners(ds).get(owner, 0)}

    @reg.prompt(
        title="Owner review",
        category="prompts",
        arguments=[PromptArgument("owner", "Owner tag value", required=True,
                                  completion=complete_owner)],
    )
    def owner_review(ctx: Any, owner: str) -> PromptResult:
        """Review everything one team owns."""
        text = (f"Call assets_by_owner(owner={owner!r}), then findings_for_asset on each "
                "asset with open findings, and summarise the team's exposure.")
        return PromptResult([PromptMessage("user", TextContent(text))], "Owner review")
```

The sync handlers run in worker threads, which is fine for in-memory work. Write the handler
`async` if it awaits I/O or must be cancellable on timeout.

`tests/mcp/test_catalog_owners.py`, using the fixtures from `tests/mcp/conftest.py`
(`workspace` is the sample estate loaded as dataset `sample`; `call` is bound to the `layer`
fixture, which this file overrides to add the new module):

```python
"""Tests for the ownership catalog module."""

from __future__ import annotations

import json

import pytest

from cloudg.mcp.catalog import default_registry, owners
from cloudg.mcp.layer import CloudGMCPLayer


@pytest.fixture
def layer(workspace):
    reg = default_registry()
    owners.register(reg)        # not needed once owners is in _modules()
    return CloudGMCPLayer(policy="open", workspace=workspace, registry=reg)


async def test_assets_by_owner(call):
    out = await call("assets_by_owner", owner="platform", limit=2)
    assert out["owner"] == "platform"
    assert out["returned"] == len(out["items"]) <= 2
    assert all(i["uri"].startswith("cloudg://assets/") for i in out["items"])


async def test_unknown_owner_is_a_tool_error(call):
    text = await call.error("assets_by_owner", owner="nobody")
    assert "No asset is tagged owner='nobody'" in text
    raw = await call.raw("assets_by_owner", owner="nobody")
    assert raw.meta["cloudg/error_code"] == -32602
    assert "platform" in raw.meta["cloudg/error_data"]["owners"]


async def test_resource_completion_and_prompt(layer):
    contents = await layer.read_resource("cloudg://owners/platform")
    assert json.loads(contents[0].text)["assets"] >= 1
    done = await layer.complete({"type": "ref/resource", "uri": "cloudg://owners/{owner}"},
                                {"name": "owner", "value": "pl"})
    assert done["values"] == ["platform"]
    prompt = await layer.get_prompt("owner_review", {"owner": "platform"})
    assert "assets_by_owner" in prompt.messages[0].content.text


async def test_strict_policy_pseudonymises(workspace):
    reg = default_registry()
    owners.register(reg)
    strict = CloudGMCPLayer(policy="strict", workspace=workspace, registry=reg)
    res = await strict.call_tool("assets_by_owner", {"owner": "platform", "limit": 1})
    assert not res.is_error
    assert "111111111111" not in json.dumps(res.structured["items"][0])
    assert "outputSchema" not in [t for t in strict.tools_wire()
                                  if t["name"] == "assets_by_owner"][0]
```

The `call` fixture: `await call(tool, **args)` returns the structured result and asserts
success; `call.raw(...)` returns the `ToolResult`; `call.error(...)` asserts an error and
returns its text. The last test is worth copying for any tool that returns identifiers: it
checks the tool under a pseudonymizing profile.

The run, from the repository root with the module and test in a scratch directory:

```text
$ PYTHONPATH=scratch/ext .venv/bin/python -m pytest -p tests.mcp.conftest scratch/ext/test_owners.py \
    -q -p no:cacheprovider -o asyncio_mode=auto
4 passed, 8 warnings in 1.02s
```

To check the catalog invariants as if the module were registered, a scratch pytest plugin
appended `owners` to `_modules()`, added `ownership` to `CATEGORIES` and `OWN_CATEGORIES`, and
added `"assets_by_owner": {"owner": "platform"}` to `OUTPUT_CALLS`. Before the `OUTPUT_CALLS`
entry, `test_structured_results_match_output_schemas` failed with
`AssertionError: {'assets_by_owner'}`; with it, `test_catalog_registry.py` gave
`221 passed, 4 warnings` (re-run after the latest catalog changes).

(The warnings are pydantic deprecation notices from elsewhere in cloudg.) Inside the repo the
`-p` and `-o` flags are unnecessary: `tests/mcp/conftest.py` and the pytest settings in
`pyproject.toml` apply automatically.

For a primitive that stays in your own deployment, the registry test does not apply. Build
the registry yourself (`reg = default_registry(); my_module.register(reg)`) and pass
`registry=reg` to the layer, or point the CLI at a factory with
`--registry my_module:build_registry`.

## 9. Writing a new adapter or transport

There are two ways in, depending on whether the target speaks MCP itself.

A framework that dispatches MCP methods to your code (another SDK, a gateway): follow
`lowlevel.py`. For each method it hands you, decide ownership, build a `ToolContext` with
`layer.context(principal, request_id=..., progress_callback=..., log_callback=...,
session=...)`, call the layer method, convert `to_wire()` output to the framework's types,
and map `MCPLayerError` to the framework's error type (`NotFoundError` to -32602, or -32002
for resources on handshake-era connections). Wrap the host's existing handlers instead of
replacing them, and merge list results. Forward change events with a `ChangeFanout`.
`export_definitions` already gives you per-method handlers if the framework is simple enough.

A raw transport (a socket, a message queue, a websocket): reuse the native protocol engine
and write only the framing. One `Session` per connection; feed it decoded messages; send back
what `handle` returns; pass a `send` coroutine for server-initiated notifications. This TCP
transport is complete and was run:

```python
"""A newline-delimited JSON-RPC transport over TCP for NativeMCPServer."""
import asyncio
import json

from cloudg.mcp import CloudGMCPLayer, Principal
from cloudg.mcp.native import NativeMCPServer
from cloudg.mcp.native.jsonrpc import PARSE_ERROR, dumps, error_response


async def serve_tcp(server: NativeMCPServer, host: str = "127.0.0.1", port: int = 0):
    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        lock = asyncio.Lock()

        async def send(message: dict) -> None:  # server-initiated notifications
            async with lock:
                writer.write((dumps(message) + "\n").encode())
                await writer.drain()

        session = server.create_session(transport="tcp", send=send,
                                        principal=Principal(id="tcp-client", roles={"default"}))
        try:
            while line := await reader.readline():
                try:
                    msg = json.loads(line)
                except ValueError:
                    await send(error_response(None, PARSE_ERROR, "Parse error"))
                    continue
                response = await session.handle(msg)
                if response is not None:
                    await send(response)
        finally:
            session.close()
            writer.close()

    return await asyncio.start_server(on_client, host, port)
```

Driving it with `initialize`, `notifications/initialized` and a `tools/call` of the test
registry's `echo` tool printed:

```text
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true},"resources":{"subscribe":true,"listChanged":true},
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\n  \"text\": \"hihi\"\n}"}],"isError":false,"structuredContent":{"text":"hihi"},"_meta":{"
```

This version handles one request at a time per connection, so `notifications/cancelled`
cannot reach a running request. `stdio.py` shows how to run requests as tasks (everything but
`initialize`, notifications and responses) while keeping writes serialized.

A checklist for any adapter or transport:

- Resolve the principal from transport facts with `resolve_principal(resolver, info)`; never
  from `clientInfo`.
- Never write protocol data and logs to the same stream.
- Keep progress monotonic per request.
- Hop to the event loop before touching sessions from change listeners.
- Do not cache list results across principals; on 2026 results keep `cacheScope: "private"`.
- Add a test module that runs the shared `_adapter_testkit.build_layer()` through the new
  path: definitions identical to `layer.tools_wire()`, a structured call, an error call,
  progress, a resource read, a completion, a prompt, a change notification.

## 10. Tests

### 10.1 Layout

| File | What it covers |
|---|---|
| `conftest.py` | Fixtures: `sample_dataset`, `sample_paths`, `workspace`, `layer` (policy `open`), `call` |
| `fixtures/sample_estate.py` | The synthetic AWS / Azure / GCP estate; `write_estate(root)` writes inventory and report files |
| `_adapter_testkit.py` | A small registry (echo, stats, slow, sleepy, fail, touch, linked, noisy, a resource, a template with completions, a prompt) and `build_layer()`, used by the adapter, native, middleware and CLI tests |
| `test_catalog_registry.py` | Catalog-wide invariants and wire validity |
| `test_catalog_regressions.py` | Regressions found by calling every tool during the tool-reference pass |
| `test_policy_regressions.py` | Privacy-layer regressions found by running the full catalog against the sample estate |
| `test_catalog_workspace.py`, `_inventory`, `_graph`, `_findings`, `_compliance`, `_ontology`, `_resources`, `_prompts`, `_export_live_meta` | The catalog modules; live tools with the engine monkeypatched |
| `test_state.py` | `Dataset` and `Workspace`: loading, lookup, caches, mutation, diff, path safety |
| `test_policy.py`, `test_transforms.py`, `test_privacy_tools.py` | Policy and transforms (see MCP_PRIVACY.md) |
| `test_middleware.py` | The five middleware classes |
| `test_native_protocol.py` | The protocol engine in memory, both eras |
| `test_native_stdio.py` | A real subprocess over stdio, raw and with the SDK client; `python -m cloudg.mcp` |
| `test_native_http.py` | Real localhost sockets with `urllib` and, when installed, the SDK client |
| `test_native_auth.py` | Token parsing and lookup |
| `test_adapters_sdk.py` | mcp 2.x (`MCPServer`, low-level, both eras) and mcp 1.x (`FastMCP`, low-level); each half skips on the other major version |
| `test_adapters_fastmcp.py` | fastmcp 2/3/4; skipped without fastmcp |
| `test_adapters_export.py` | `export_definitions`, detection, `build_server` |
| `test_adapters_serve.py` | `create_layer_from_options` and serving over HTTP with each flavor |
| `test_cli_mcp.py` | The click commands through `CliRunner` |

### 10.2 Running

```bash
.venv/bin/python -m pytest tests/mcp -q
.venv/bin/ruff check cloudg/mcp tests/mcp
```

On the branch with mcp 2.3.0 and no fastmcp, the suite gave
`823 passed, 6 skipped, 834 warnings in 89.51s`. The skips are the mcp 1.x and fastmcp
sections.

### 10.3 The framework matrix

The adapters are only proven against the frameworks they were run with. Build one throwaway
venv per target with `uv`, install cloudg editable plus the framework and pytest, and run the
adapter-facing tests from the repository root:

```bash
cd /path/to/cloudg

uv venv /tmp/venv-mcp1 --python 3.13
uv pip install --python /tmp/venv-mcp1/bin/python -e . "mcp<2" pytest pytest-asyncio

uv venv /tmp/venv-fastmcp4 --python 3.13
uv pip install --python /tmp/venv-fastmcp4/bin/python -e . "fastmcp>=4,<5" pytest pytest-asyncio

uv venv /tmp/venv-fastmcp3 --python 3.13
uv pip install --python /tmp/venv-fastmcp3/bin/python -e . "fastmcp>=3,<4" pytest pytest-asyncio

uv venv /tmp/venv-fastmcp2 --python 3.13
uv pip install --python /tmp/venv-fastmcp2/bin/python -e . "fastmcp>=2,<3" pytest pytest-asyncio

for v in /tmp/venv-mcp1 /tmp/venv-fastmcp4 /tmp/venv-fastmcp3 /tmp/venv-fastmcp2; do
  $v/bin/python -m pytest tests/mcp/test_native_*.py tests/mcp/test_adapters_*.py \
    tests/mcp/test_middleware.py tests/mcp/test_cli_mcp.py -q
done
```

What those environments contained and what they gave for this release:

| venv | Packages | Command | Result |
|---|---|---|---|
| mcp 1.x | mcp 1.30.0 | native, adapters, middleware, CLI tests | 98 passed, 28 skipped |
| fastmcp 4 | fastmcp 4.0.11, mcp 2.3.0 | `test_adapters_fastmcp.py test_adapters_sdk.py` | 20 passed, 2 skipped |
| fastmcp 3 | fastmcp 3.4.8, mcp 1.30.0 | same | 10 passed, 12 skipped, 2 warnings |
| fastmcp 2 | fastmcp 2.14.7, mcp 1.30.0 | same | 10 passed, 12 skipped |

The venvs used for those numbers were created with `uv venv` and an editable install as
above; the exact `uv pip install` lines are a reconstruction from their contents (editable
cloudg, the framework, pytest 9.1.1, pytest-asyncio 1.4.0).

When you touch an adapter, run the matrix for every framework that adapter serves, and
update the version table in MCP.md section 7.

## 11. Known quirks and open questions

Found while writing this guide, and still present after the fixes that followed it (each
re-checked by running it). The earlier list also had items about annotation hints for
`cloud_access` and `exec`, unprefixed names resolving in-process, unvalidated prefixes, the
`truncated_chars` count, completions bypassing middleware, cache hits skipping the policy, the
fastmcp and SDK flavors' Origin handling, the resource decorators' missing parameters, native
2026 header leniency, token-spec parsing, and two redaction false positives (`"SECRET"` asset
counts redacted under `standard`, Azure subscription ids labelled `aws_account_id` under
`strict`). Those are fixed and covered by tests.

1. `register_into(prefix=...)` (adapters/__init__.py 124-125) assigns `layer.prefix` on the
   shared layer. One layer therefore cannot be mounted under two prefixes, and this path skips
   the constructor's prefix validation: `register_into(layer, server, prefix="bad:")` was
   accepted, and the error only appeared when the tool list was rendered
   (`ValueError: Invalid exposed tool name 'bad:echo'`).
2. A completion that the policy denies or rate-limits raises out of `_completion_terminal`
   (layer.py 694), so the adapters answer with a JSON-RPC error (-31001 / -31029), while an
   unknown or hidden ref gets an empty completion. In a run with a one-per-minute limit on a
   template, the second `layer.complete(...)` raised
   `RateLimitedError -31029 "Rate limit exceeded for completion 'test://items/{item_id}' (1/minute); retry in 60.0s"`.
   Arguably fine (the spec asks for rate limiting), but clients may not expect errors from
   completions.
3. Tool and prompt wire dicts always contain `description`, empty or not (core.py 449, 589);
   the spec allows omitting it.
4. `cloudg mcp config --client claude-desktop --transport http --token-env VAR` still produces
   an `mcp-remote` entry with no `env` block (cli.py 513-519); whether `${VAR}` expands
   depends on the environment Claude Desktop gives `npx`. Not tested.
5. A two-field spec is read from the right, so `--auth-token abc:def` means token `abc` with
   role `def` (auth.py 149). That is the documented rule, but an operator with a colon in a
   token gets a silently different token, with no error to warn them.
6. `test_catalog_registry.py` (line 47) still requires `openWorldHint` false for every catalog
   tool without `cloud_access`, while the derivation in 3.5 now makes an `exec`-only tool
   open-world. No catalog tool has `exec` without `cloud_access` today, so the test passes;
   a future offline-scanner tool would trip it.
