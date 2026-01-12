# Sentinel Transform Agent

Request and response transformation agent for [Sentinel](https://sentinel.raskell.io) reverse proxy. Apply URL rewrites, header manipulation, and JSON body transformations based on configurable matching rules.

## Features

- **URL Rewriting**: Path rewriting with regex capture groups, query parameter manipulation
- **Header Transformation**: Add, set, or remove headers on requests and responses
- **JSON Body Transformation**: Set, delete, rename, wrap, merge, copy, move operations
- **Flexible Matching**: Path patterns (exact/glob/regex), methods, headers, query params, JSON body
- **Variable Interpolation**: Use request/response properties, captures, JSON paths in transformations
- **Priority-Based Rules**: Higher priority rules evaluated first, first match wins
- **Debug Mode**: Optional headers showing which rule matched and timing

## Installation

```bash
cargo install sentinel-agent-transform
```

## Quick Start

Create a configuration file `transform.yaml`:

```yaml
version: "1"

rules:
  - name: "api-v1-to-v2"
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
    request:
      url:
        rewrite: "/api/v2/${1}"
```

Run the agent:

```bash
sentinel-agent-transform --config transform.yaml --socket /tmp/transform.sock
```

Configure Sentinel to use the agent:

```kdl
agents {
    agent "transform" type="custom" {
        unix-socket path="/tmp/transform.sock"
        events "request_headers" "request_body" "response_headers" "response_body"
    }
}
```

## Configuration

### Settings

```yaml
version: "1"

settings:
  max_body_size: 10485760    # Max body size to process (default: 10MB)
  template_dir: "/etc/sentinel/templates"
  cache_templates: true
  debug_headers: false       # Add X-Transform-Rule and X-Transform-Time headers
  timeout_ms: 100
```

### Rule Structure

```yaml
rules:
  - name: "rule-name"           # Unique identifier
    description: "..."          # Optional description
    enabled: true               # Enable/disable rule
    priority: 100               # Higher = evaluated first

    match:                      # Conditions (all must pass)
      path: { ... }
      methods: [...]
      headers: [...]
      query: [...]
      body: [...]
      response: { ... }

    request:                    # Request transformations
      url: { ... }
      headers: { ... }
      body: { ... }

    response:                   # Response transformations
      status: 200
      headers: { ... }
      body: { ... }
```

## Matchers

### Path Matching

```yaml
match:
  path:
    pattern: "/api/users"
    type: exact                 # exact, glob, or regex
```

```yaml
match:
  path:
    pattern: "/api/*/items"
    type: glob                  # Wildcards: * (segment), ** (multi-segment)
```

```yaml
match:
  path:
    pattern: "^/api/v(\\d+)/(?P<resource>.*)$"
    type: regex                 # Capture groups: ${1}, ${resource}
```

### Method Matching

```yaml
match:
  methods: ["GET", "POST", "PUT"]
```

### Header Matching

```yaml
match:
  headers:
    - name: "Content-Type"
      equals: "application/json"

    - name: "Authorization"
      contains: "Bearer"

    - name: "X-Api-Key"
      pattern: "^key-[a-z0-9]+$"

    - name: "X-Request-Id"
      present: true

    - name: "X-Debug"
      absent: true
```

### Query Parameter Matching

```yaml
match:
  query:
    - name: "api_key"
      present: true

    - name: "format"
      equals: "json"

    - name: "search"
      contains: "test"
```

### Body Matching (JSON)

```yaml
match:
  body:
    - path: "$.type"
      equals: "order"

    - path: "$.items"
      exists: true

    - path: "$.metadata.source"
      contains: "mobile"
```

### Response Matching

```yaml
match:
  response:
    status: [200, 201]
    content_type: "application/json"
```

## Transformers

### URL Transformation

```yaml
request:
  url:
    rewrite: "/api/v2/${1}"     # Path with captures
    preserve_query: true         # Keep original query params
    add_query:
      version: "2"
      trace: "${correlation_id}"
    remove_query:
      - "debug"
      - "internal"
```

### Header Transformation

```yaml
request:
  headers:
    add:                         # Add if not present
      - name: "X-Forwarded-By"
        value: "sentinel"
    set:                         # Always set (overwrite)
      - name: "User-Agent"
        value: "sentinel-transform/1.0"
    remove:
      - "X-Debug-Mode"
      - "X-Internal-Token"

response:
  headers:
    add:
      - name: "X-Served-By"
        value: "sentinel"
    remove:
      - "Server"
      - "X-Powered-By"
```

### JSON Body Transformation

```yaml
request:
  body:
    json:
      operations:
        # Set a value at path
        - set:
            path: "$.api_version"
            value: "v2"

        # Set with interpolation
        - set:
            path: "$.request_id"
            value: "${correlation_id}"

        # Delete paths
        - delete:
            - "$.debug"
            - "$.internal_flags"

        # Rename field
        - rename:
            from: "$.userId"
            to: "$.user_id"

        # Wrap in parent object
        - wrap:
            path: "$"
            key: "data"

        # Merge additional fields
        - merge:
            path: "$.metadata"
            with:
              processed: true
              timestamp: "${now}"

        # Copy value to another path
        - copy:
            from: "$.user.id"
            to: "$.audit.user_id"

        # Move value to another path
        - move:
            from: "$.temp_field"
            to: "$.permanent_field"
```

## Variable Interpolation

Variables can be used in URL rewrites, header values, and JSON values:

| Variable | Description |
|----------|-------------|
| `${request.method}` | HTTP method |
| `${request.path}` | Request path |
| `${request.query}` | Query string |
| `${request.header.X-Name}` | Request header value |
| `${request.query_param.name}` | Query parameter value |
| `${request.client_ip}` | Client IP address |
| `${response.status}` | Response status code |
| `${response.header.X-Name}` | Response header value |
| `${1}`, `${2}`, ... | Regex numbered capture groups |
| `${name}` | Regex named capture group |
| `${body.path.to.field}` | Request body JSON path |
| `${response_body.field}` | Response body JSON path |
| `${correlation_id}` | Unique request ID |
| `${now}` | Current timestamp (ISO 8601) |

## Examples

### API Version Migration

```yaml
rules:
  - name: "v1-to-v2-migration"
    priority: 100
    match:
      path:
        pattern: "^/api/v1/(.*)$"
        type: regex
    request:
      url:
        rewrite: "/api/v2/${1}"
        preserve_query: true
      headers:
        add:
          - name: "X-API-Version"
            value: "2"
```

### Add Authentication Headers

```yaml
rules:
  - name: "inject-internal-auth"
    match:
      path:
        pattern: "/internal/*"
        type: glob
    request:
      headers:
        add:
          - name: "X-Internal-Token"
            value: "secret-token"
          - name: "X-Request-Id"
            value: "${correlation_id}"
```

### Response Sanitization

```yaml
rules:
  - name: "sanitize-response"
    match:
      path:
        pattern: "/api/.*"
        type: regex
      response:
        content_type: "application/json"
    response:
      headers:
        remove:
          - "Server"
          - "X-Powered-By"
      body:
        json:
          operations:
            - delete:
                - "$.debug"
                - "$.internal_id"
                - "$.stack_trace"
```

### Request Normalization

```yaml
rules:
  - name: "normalize-user-payload"
    match:
      path:
        pattern: "/users"
        type: exact
      methods: ["POST", "PUT"]
    request:
      body:
        json:
          operations:
            - rename:
                from: "$.firstName"
                to: "$.first_name"
            - rename:
                from: "$.lastName"
                to: "$.last_name"
            - set:
                path: "$.normalized"
                value: true
```

### Conditional Response Wrapping

```yaml
rules:
  - name: "wrap-api-response"
    match:
      path:
        pattern: "/api/.*"
        type: regex
      response:
        status: [200]
    response:
      body:
        json:
          operations:
            - wrap:
                path: "$"
                key: "data"
            - merge:
                path: "$"
                with:
                  success: true
                  timestamp: "${now}"
```

## CLI Options

```
sentinel-agent-transform [OPTIONS]

Options:
  -s, --socket <PATH>        Unix socket path [default: /tmp/sentinel-transform.sock]
  -c, --config <FILE>        Configuration file (YAML or JSON)
  -t, --template-dir <DIR>   Template directory
  -l, --log-level <LEVEL>    Log level: trace, debug, info, warn, error [default: info]
      --json-logs            Output logs in JSON format
  -h, --help                 Print help
  -V, --version              Print version
```

## Debug Mode

Enable debug headers to see transformation info:

```yaml
settings:
  debug_headers: true
```

Response will include:
- `X-Transform-Rule: <rule-name>` - Which rule matched
- `X-Transform-Time: <ms>` - Processing time in milliseconds

## License

Apache-2.0
