# Overwatch Query Language (OQL)

OQL is a domain-specific language designed for expressing complex security vulnerability patterns as flow queries through an application's Data Flow Graph (DFG).

## Core Syntax

A basic OQL query follows this structure:

```oql
FIND path 
WHERE source -> NOT sanitized -> sink
```

### Components

#### 1. `FIND` Statement
Defines what the query is looking for. Currently, `path` is the primary target, representing a tainted data flow from a source to a sink.

#### 2. `WHERE` Clause
Specifies the constraints on the flow.

*   **`source(...)`**: Defines the origin of untrusted data.
*   **`sink(...)`**: Defines the dangerous operation where data ends up.
*   **`sanitized(...)`**: Defines functions or nodes that clean the data, breaking the taint flow.
*   **`->` (Flow Operator)**: Connects nodes in the data flow path.

### Attributes
Node selectors (source, sink, sanitizer) can be filtered by attributes:

| Attribute | Description | Example |
| :--- | :--- | :--- |
| `name` | The identifier name (regex supported) | `name="os.exec.*"` |
| `kind` | The AST node type | `kind="function_call"` |
| `lang` | The programming language | `lang="go"` |

### Logical Operators
*   **`NOT` / `!`**: Negates a condition (e.g., `NOT sanitized`).
*   **`AND` / `&&`**: Combines multiple constraints.

---

## Examples

### Command Injection (Python)
```oql
FIND path 
WHERE 
  source(name="request.args.get") 
  -> NOT sanitized(name="shlex.quote") 
  -> sink(name="os.system")
  AND lang="python"
```

### SQL Injection (Go)
```oql
FIND path 
WHERE 
  source(kind="parameter") 
  -> sink(name="db.Query")
  AND lang="go"
```

---

## Formal Grammar (EBNF-ish)

```ebnf
query        = "FIND" target "WHERE" expression [ language_gate ]
target       = "path" | "node"
expression   = flow_expr | bool_expr
flow_expr    = selector { "->" selector }
selector     = [ "NOT" ] ( "source" | "sink" | "sanitized" ) [ "(" attributes ")" ]
attributes   = attribute { "," attribute }
attribute    = identifier "=" string
language_gate = "AND" "lang" "=" string
identifier   = [a-zA-Z_][a-zA-Z0-9_]*
string       = "\"" { any_character } "\""
```

## Advanced Patterns

### 1. Multi-Step Sanitization
OQL supports multiple sanitizers in a single path.
```oql
FIND path 
WHERE source(kind="parameter") 
  -> NOT sanitized(name="strip_tags") 
  -> NOT sanitized(name="escape_sql") 
  -> sink(name="db.execute")
```

### 2. Node Selection by AST Kind
Instead of just names, you can target specific AST node types.
```oql
FIND path 
WHERE source(kind="parameter") 
  -> sink(kind="shell_command") 
  AND lang="go"
```

---

## Integration with Taint Engine

The OQL compiler generates a `Query` object that the Taint Engine uses to perform a breadth-first search (BFS) or depth-first search (DFS) on the Data Flow Graph.

1.  **Seed Selection**: The engine identifies all AST nodes matching the `source(...)` selectors.
2.  **Propagation**: For each source, it follows edges in the DFG (assignments, function calls, returns).
3.  **Filtering**: If a node matches a `NOT sanitized(...)` constraint, the flow is considered "cleaned" and propagation stops for that branch.
4.  **Sinking**: If a node matches a `sink(...)` selector, a vulnerability finding is recorded.
