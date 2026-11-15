use serde_json::json;

use super::{py, schema, ts};

fn defs() -> Vec<schema::Def> {
    schema::definitions(&json!({"components": {"schemas": {
        "Mode": {"description": "How.", "oneOf": [
            {"const": "a", "description": "First.", "type": "string"},
            {"enum": ["b", "c"], "type": "string"}]},
        "Thing": {"type": "object", "additionalProperties": false, "required": ["id", "kind"], "properties": {
            "id": {"type": "integer", "format": "int64"},
            "kind": {"$ref": "#/components/schemas/Mode"},
            "name": {"type": ["string", "null"], "description": "Optional name."},
            "from": {"type": "integer"},
            "tags": {"type": "object", "additionalProperties": {"type": "number"}},
            "pair": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "integer"}], "minItems": 2},
            "any": true,
            "items": {"type": "array", "items": {"anyOf": [{"$ref": "#/components/schemas/Mode"}, {"type": "null"}]}}}}
    }}}))
}

#[test]
fn typescript_output() {
    let out = ts::render(&defs());
    assert!(out.contains("export interface Thing {"), "{out}");
    assert!(out.contains("  id: number;"), "{out}");
    assert!(out.contains("  /** Optional name. */\n  name?: string | null;"), "{out}");
    assert!(out.contains("  tags?: { [key: string]: number };"), "{out}");
    assert!(out.contains("  pair?: [string, number];"), "{out}");
    assert!(out.contains("  any?: unknown;"), "{out}");
    assert!(out.contains("  items?: (Mode | null)[];"), "{out}");
    assert!(out.contains("  /** First. */\n  | \"a\"\n  | \"b\"\n  | \"c\";"), "{out}");
}

#[test]
fn python_output() {
    let out = py::render(&defs());
    assert!(out.contains("Mode = _t.Literal[\"a\", \"b\", \"c\"]"), "{out}");
    assert!(out.contains("_ThingRequired = TypedDict("), "{out}");
    assert!(out.contains("class Thing(_ThingRequired, _ThingOptional):"), "{out}");
    assert!(out.contains("\"name\": _t.Optional[str],"), "{out}");
    assert!(out.contains("\"pair\": _t.Tuple[str, int],"), "{out}");
}
