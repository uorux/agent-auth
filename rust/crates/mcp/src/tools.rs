//! The tools as this server lists them, and argument parsing. The table
//! itself (names, descriptions, parameters, schemas) is shared with the
//! broker's remote MCP endpoint: `agent_auth_wire::mcp_tools`.

use serde_json::{Map, Value, json};

pub use agent_auth_wire::mcp_tools::{
    DefaultValue, Param, SERVER_NAME, STDIO_INSTRUCTIONS as INSTRUCTIONS, TOOLS, ToolDef, Ty,
    input_schema, output_schema, tool as find, tool_names,
};

/// Every tool as `tools/list` lists it.
#[must_use]
pub fn rmcp_tools() -> Vec<rmcp::model::Tool> {
    TOOLS
        .iter()
        .map(|t| {
            let mut tool = rmcp::model::Tool::default();
            tool.name = t.name.into();
            tool.description = Some(t.description.into());
            tool.input_schema = std::sync::Arc::new(input_schema(t));
            tool.output_schema = Some(std::sync::Arc::new(output_schema(t)));
            tool
        })
        .collect()
}

/// A call's arguments, checked against the tool's parameters: present when
/// required, of their type (an integral float is an integer, any number a
/// float, as pydantic's lax mode), defaults filled in. Unknown arguments are
/// ignored, as pydantic did.
#[derive(Debug, Clone)]
pub struct Args(Map<String, Value>);

impl Args {
    pub fn parse(tool: &ToolDef, given: Option<&Map<String, Value>>) -> Result<Self, String> {
        let mut out = Map::new();
        let empty = Map::new();
        let given = given.unwrap_or(&empty);
        for p in tool.params {
            let value = match given.get(p.name) {
                Some(v) => v.clone(),
                None => match p.default.value() {
                    Some(d) => d,
                    None => return Err(format!("{}: Field required", p.name)),
                },
            };
            let value = if value.is_null() && (p.nullable || p.default == DefaultValue::Null) {
                Value::Null
            } else {
                check(p, value)?
            };
            out.insert(p.name.into(), value);
        }
        Ok(Args(out))
    }

    fn get(&self, name: &str) -> &Value {
        self.0.get(name).unwrap_or(&Value::Null)
    }

    /// A string argument (checked: present and a string unless nullable).
    #[must_use]
    pub fn str(&self, name: &str) -> &str {
        self.get(name).as_str().unwrap_or_default()
    }

    #[must_use]
    pub fn opt_str(&self, name: &str) -> Option<&str> {
        self.get(name).as_str()
    }

    #[must_use]
    pub fn num(&self, name: &str) -> f64 {
        self.get(name).as_f64().unwrap_or_default()
    }

    #[must_use]
    pub fn int(&self, name: &str) -> i64 {
        self.opt_int(name).unwrap_or_default()
    }

    #[must_use]
    pub fn opt_int(&self, name: &str) -> Option<i64> {
        self.get(name).as_i64()
    }

    #[must_use]
    pub fn bool(&self, name: &str) -> bool {
        self.get(name).as_bool().unwrap_or_default()
    }

    #[must_use]
    pub fn obj(&self, name: &str) -> Option<Map<String, Value>> {
        self.get(name).as_object().cloned()
    }

    /// A nullable list of strings: None when null or absent.
    #[must_use]
    pub fn opt_list(&self, name: &str) -> Option<Vec<String>> {
        self.get(name).as_array().map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
    }

    #[must_use]
    pub fn str_list(&self, name: &str) -> Vec<String> {
        self.get(name)
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn check(p: &Param, value: Value) -> Result<Value, String> {
    let bad = |what: &str| Err(format!("{}: Input should be {what}", p.name));
    match p.ty {
        Ty::Str if value.is_string() => Ok(value),
        Ty::Str => bad("a valid string"),
        Ty::Bool if value.is_boolean() => Ok(value),
        Ty::Bool => bad("a valid boolean"),
        Ty::Num if value.is_number() => Ok(value),
        Ty::Num => bad("a valid number"),
        Ty::Int => match &value {
            Value::Number(n) if n.is_i64() => Ok(value),
            Value::Number(n) => match n.as_f64() {
                // An integral float within i64 is that integer, as pydantic.
                Some(f) if f.fract() == 0.0 && f.abs() < 9.0e15 => {
                    // Exact: integral and well within i64.
                    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
                    let int = f as i64;
                    Ok(json!(int))
                }
                _ => bad("a valid integer"),
            },
            _ => bad("a valid integer"),
        },
        Ty::Obj if value.is_object() => Ok(value),
        Ty::Obj => bad("a valid dictionary"),
        Ty::StrMap => match &value {
            Value::Object(m) if m.values().all(Value::is_string) => Ok(value),
            _ => bad("a valid dictionary of strings"),
        },
        Ty::StrList => match &value {
            Value::Array(a) if a.iter().all(Value::is_string) => Ok(value),
            _ => bad("a valid list of strings"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thirty_five_tools() {
        assert_eq!(TOOLS.len(), 35);
        let mut names: Vec<_> = tool_names().collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 35);
    }

    #[test]
    fn arguments() {
        let tool = find("a2a_poll").unwrap();
        let args = Args::parse(
            tool,
            json!({"thread_id": "t", "after_seq": 3.0, "extra": 1}).as_object(),
        )
        .unwrap();
        assert_eq!(args.str("thread_id"), "t");
        assert_eq!(args.int("after_seq"), 3);
        assert!((args.num("wait") - 60.0).abs() < f64::EPSILON);
        assert_eq!(args.opt_str("session_key"), None);

        assert_eq!(
            Args::parse(tool, json!({}).as_object()).unwrap_err(),
            "thread_id: Field required"
        );
        assert_eq!(
            Args::parse(tool, json!({"thread_id": 1}).as_object()).unwrap_err(),
            "thread_id: Input should be a valid string"
        );
        assert!(
            Args::parse(
                tool,
                json!({"thread_id": "t", "after_seq": 1.5}).as_object()
            )
            .is_err()
        );
        assert!(Args::parse(tool, json!({"thread_id": "t", "wait": null}).as_object()).is_err());
        let run = find("host_run").unwrap();
        assert!(
            Args::parse(
                run,
                json!({"host": "h", "argv": ["a", 1], "justification": "j"}).as_object()
            )
            .is_err()
        );
        assert!(
            Args::parse(
                run,
                json!({"host": "h", "argv": [], "justification": "j", "env": {"A": 1}}).as_object()
            )
            .is_err()
        );
    }
}
