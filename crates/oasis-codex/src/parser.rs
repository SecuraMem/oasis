use anyhow::{Context, Result};
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

/// Supported languages for the Codex
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageType {
    Rust,
    Python,
    JavaScript,
    TypeScript,
}

impl LanguageType {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "rs" => Some(Self::Rust),
            "py" => Some(Self::Python),
            "js" | "jsx" => Some(Self::JavaScript),
            "ts" | "tsx" => Some(Self::TypeScript),
            _ => None,
        }
    }
}

/// A symbol extracted from source code
#[derive(Debug, Clone)]
pub struct CodeSymbol {
    pub name: String,
    pub kind: String,
    pub content: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// Hardcoded Tree-Sitter Queries (Constraint: No .scm files)
const RUST_QUERY: &str = r#"
(function_item name: (identifier) @name) @def
(struct_item name: (type_identifier) @name) @def
(impl_item type: (type_identifier) @name) @def
"#;

const PYTHON_QUERY: &str = r#"
(function_definition name: (identifier) @name) @def
(class_definition name: (identifier) @name) @def
"#;

const JS_TS_QUERY: &str = r#"
(function_declaration name: (identifier) @name) @def
(class_declaration name: (identifier) @name) @def
(method_definition name: (property_identifier) @name) @def
"#;

pub struct CodeParser {
    // Parsers are cheap to create, but we could cache them if needed
}

impl CodeParser {
    pub fn new() -> Self {
        Self {}
    }

    pub fn parse_file(&self, path: &Path, content: &str) -> Result<Vec<CodeSymbol>> {
        let lang_type = LanguageType::from_path(path)
            .context("Unsupported file extension")?;

        let mut parser = Parser::new();
        let language = match lang_type {
            LanguageType::Rust => tree_sitter_rust::language(),
            LanguageType::Python => tree_sitter_python::language(),
            LanguageType::JavaScript => tree_sitter_javascript::language(),
            LanguageType::TypeScript => tree_sitter_typescript::language_typescript(),
        };

        parser.set_language(language).context("Failed to set language")?;

        let tree = parser.parse(content, None).context("Failed to parse code")?;
        let query_str = match lang_type {
            LanguageType::Rust => RUST_QUERY,
            LanguageType::Python => PYTHON_QUERY,
            LanguageType::JavaScript | LanguageType::TypeScript => JS_TS_QUERY,
        };

        let query = Query::new(language, query_str).context("Failed to compile query")?;
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

        let mut symbols = Vec::new();
        let def_idx = query.capture_index_for_name("def").unwrap();
        let name_idx = query.capture_index_for_name("name").unwrap();

        for m in matches {
            let mut def_node = None;
            let mut name_node = None;

            for capture in m.captures {
                if capture.index == def_idx {
                    def_node = Some(capture.node);
                } else if capture.index == name_idx {
                    name_node = Some(capture.node);
                }
            }

            if let (Some(def), Some(name)) = (def_node, name_node) {
                let name_text = name.utf8_text(content.as_bytes())?.to_string();
                let content_text = def.utf8_text(content.as_bytes())?.to_string();
                let kind = def.kind().to_string();
                
                symbols.push(CodeSymbol {
                    name: name_text,
                    kind,
                    content: content_text,
                    start_line: def.start_position().row + 1,
                    end_line: def.end_position().row + 1,
                });
            }
        }

        Ok(symbols)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_parser() {
        let code = r#"
            fn hello() { println!("world"); }
            struct Foo { x: i32 }
            impl Foo {}
        "#;
        let parser = CodeParser::new();
        let path = Path::new("test.rs");
        let symbols = parser.parse_file(path, code).expect("Failed to parse");
        
        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "hello");
        assert_eq!(symbols[0].kind, "function_item");
        assert_eq!(symbols[1].name, "Foo");
        assert_eq!(symbols[1].kind, "struct_item");
        assert_eq!(symbols[2].name, "Foo");
        assert_eq!(symbols[2].kind, "impl_item");
    }

    #[test]
    fn test_python_parser() {
        let code = r#"
def hello():
    print("world")

class Foo:
    pass
"#;
        let parser = CodeParser::new();
        let path = Path::new("test.py");
        let symbols = parser.parse_file(path, code).expect("Failed to parse");
        
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "hello");
        assert_eq!(symbols[0].kind, "function_definition");
        assert_eq!(symbols[1].name, "Foo");
        assert_eq!(symbols[1].kind, "class_definition");
    }
}
