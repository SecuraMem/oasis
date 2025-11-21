use anyhow::{Context, Result};
use securamem_firewall::engine::SemanticEngine;
use securamem_storage::Database;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::path::Path;
use crate::parser::CodeParser;

pub struct CodexIndexer<'a> {
    db: &'a Database,
    engine: &'a SemanticEngine,
    parser: CodeParser,
}

impl<'a> CodexIndexer<'a> {
    pub fn new(db: &'a Database, engine: &'a SemanticEngine) -> Self {
        Self {
            db,
            engine,
            parser: CodeParser::new(),
        }
    }

    pub async fn index_file(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(path).context("Failed to read file")?;
        
        // 1. Calculate Hash
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hex::encode(hasher.finalize());

        // 2. Check if already indexed (Incremental Indexing)
        let path_str = path.to_string_lossy().to_string();
        let existing: Option<String> = sqlx::query("SELECT content_hash FROM semantic_index WHERE file_path = ?")
            .bind(&path_str)
            .fetch_optional(&self.db.pool)
            .await
            .context("Failed to query DB")?
            .map(|row| row.get("content_hash"));

        if let Some(stored_hash) = existing {
            if stored_hash == hash {
                tracing::debug!("Skipping unchanged file: {}", path_str);
                return Ok(());
            }
        }

        // 3. Parse Symbols
        let symbols = self.parser.parse_file(path, &content)?;
        if symbols.is_empty() {
            return Ok(());
        }

        tracing::info!("Indexing {} symbols from {}", symbols.len(), path_str);

        // 4. Clear old entries for this file
        sqlx::query("DELETE FROM semantic_index WHERE file_path = ?")
            .bind(&path_str)
            .execute(&self.db.pool)
            .await?;

        // 5. Generate Embeddings & Store
        for symbol in symbols {
            let embedding_vec = self.engine.embed(&symbol.content)?;
            
            // CRITICAL: Serialize Vec<f32> to Little Endian Bytes for BLOB storage
            let embedding_bytes: Vec<u8> = bytemuck::cast_slice(&embedding_vec).to_vec();

            sqlx::query(
                r#"
                INSERT INTO semantic_index (
                    file_path, symbol_name, symbol_type, code_content, content_hash, embedding
                )
                VALUES (?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&path_str)
            .bind(&symbol.name)
            .bind(&symbol.kind)
            .bind(&symbol.content)
            .bind(&hash)
            .bind(&embedding_bytes)
            .execute(&self.db.pool)
            .await?;
        }

        Ok(())
    }
}
