use anyhow::{Context, Result};
use securamem_firewall::engine::SemanticEngine;
use securamem_storage::Database;
use sqlx::Row;

#[derive(Debug)]
pub struct SearchResult {
    pub file_path: String,
    pub symbol_name: String,
    pub code_content: String,
    pub score: f32,
}

pub struct CodexSearch<'a> {
    db: &'a Database,
    engine: &'a SemanticEngine,
}

impl<'a> CodexSearch<'a> {
    pub fn new(db: &'a Database, engine: &'a SemanticEngine) -> Self {
        Self { db, engine }
    }

    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>> {
        // 1. Embed the query
        let query_embedding = self.engine.embed(query)?;

        // 2. Fetch all vectors (In-Memory Scan)
        // Note: For a codebase of <100k symbols, this is fast enough (<50ms)
        let rows = sqlx::query("SELECT file_path, symbol_name, code_content, embedding FROM semantic_index")
            .fetch_all(&self.db.pool)
            .await
            .context("Failed to fetch index")?;

        let mut results = Vec::with_capacity(rows.len());

        for row in rows {
            let file_path: String = row.get("file_path");
            let symbol_name: String = row.get("symbol_name");
            let code_content: String = row.get("code_content");
            let embedding_bytes: Vec<u8> = row.get("embedding");

            // Deserialize BLOB to Vec<f32>
            let embedding: &[f32] = bytemuck::cast_slice(&embedding_bytes);

            // 3. Compute Cosine Similarity
            let score = self.engine.cosine_similarity(&query_embedding, embedding)?;

            results.push(SearchResult {
                file_path,
                symbol_name,
                code_content,
                score,
            });
        }

        // 4. Sort and Limit
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);

        Ok(results)
    }
}
