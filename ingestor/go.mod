// Sentinel RAG log ingestor.
//
// Deliberately dependency-free: the entire hot path (scan -> sanitize -> parse
// -> enrich -> encode) uses only the Go standard library so the binary stays
// small, auditable, and free of supply-chain risk on a log-ingest boundary.
module github.com/TheRealArron/sentinel-rag/ingestor

go 1.22
