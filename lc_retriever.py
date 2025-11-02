import os
from typing import List, Dict, Optional
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

# Production settings
MAX_K = int(os.getenv("RETRIEVER_MAX_K", "3"))  # Reduced for token efficiency
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "600"))  # Smaller chunks for better relevance
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "50"))

# Optional HuggingFace embeddings fallback
USE_HF_EMBEDDINGS = os.getenv("USE_HF_EMBEDDINGS", "false").lower() == "true"


def _chunk_text(text: str, chunk_size: int = None, overlap: int = None):
    if not text:
        return []
    chunk_size = chunk_size or CHUNK_SIZE
    overlap = overlap or CHUNK_OVERLAP
    
    chunks = []
    start = 0
    length = len(text)
    while start < length:
        end = start + chunk_size
        chunks.append(text[start:end])
        start = max(end - overlap, end)
    return chunks

def _get_embeddings():
    """Get embeddings model with fallback options."""
    if USE_HF_EMBEDDINGS:
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
            return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        except ImportError:
            pass
    
    try:
        return OpenAIEmbeddings()
    except Exception:
        # Final fallback - use a simple embedding stub
        class SimpleEmbeddings:
            def embed_documents(self, texts):
                return [[0.1] * 384 for _ in texts]
            def embed_query(self, text):
                return [0.1] * 384
        return SimpleEmbeddings()


def build_inmemory_kb(cve_docs: List[Dict]) -> Optional[object]:
    """Build knowledge base with token optimization and error handling."""
    texts = []
    metadatas = []
    
    for j in cve_docs:
        for it in j.get("vulnerabilities", []):
            cve = it.get("cve", {})
            cve_id = cve.get("id", "")
            desc = " ".join(d.get("value", "") for d in cve.get("descriptions", []))
            
            metrics = cve.get("metrics", {})
            sev = ""
            for k in metrics:
                arr = metrics[k]
                if arr and "cvssData" in arr[0]:
                    cv = arr[0]["cvssData"]
                    sev = f"CVSS {cv.get('version','')} {cv.get('baseSeverity','')} {cv.get('baseScore','')}"
                    break
            
            # Token-optimized text construction
            text = f"{cve_id} {sev}\n{desc}".strip()
            if not text or len(text) < 20:  # Skip very short entries
                continue
                
            # Use production chunk settings
            chunks = _chunk_text(text)
            for c in chunks:
                if len(c.strip()) > 30:  # Skip tiny chunks
                    texts.append(c)
                    metadatas.append({"id": cve_id, "severity": sev})

    if not texts:
        return None

    try:
        embeddings = _get_embeddings()
        vs = FAISS.from_texts(texts, embeddings, metadatas=metadatas)
        return vs.as_retriever(k=MAX_K)
    except Exception as e:
        print(f"Warning: Could not build vector store: {e}")
        return None


def format_retrieval_snippets(snips) -> str:
    """Format snippets with token optimization."""
    if not snips:
        return ""
    
    # Token-optimized formatting
    formatted = []
    char_count = 0
    max_chars = 1200  # Token budget
    
    for d in snips[:MAX_K]:
        cve_id = d.metadata.get('id', '')
        severity = d.metadata.get('severity', '')
        content = d.page_content[:600]  # Reduced content length
        
        snippet = f"[{cve_id}]"
        if severity:
            snippet += f" {severity}"
        snippet += f" {content}"
        
        if char_count + len(snippet) > max_chars:
            break
            
        formatted.append(snippet)
        char_count += len(snippet)
    
    return "\n\n".join(formatted)