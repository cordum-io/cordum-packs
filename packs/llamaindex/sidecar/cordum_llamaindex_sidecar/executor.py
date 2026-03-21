"""LlamaIndex executor — handles query, retrieve, index, and ingest actions."""
from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger("cordum.sidecar.llamaindex")


class LlamaIndexExecutor:
    """Implements the sidecar Executor protocol for LlamaIndex operations."""

    def execute(
        self,
        *,
        action: str,
        config: dict[str, Any],
        payload: Any,
        callback_url: str,
    ) -> Any:
        start = time.monotonic()

        handlers = {
            "query": self._execute_query,
            "retrieve": self._execute_retrieve,
            "index": self._execute_index,
            "ingest": self._execute_ingest,
        }

        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"unsupported action: {action}")

        result = handler(config=config, payload=payload)
        duration_ms = (time.monotonic() - start) * 1000
        logger.info("llamaindex execution complete", extra={"action": action, "duration_ms": duration_ms})
        return result

    def _execute_query(self, *, config: dict[str, Any], payload: Any) -> dict[str, Any]:
        query = ""
        similarity_top_k = 5
        response_mode_str = "compact"

        if isinstance(payload, dict):
            query = payload.get("query", "")
            similarity_top_k = payload.get("similarity_top_k", 5)
            response_mode_str = payload.get("response_mode", "compact")
        elif isinstance(payload, str):
            query = payload

        if not query:
            raise ValueError("query is required")

        from llama_index.core import VectorStoreIndex, Settings
        from llama_index.core.response_synthesizers import ResponseMode

        _configure_llm(config.get("llm_config") or payload.get("llm_config", {}))
        index = _build_index(config.get("index_config") or config)

        response_mode = ResponseMode(response_mode_str)
        query_engine = index.as_query_engine(
            similarity_top_k=similarity_top_k,
            response_mode=response_mode,
        )

        response = query_engine.query(query)

        source_nodes = []
        for node in getattr(response, "source_nodes", []):
            source_nodes.append({
                "text": node.get_content(),
                "score": getattr(node, "score", None),
                "metadata": node.metadata,
                "node_id": node.node_id,
            })

        return {
            "response": str(response),
            "source_nodes": source_nodes,
        }

    def _execute_retrieve(self, *, config: dict[str, Any], payload: Any) -> dict[str, Any]:
        query = ""
        similarity_top_k = 5

        if isinstance(payload, dict):
            query = payload.get("query", "")
            similarity_top_k = payload.get("similarity_top_k", 5)
        elif isinstance(payload, str):
            query = payload

        if not query:
            raise ValueError("query is required")

        index = _build_index(config.get("index_config") or config)
        retriever = index.as_retriever(similarity_top_k=similarity_top_k)
        nodes = retriever.retrieve(query)

        source_nodes = []
        for node in nodes:
            source_nodes.append({
                "text": node.get_content(),
                "score": getattr(node, "score", None),
                "metadata": node.metadata,
                "node_id": node.node_id,
            })

        return {"source_nodes": source_nodes}

    def _execute_index(self, *, config: dict[str, Any], payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object with action and documents")

        action = payload.get("action", "create")
        documents_data = payload.get("documents", [])

        if action not in ("create", "update", "delete"):
            raise ValueError(f"unsupported index action: {action}")

        if action == "delete":
            raise ValueError("index deletion requires index_id and backend-specific cleanup")

        if action == "create":
            valid_docs = [d for d in documents_data if isinstance(d, dict) and "text" in d]
            if not valid_docs:
                raise ValueError("documents are required for index creation")

            from llama_index.core import Document, VectorStoreIndex

            documents = [
                Document(text=d["text"], metadata=d.get("metadata", {}))
                for d in valid_docs
            ]

            _configure_llm(config.get("llm_config", {}))
            index = VectorStoreIndex.from_documents(documents)

            storage_dir = config.get("store_config", {}).get("persist_dir", "./llamaindex_storage")
            index.storage_context.persist(persist_dir=storage_dir)

            return {
                "index_id": str(id(index)),
                "documents_ingested": len(documents),
                "persist_dir": storage_dir,
            }

        else:
            raise ValueError(f"unsupported index action: {action}")

    def _execute_ingest(self, *, config: dict[str, Any], payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object with source")

        source = payload.get("source", {})
        source_type = source.get("type", "text")

        if source_type not in ("text", "file", "directory", "s3"):
            raise ValueError(f"unsupported source type: {source_type}")

        chunking = payload.get("chunking", {})
        chunk_size = chunking.get("chunk_size", 1024)
        chunk_overlap = chunking.get("chunk_overlap", 200)

        # Pre-validate before importing llama_index
        if source_type == "text":
            texts = source.get("texts", [])
            if not texts:
                raise ValueError("no documents to ingest")

        from llama_index.core import Document, VectorStoreIndex
        from llama_index.core.node_parser import SentenceSplitter

        documents = []

        if source_type == "text":
            texts = source.get("texts", [])
            for text in texts:
                documents.append(Document(text=text))

        elif source_type == "file":
            from llama_index.core import SimpleDirectoryReader
            path = source.get("path", "")
            if not path:
                raise ValueError("path is required for file source")
            reader = SimpleDirectoryReader(input_files=[path])
            documents = reader.load_data()

        elif source_type == "directory":
            from llama_index.core import SimpleDirectoryReader
            path = source.get("path", "")
            if not path:
                raise ValueError("path is required for directory source")
            reader = SimpleDirectoryReader(input_dir=path)
            documents = reader.load_data()

        if not documents:
            raise ValueError("no documents to ingest")

        _configure_llm(config.get("llm_config", {}))
        splitter = SentenceSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        index = VectorStoreIndex.from_documents(documents, transformations=[splitter])

        storage_dir = (config.get("index_config") or config).get("store_config", {}).get("persist_dir", "./llamaindex_storage")
        index.storage_context.persist(persist_dir=storage_dir)

        return {
            "documents_ingested": len(documents),
            "persist_dir": storage_dir,
        }


def _configure_llm(llm_config: dict[str, Any]) -> None:
    """Configure the global LLM settings."""
    from llama_index.core import Settings

    provider = llm_config.get("provider", "openai")
    model = llm_config.get("model", "gpt-4o-mini")
    temperature = llm_config.get("temperature", 0.0)
    api_key_env = llm_config.get("api_key_env")

    if provider == "openai":
        from llama_index.llms.openai import OpenAI
        kwargs: dict[str, Any] = {"model": model, "temperature": temperature}
        if api_key_env:
            kwargs["api_key"] = os.environ.get(api_key_env, "")
        Settings.llm = OpenAI(**kwargs)

    elif provider == "anthropic":
        from llama_index.llms.anthropic import Anthropic
        kwargs = {"model": model, "temperature": temperature}
        if api_key_env:
            kwargs["api_key"] = os.environ.get(api_key_env, "")
        Settings.llm = Anthropic(**kwargs)


def _build_index(index_config: dict[str, Any]) -> Any:
    """Build or load a LlamaIndex index from config."""
    from llama_index.core import StorageContext, load_index_from_storage

    store_config = index_config.get("store_config", {})
    backend = store_config.get("backend", "local")
    persist_dir = store_config.get("persist_dir", "./llamaindex_storage")

    if backend == "local":
        storage_context = StorageContext.from_defaults(persist_dir=persist_dir)
        return load_index_from_storage(storage_context)

    elif backend == "chroma":
        import chromadb
        from llama_index.vector_stores.chroma import ChromaVectorStore
        from llama_index.core import VectorStoreIndex

        collection_name = store_config.get("collection_name", "default")
        chroma_client = chromadb.PersistentClient(path=persist_dir)
        collection = chroma_client.get_or_create_collection(collection_name)
        vector_store = ChromaVectorStore(chroma_collection=collection)
        return VectorStoreIndex.from_vector_store(vector_store)

    else:
        raise ValueError(f"unsupported vector store backend: {backend}")
