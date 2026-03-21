"""LangChain executor — builds chains, agents, and retrievers from config and dispatches."""
from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger("cordum.sidecar.langchain")


class LangChainExecutor:
    """Implements the sidecar Executor protocol for LangChain operations."""

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
            "chain.invoke": self._execute_chain,
            "agent.invoke": self._execute_agent,
            "retriever.invoke": self._execute_retriever,
        }

        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"unsupported action: {action}")

        result = handler(config=config, payload=payload, callback_url=callback_url)
        duration_ms = (time.monotonic() - start) * 1000

        logger.info(
            "langchain execution complete",
            extra={"event": "execution_complete", "action": action, "duration_ms": duration_ms},
        )

        return result

    def _execute_chain(
        self, *, config: dict[str, Any], payload: Any, callback_url: str
    ) -> dict[str, Any]:
        from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
        from langchain_core.output_parsers import StrOutputParser

        llm = _build_llm(config.get("llm_config", {}))

        chain_type = config.get("chain_type", "llm")
        prompt_template = config.get("prompt_template")

        if chain_type == "llm":
            if prompt_template:
                prompt = PromptTemplate.from_template(prompt_template)
                chain = prompt | llm | StrOutputParser()
            else:
                chain = llm | StrOutputParser()

            # Determine input
            chain_input: Any
            if isinstance(payload, str):
                chain_input = payload
            elif isinstance(payload, dict):
                chain_input = payload
            else:
                chain_input = str(payload) if payload is not None else ""

            output = chain.invoke(chain_input)

            return {"output": output}

        raise ValueError(f"unsupported chain_type: {chain_type}")

    def _execute_agent(
        self, *, config: dict[str, Any], payload: Any, callback_url: str
    ) -> dict[str, Any]:
        from langchain.agents import AgentExecutor, create_react_agent, create_openai_functions_agent, create_structured_chat_agent
        from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
        from .governance import wrap_tools_with_governance

        llm = _build_llm(config.get("llm_config", {}))
        agent_type = config.get("agent_type", "openai-functions")
        max_iterations = config.get("max_iterations", 10)
        early_stopping = config.get("early_stopping_method", "force")
        system_message = config.get("system_message", "You are a helpful assistant.")

        # Build tools with governance wrapping
        raw_tools = config.get("tools", [])
        tools = wrap_tools_with_governance(
            tool_configs=raw_tools,
            callback_url=callback_url,
        )

        # Build agent based on type
        if agent_type in ("openai-functions", "openai-tools"):
            prompt = ChatPromptTemplate.from_messages([
                ("system", system_message),
                MessagesPlaceholder(variable_name="chat_history", optional=True),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ])
            agent = create_openai_functions_agent(llm, tools, prompt)

        elif agent_type == "structured-chat":
            prompt = ChatPromptTemplate.from_messages([
                ("system", system_message),
                MessagesPlaceholder(variable_name="chat_history", optional=True),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ])
            agent = create_structured_chat_agent(llm, tools, prompt)

        elif agent_type == "react":
            from langchain_core.prompts import PromptTemplate as ReactPromptTemplate
            react_template = f"""{system_message}

You have access to the following tools:
{{tools}}

Use the following format:
Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{{tool_names}}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {{input}}
Thought: {{agent_scratchpad}}"""
            prompt = ReactPromptTemplate.from_template(react_template)
            agent = create_react_agent(llm, tools, prompt)

        else:
            raise ValueError(f"unsupported agent_type: {agent_type}")

        executor = AgentExecutor(
            agent=agent,
            tools=tools,
            max_iterations=max_iterations,
            early_stopping_method=early_stopping,
            return_intermediate_steps=True,
            handle_parsing_errors=True,
        )

        # Prepare input
        agent_input: dict[str, Any]
        if isinstance(payload, str):
            agent_input = {"input": payload}
        elif isinstance(payload, dict):
            agent_input = payload if "input" in payload else {"input": str(payload)}
        else:
            agent_input = {"input": str(payload) if payload is not None else ""}

        result = executor.invoke(agent_input)

        # Format intermediate steps with governance info
        intermediate_steps = []
        tool_calls = []
        for step in result.get("intermediate_steps", []):
            if len(step) >= 2:
                action_obj, observation = step[0], step[1]
                step_info: dict[str, Any] = {
                    "action": {
                        "tool": getattr(action_obj, "tool", str(action_obj)),
                        "tool_input": getattr(action_obj, "tool_input", ""),
                        "log": getattr(action_obj, "log", ""),
                    },
                    "observation": observation,
                }
                intermediate_steps.append(step_info)
                tool_calls.append({
                    "tool_name": getattr(action_obj, "tool", str(action_obj)),
                    "arguments": getattr(action_obj, "tool_input", {}),
                    "result": observation,
                })

        return {
            "output": result.get("output", ""),
            "intermediate_steps": intermediate_steps,
            "tool_calls": tool_calls,
        }

    def _execute_retriever(
        self, *, config: dict[str, Any], payload: Any, callback_url: str
    ) -> dict[str, Any]:
        query = ""
        k = 4
        if isinstance(payload, dict):
            query = payload.get("query", "")
            k = payload.get("k", 4)
        elif isinstance(payload, str):
            query = payload

        if not query:
            raise ValueError("query is required for retriever")

        retriever = _build_retriever(config, k=k)
        docs = retriever.invoke(query)

        documents = []
        for doc in docs:
            documents.append({
                "page_content": doc.page_content,
                "metadata": doc.metadata,
            })

        return {"output": documents, "documents": documents}


def _build_llm(llm_config: dict[str, Any]) -> Any:
    """Build a LangChain LLM/ChatModel from config."""
    provider = llm_config.get("provider", "openai")
    model = llm_config.get("model", "gpt-4o")
    temperature = llm_config.get("temperature", 0.0)
    max_tokens = llm_config.get("max_tokens")
    api_key_env = llm_config.get("api_key_env")

    kwargs: dict[str, Any] = {"model": model, "temperature": temperature}
    if max_tokens:
        kwargs["max_tokens"] = max_tokens

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        if api_key_env:
            kwargs["api_key"] = os.environ.get(api_key_env, "")
        return ChatOpenAI(**kwargs)

    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        if api_key_env:
            kwargs["api_key"] = os.environ.get(api_key_env, "")
        return ChatAnthropic(**kwargs)

    elif provider == "mistral":
        from langchain_mistralai import ChatMistralAI
        if api_key_env:
            kwargs["api_key"] = os.environ.get(api_key_env, "")
        return ChatMistralAI(**kwargs)

    elif provider == "cohere":
        from langchain_cohere import ChatCohere
        if api_key_env:
            kwargs["cohere_api_key"] = os.environ.get(api_key_env, "")
        return ChatCohere(**kwargs)

    else:
        raise ValueError(f"unsupported LLM provider: {provider}")


def _build_retriever(config: dict[str, Any], k: int = 4) -> Any:
    """Build a LangChain retriever from config."""
    store_config = config.get("store_config", {})
    provider = store_config.get("provider", "chroma")
    search_type = config.get("search_type", "similarity")
    search_kwargs = config.get("search_kwargs", {})
    search_kwargs.setdefault("k", k)

    embedding = _build_embedding(store_config.get("embedding_config", {}))

    if provider == "chroma":
        from langchain_chroma import Chroma
        collection = store_config.get("collection_name", "default")
        persist_dir = store_config.get("persist_directory", "./chroma_db")
        vectorstore = Chroma(
            collection_name=collection,
            embedding_function=embedding,
            persist_directory=persist_dir,
        )
    elif provider == "faiss":
        from langchain_community.vectorstores import FAISS
        index_path = store_config.get("index_path", "./faiss_index")
        vectorstore = FAISS.load_local(index_path, embedding, allow_dangerous_deserialization=True)
    else:
        raise ValueError(f"unsupported vector store provider: {provider}")

    return vectorstore.as_retriever(search_type=search_type, search_kwargs=search_kwargs)


def _build_embedding(embedding_config: dict[str, Any]) -> Any:
    """Build a LangChain embedding model from config."""
    provider = embedding_config.get("provider", "openai")
    model = embedding_config.get("model", "text-embedding-3-small")
    api_key_env = embedding_config.get("api_key_env")

    if provider == "openai":
        from langchain_openai import OpenAIEmbeddings
        kwargs: dict[str, Any] = {"model": model}
        if api_key_env:
            kwargs["api_key"] = os.environ.get(api_key_env, "")
        return OpenAIEmbeddings(**kwargs)

    elif provider == "huggingface":
        from langchain_huggingface import HuggingFaceEmbeddings
        return HuggingFaceEmbeddings(model_name=model)

    elif provider == "cohere":
        from langchain_cohere import CohereEmbeddings
        kwargs = {"model": model}
        if api_key_env:
            kwargs["cohere_api_key"] = os.environ.get(api_key_env, "")
        return CohereEmbeddings(**kwargs)

    else:
        raise ValueError(f"unsupported embedding provider: {provider}")
