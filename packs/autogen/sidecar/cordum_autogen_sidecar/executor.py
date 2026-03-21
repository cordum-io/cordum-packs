"""AutoGen executor — group chat, single agent, and sandboxed code execution."""
from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger("cordum.sidecar.autogen")


class AutoGenExecutor:
    """Implements the sidecar Executor protocol for AutoGen operations."""

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
            "groupchat": self._execute_groupchat,
            "agent": self._execute_agent,
            "code": self._execute_code,
        }

        handler = handlers.get(action)
        if handler is None:
            raise ValueError(f"unsupported action: {action}")

        result = handler(config=config, payload=payload, callback_url=callback_url)
        duration_ms = (time.monotonic() - start) * 1000
        logger.info("autogen execution complete", extra={"action": action, "duration_ms": duration_ms})
        return result

    def _execute_groupchat(
        self, *, config: dict[str, Any], payload: Any, callback_url: str
    ) -> dict[str, Any]:
        agents_config = config.get("agents", [])
        if not agents_config:
            raise ValueError("agents array is required for group chat")

        message = payload if isinstance(payload, str) else config.get("message", "")
        if not message:
            raise ValueError("message is required")

        max_rounds = config.get("max_rounds", 10)
        speaker_selection = config.get("speaker_selection", "auto")

        from autogen import AssistantAgent, UserProxyAgent, GroupChat, GroupChatManager

        agents = []
        for agent_cfg in agents_config:
            name = agent_cfg.get("name", "assistant")
            system_message = agent_cfg.get("system_message", "You are a helpful assistant.")
            llm_config = _build_llm_config(agent_cfg.get("llm_config", {}))

            human_input_mode = agent_cfg.get("human_input_mode", "NEVER")
            code_exec = agent_cfg.get("code_execution_config", False)

            if code_exec:
                agent = UserProxyAgent(
                    name=name,
                    system_message=system_message,
                    human_input_mode=human_input_mode,
                    code_execution_config=_build_code_exec_config(code_exec),
                )
            else:
                agent = AssistantAgent(
                    name=name,
                    system_message=system_message,
                    llm_config=llm_config,
                    human_input_mode=human_input_mode,
                )

            # Register governed tools if callback_url provided
            if callback_url and agent_cfg.get("tools"):
                _register_governed_tools(agent, agent_cfg["tools"], callback_url)

            agents.append(agent)

        groupchat = GroupChat(
            agents=agents,
            messages=[],
            max_round=max_rounds,
            speaker_selection_method=speaker_selection,
        )

        manager_llm = _build_llm_config(config.get("manager_llm_config") or agents_config[0].get("llm_config", {}))
        manager = GroupChatManager(groupchat=groupchat, llm_config=manager_llm)

        # Initiate chat from first agent
        initiator = agents[0]
        initiator.initiate_chat(manager, message=message)

        # Collect results
        chat_history = []
        for msg in groupchat.messages:
            chat_history.append({
                "name": msg.get("name", ""),
                "role": msg.get("role", ""),
                "content": msg.get("content", ""),
            })

        summary = chat_history[-1]["content"] if chat_history else ""

        return {
            "summary": summary,
            "chat_history": chat_history,
            "agent_transitions": len(chat_history),
        }

    def _execute_agent(
        self, *, config: dict[str, Any], payload: Any, callback_url: str
    ) -> dict[str, Any]:
        agent_config = config if "name" in config else config.get("agent_config", config)
        name = agent_config.get("name", "assistant")
        if not name:
            raise ValueError("agent name is required")

        message = payload if isinstance(payload, str) else config.get("message", "")
        if not message:
            raise ValueError("message is required")

        from autogen import AssistantAgent, UserProxyAgent

        llm_config = _build_llm_config(agent_config.get("llm_config", {}))

        assistant = AssistantAgent(
            name=name,
            system_message=agent_config.get("system_message", "You are a helpful assistant."),
            llm_config=llm_config,
            human_input_mode="NEVER",
        )

        if callback_url and agent_config.get("tools"):
            _register_governed_tools(assistant, agent_config["tools"], callback_url)

        user_proxy = UserProxyAgent(
            name="user_proxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

        user_proxy.initiate_chat(assistant, message=message)

        chat_history = []
        for msg in user_proxy.chat_messages.get(assistant, []):
            chat_history.append({
                "name": msg.get("name", ""),
                "role": msg.get("role", ""),
                "content": msg.get("content", ""),
            })

        summary = chat_history[-1]["content"] if chat_history else ""

        return {"summary": summary, "chat_history": chat_history}

    def _execute_code(
        self, *, config: dict[str, Any], payload: Any, callback_url: str
    ) -> dict[str, Any]:
        code = payload if isinstance(payload, str) else config.get("code", "")
        if not code:
            raise ValueError("code is required")

        language = config.get("language", "python")
        timeout = config.get("timeout", int(os.getenv("CORDUM_AUTOGEN_CODE_TIMEOUT", "30")))
        execution_mode = os.getenv("CORDUM_AUTOGEN_CODE_EXECUTION", "docker")

        if execution_mode == "disabled":
            raise ValueError("code execution is disabled by configuration")

        if execution_mode == "docker":
            return _execute_code_docker(code, language, config, timeout)
        else:
            raise ValueError(f"unsupported code execution mode: {execution_mode}. Only 'docker' is allowed.")


def _execute_code_docker(code: str, language: str, config: dict[str, Any], timeout: int) -> dict[str, Any]:
    """Execute code in a Docker sandbox."""
    docker_image = config.get("docker_image", os.getenv("CORDUM_AUTOGEN_DOCKER_IMAGE", "python:3.12-slim"))
    work_dir = config.get("work_dir", "/tmp/autogen_code")

    try:
        from autogen.coding import DockerCommandLineCodeExecutor
    except ImportError:
        try:
            from autogen.code_utils import execute_code
            result = execute_code(code, lang=language, timeout=timeout, use_docker=docker_image, work_dir=work_dir)
            return {
                "code_output": {
                    "exit_code": result[0],
                    "stdout": result[1] if len(result) > 1 else "",
                    "stderr": "",
                },
            }
        except ImportError:
            raise ValueError("Docker code execution requires autogen with Docker support installed")

    executor = DockerCommandLineCodeExecutor(
        image=docker_image,
        timeout=timeout,
        work_dir=work_dir,
    )

    from autogen.coding import CodeBlock
    code_block = CodeBlock(code=code, language=language)

    result = executor.execute_code_blocks([code_block])

    return {
        "code_output": {
            "exit_code": result.exit_code,
            "stdout": result.output,
            "stderr": "",
        },
    }


def _build_llm_config(llm_config: dict[str, Any]) -> dict[str, Any]:
    """Build AutoGen LLM config from our config format."""
    model = llm_config.get("model", "gpt-4o")
    api_key_env = llm_config.get("api_key_env", "OPENAI_API_KEY")
    api_key = os.environ.get(api_key_env, "")

    config_list = [{"model": model, "api_key": api_key}]

    result: dict[str, Any] = {"config_list": config_list}
    if "temperature" in llm_config:
        result["temperature"] = llm_config["temperature"]

    return result


def _build_code_exec_config(config: Any) -> dict[str, Any] | bool:
    """Build code execution config."""
    if isinstance(config, bool):
        return config
    if isinstance(config, dict):
        return {
            "work_dir": config.get("work_dir", "/tmp/autogen_code"),
            "use_docker": config.get("docker_image", os.getenv("CORDUM_AUTOGEN_DOCKER_IMAGE", "python:3.12-slim")),
            "timeout": config.get("timeout", int(os.getenv("CORDUM_AUTOGEN_CODE_TIMEOUT", "30"))),
        }
    return False


def _register_governed_tools(agent: Any, tools: list[dict[str, Any]], callback_url: str) -> None:
    """Register governed tools on an agent via the callback server."""
    from governance import GovernedAutoGenFunction

    for tool_cfg in tools:
        name = tool_cfg.get("name", "")
        if not name:
            continue

        governed_func = GovernedAutoGenFunction(
            name=name,
            callback_url=callback_url,
            description=tool_cfg.get("description", ""),
            parameter_schema=tool_cfg.get("parameters"),
        )

        agent.register_function(
            function_map={name: governed_func}
        )
        logger.info("registered governed tool: %s", name)
