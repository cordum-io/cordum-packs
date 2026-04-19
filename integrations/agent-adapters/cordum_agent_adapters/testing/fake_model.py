"""Scripted FakeModel for integration tests.

Subclass of :class:`agents.models.Model` that returns a deterministic
sequence of tool-call / message items instead of calling a real LLM.
Shared across the three adapter integration tests so every framework
exercises the same governance scenario: first turn allowed, second
turn policy-denied, third turn final message.

The SDK's Model interface evolves across versions; this helper
best-effort targets openai-agents>=0.1 (``agents.models.Model`` with a
``get_response(...)`` coroutine). Tests that rely on this file use
:func:`pytest.importorskip` so a version mismatch simply skips rather
than crashing collection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional

try:
    # openai-agents >= 0.14 exposes the Model ABC at this path. Older
    # versions put it under agents.models.Model; the import-from-
    # interface form is the stable location the SDK's type stubs use.
    from agents.models.interface import Model  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional dep
    Model = object  # type: ignore[assignment]


@dataclass
class ScriptedTurn:
    """Single turn the FakeModel returns.

    ``tool_calls`` drives a tool-call-only turn; when empty the turn
    emits ``content`` as the final assistant message.
    """

    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    content: str = ""


class FakeModel(Model):  # type: ignore[misc, valid-type]
    """Deterministic model that replays a pre-scripted sequence of turns.

    Subclasses ``agents.models.interface.Model`` so ``Agent(model=model)``
    passes the SDK's isinstance check ("Agent model must be a string,
    Model, or None"). ``get_response`` pops the next turn on each call;
    ``stream_response`` is implemented as an empty async generator
    because the adapter's governed path uses ``Runner.run_streamed``
    which dispatches through ``get_response``, not ``stream_response``.

    The returned ModelResponse object is deliberately duck-typed
    instead of tied to a specific openai-agents internal shape — the
    SDK's own test doubles swap exact classes across releases, and we
    only care that ``ModelResponse.output`` looks like a list of items
    with ``.type`` and tool-call-shaped fields.
    """

    def __init__(self, turns: List[ScriptedTurn]) -> None:
        self._turns: Iterator[ScriptedTurn] = iter(turns)
        self.call_count = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ARG002
        self.call_count += 1
        try:
            turn = next(self._turns)
        except StopIteration:
            turn = ScriptedTurn(content="(exhausted)")
        return _ModelResponse(turn=turn, call_index=self.call_count)

    async def stream_response(  # type: ignore[override]
        self, *args: Any, **kwargs: Any
    ) -> AsyncIterator[Any]:
        """Emit scripted SSE-shaped events for Runner.run_streamed.

        Runner.run_streamed consumes:

        * ``ResponseOutputItemDoneEvent`` for each output item produced
          by the "model" (tool calls + assistant messages).
        * ``ResponseCompletedEvent`` once at the end carrying a
          ``Response`` object with the full output list.

        We synthesise both so the Runner's run loop treats the
        scripted turn as a complete model response and advances to
        tool dispatch (or termination on a final message).
        """
        from openai.types.responses import (
            Response,
            ResponseCompletedEvent,
            ResponseOutputItemDoneEvent,
        )

        self.call_count += 1
        try:
            turn = next(self._turns)
        except StopIteration:
            turn = ScriptedTurn(content="(exhausted)")

        output_items: List[Any] = []
        for idx, tc in enumerate(turn.tool_calls):
            output_items.append(
                _build_tool_call(
                    name=tc["name"],
                    arguments=tc.get("arguments", {}),
                    call_id=f"call-{self.call_count}-{idx}",
                )
            )
        if turn.content:
            output_items.append(_build_message(turn.content, self.call_count))

        seq = 0
        for item in output_items:
            yield ResponseOutputItemDoneEvent(
                item=item,
                output_index=seq,
                sequence_number=seq,
                type="response.output_item.done",
            )
            seq += 1

        response = Response(
            id=f"fake-{self.call_count}",
            created_at=0.0,
            model="fake-model",
            object="response",
            output=output_items,
            parallel_tool_calls=False,
            tool_choice="auto",
            tools=[],
            status="completed",
        )
        yield ResponseCompletedEvent(
            response=response,
            sequence_number=seq,
            type="response.completed",
        )


def _build_tool_call(name: str, arguments: Dict[str, Any], call_id: str) -> Any:
    """Return a ResponseFunctionToolCall the SDK's output parser accepts."""
    import json as _json

    from openai.types.responses import ResponseFunctionToolCall

    return ResponseFunctionToolCall(
        id=call_id,
        call_id=call_id,
        name=name,
        arguments=_json.dumps(arguments),
        type="function_call",
    )


def _build_message(text: str, call_index: int) -> Any:
    """Return a ResponseOutputMessage the SDK recognises as terminal."""
    from openai.types.responses import ResponseOutputMessage, ResponseOutputText

    return ResponseOutputMessage(
        id=f"msg-{call_index}",
        content=[ResponseOutputText(annotations=[], text=text, type="output_text")],
        role="assistant",
        status="completed",
        type="message",
    )


class _ModelResponse:
    """Duck-typed ModelResponse. The SDK's run loop treats this as
    an ``agents.models.ModelResponse`` — it reads ``.output``,
    ``.usage``, and ``.response_id``. We don't construct the real
    class to stay compatible across 0.1.x / 0.14.x.
    """

    def __init__(self, turn: ScriptedTurn, call_index: int) -> None:
        from agents.usage import Usage

        output: List[Any] = []
        for idx, tc in enumerate(turn.tool_calls):
            output.append(
                _build_tool_call(
                    name=tc["name"],
                    arguments=tc.get("arguments", {}),
                    call_id=f"call-{call_index}-{idx}",
                )
            )
        if turn.content:
            output.append(_build_message(turn.content, call_index))
        self.output = output
        self.usage = Usage()
        self.response_id = f"fake-{call_index}"


__all__ = ["FakeModel", "ScriptedTurn"]
