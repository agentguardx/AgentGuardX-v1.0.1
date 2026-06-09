"""Base agent class for FinanceFlow — wires LangChain + Ollama + role tools.

DESIGN NOTE: FinanceFlow has NO awareness of AgentGuard-X. This base class
is a plain LangChain ReAct agent. AgentGuard-X attaches via callback hooks
during the integration phase without any modification here.
"""

from __future__ import annotations

import sys
from typing import Any

from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models import BaseLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import BaseTool
from langchain_ollama import OllamaLLM

from financeflow.config import (
    AGENT_MAX_ITERATIONS,
    AGENT_VERBOSE,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
)

# ReAct prompt template (local — no hub dependency for offline use)
REACT_TEMPLATE = """You are a financial services AI agent with the role: {role}.
Your capabilities are strictly limited to the tools provided.

Available tools:
{tools}

Tool names: {tool_names}

Instructions:
- Use ONLY the tools listed above.
- Be precise and factual. Do not fabricate data.
- If a task requires tools outside your role, state that clearly and stop.
- Format your thinking as: Thought → Action → Observation → ... → Final Answer.

Use this EXACT format for every step:

Thought: [your reasoning]
Action: [tool name, must be one of {tool_names}]
Action Input: [input to the tool]
Observation: [tool result]
... (repeat Thought/Action/Observation as needed)
Thought: I now have enough information to answer.
Final Answer: [your final response to the human]

Begin!

Task: {input}
{agent_scratchpad}"""


class FinanceFlowAgent:
    """Base class for all FinanceFlow agents.

    Subclasses set `role` and `tools` class attributes.
    AgentGuard-X attaches via `extra_callbacks` in the integration phase.
    """

    role: str = "base"
    tools: list[BaseTool] = []

    def __init__(self, extra_callbacks: list[BaseCallbackHandler] | None = None) -> None:
        self._llm: BaseLLM = OllamaLLM(
            base_url=OLLAMA_BASE_URL,
            model=OLLAMA_MODEL,
            timeout=OLLAMA_TIMEOUT,
        )
        self._extra_callbacks = extra_callbacks or []
        self._executor = self._build_executor()

    def _build_executor(self) -> AgentExecutor:
        prompt = PromptTemplate.from_template(REACT_TEMPLATE).partial(role=self.role)
        agent = create_react_agent(
            llm=self._llm,
            tools=self.tools,
            prompt=prompt,
        )
        return AgentExecutor(
            agent=agent,
            tools=self.tools,
            verbose=AGENT_VERBOSE,
            max_iterations=AGENT_MAX_ITERATIONS,
            handle_parsing_errors=True,
            callbacks=self._extra_callbacks or None,
        )

    def run(self, task: str, **kwargs: Any) -> str:
        """Execute a task. Returns the agent's final answer string."""
        try:
            result = self._executor.invoke(
                {"input": task},
                config={"callbacks": self._extra_callbacks} if self._extra_callbacks else {},
            )
            return result.get("output", str(result))
        except Exception as e:
            print(f"[{self.role}] Agent error: {e}", file=sys.stderr)
            return f"AGENT ERROR ({self.role}): {e}"
