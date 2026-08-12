import logging
import os

import httpx

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama.ollama.svc.cluster.local:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


class SummarizerAgent:
    """Summarizer Agent — returns a one-sentence summary of any text using Ollama."""

    async def invoke(self, text: str) -> str:
        prompt = f"Summarize the following text in one sentence:\n\n{text}"
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            response.raise_for_status()
            return response.json()["response"].strip()


class SummarizerAgentExecutor(AgentExecutor):
    """A2A AgentExecutor for the summarizer agent."""

    def __init__(self):
        self.agent = SummarizerAgent()

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        # Extract text from the first text part of the message
        text = ""
        if context.message and context.message.parts:
            for part in context.message.parts:
                root = getattr(part, "root", part)
                content = getattr(root, "text", None)
                if content:
                    text = content
                    break

        if not text:
            await event_queue.enqueue_event(
                new_agent_text_message("No text provided to summarize.")
            )
            return

        result = await self.agent.invoke(text)
        await event_queue.enqueue_event(new_agent_text_message(result))

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        raise Exception("cancel not supported")
