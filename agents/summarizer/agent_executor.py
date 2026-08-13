import logging
import os

import httpx

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import Part
from a2a.types.a2a_pb2 import Task, TaskState, TaskStatus

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
        task_id = context.task_id
        context_id = context.context_id
        if not task_id or not context_id:
            raise ValueError("task_id and context_id are required")

        await event_queue.enqueue_event(
            Task(
                id=task_id,
                context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
            )
        )

        updater = TaskUpdater(event_queue, task_id, context_id)
        text = context.get_user_input().strip()

        if not text:
            await updater.complete(
                updater.new_agent_message([Part(text="No text provided to summarize.")])
            )
            return

        await updater.start_work()
        result = await self.agent.invoke(text)
        await updater.complete(updater.new_agent_message([Part(text=result)]))

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        raise Exception("cancel not supported")
