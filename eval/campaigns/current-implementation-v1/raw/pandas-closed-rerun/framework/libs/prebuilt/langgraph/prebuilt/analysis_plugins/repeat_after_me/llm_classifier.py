"""Optional live LangChain model service; no provider dependency or agent tools."""

from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from langgraph.prebuilt.analysis.serialization import canonical, digest
from langgraph.prebuilt.analysis_plugins.repeat_after_me.classifier import (
    ClassificationInput,
)
from langgraph.prebuilt.analysis_plugins.repeat_after_me.schema import Classification


class LLMRepeatClassifier:
    """The injected client must enforce the declared local destination and deadline."""

    def __init__(
        self,
        client,
        *,
        model_digest: str,
        service_version: str,
        max_input_bytes: int = 32768,
        destination: str = "ollama:localhost",
        authorize_destination=lambda destination: destination == "ollama:localhost",
    ) -> None:
        if (
            not model_digest
            or not service_version
            or not authorize_destination(destination)
        ):
            raise ValueError("ram:unconfigured_analysis_service")
        self._client = client
        self.max_input_bytes = max_input_bytes
        self.prompt = (
            Path(__file__).with_name("classifier_prompt.txt").read_text().strip()
        )
        self.configuration = {
            "prompt_version": "1",
            "prompt_hash": digest(self.prompt),
            "model_digest": model_digest,
            "service_version": service_version,
            "input_limit": max_input_bytes,
            "response_tokens": 512,
            "deadline_seconds": 30,
            "destination": destination,
            "temperature": 0,
        }
        self.configuration_digest = digest(self.configuration)

    def _messages(self, candidate):
        data = canonical(
            {
                "sources": candidate.sources,
                "event_name": candidate.event_name,
                "metadata": candidate.metadata_json,
            }
        )
        if len(data.encode()) > self.max_input_bytes:
            raise ValueError("ram:input_limit")
        schema = canonical(Classification.model_json_schema())
        return [
            SystemMessage(content=self.prompt + "\nRequired JSON schema:\n" + schema),
            HumanMessage(content=data),
        ]

    def _parse(self, response, candidate):
        if getattr(response, "tool_calls", None) or not isinstance(
            response.content, str
        ):
            raise ValueError("ram:invalid_response")
        metadata = response.response_metadata
        if metadata.get("finish_reason", metadata.get("done_reason")) in (
            "length",
            "max_tokens",
        ):
            raise ValueError("ram:truncated_response")
        return Classification.parse(
            response.content, frozenset(source_id for source_id, _ in candidate.sources)
        )

    def classify(self, candidate: ClassificationInput) -> Classification:
        response = self._client.invoke(
            self._messages(candidate), tools=[], temperature=0, num_predict=512
        )
        return self._parse(response, candidate)

    async def aclassify(self, candidate: ClassificationInput) -> Classification:
        response = await self._client.ainvoke(
            self._messages(candidate), tools=[], temperature=0, num_predict=512
        )
        return self._parse(response, candidate)
