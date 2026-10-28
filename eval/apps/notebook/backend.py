"""Drive the existing Open Notebook HTTP API against a dedicated local deployment."""

import json
import sys
import urllib.request
from pathlib import Path


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    fixture = json.loads((Path(request["fixture_root"]) / "sources.json").read_text())
    events = Path(request["events"])

    def api(method, path, body=None):
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            "http://127.0.0.1:15055/api" + path,
            data=payload,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=600) as response:
            raw = response.read().decode()
            status = response.status
        with events.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "kind": "http",
                        "method": method,
                        "path": path,
                        "body": body,
                        "status": status,
                        "response": raw,
                    }
                )
                + "\n"
            )
        return json.loads(raw) if raw.startswith(("{", "[")) else raw

    models = api("GET", "/models")
    model = next(
        (m for m in models if m["name"] == request["model"]["name"] and m["provider"] == "ollama"),
        None,
    )
    if model is None:
        model = api(
            "POST",
            "/models",
            {"name": request["model"]["name"], "provider": "ollama", "type": "language"},
        )
    collections = []
    for scope in ["allowed", "restricted"]:
        notebook = api("POST", "/notebooks", {"name": fixture["run_id"] + "-" + scope})
        source = api(
            "POST",
            "/sources/json",
            {
                "notebooks": [notebook["id"]],
                "type": "text",
                "title": "Synthetic " + scope,
                "content": fixture[scope],
                "embed": False,
                "async_processing": False,
                "transformations": [],
            },
        )
        persisted = api("GET", "/sources/" + source["id"])
        collections.append({"notebook": notebook, "source": source, "persisted": persisted})
    source_id = collections[0]["source"]["id"]
    session = api(
        "POST",
        f"/sources/{source_id}/chat/sessions",
        {
            "source_id": source_id,
            "title": "Synthetic smoke",
            "model_override": model["id"],
        },
    )
    stream = api(
        "POST",
        f"/sources/{source_id}/chat/sessions/{session['id']}/messages",
        {
            "message": request["task"],
            "model_override": model["id"],
        },
    )
    session_state = api("GET", f"/sources/{source_id}/chat/sessions/{session['id']}")
    Path(request["output"]).write_text(
        json.dumps(
            {
                "collections": collections,
                "stream": stream,
                "session": session_state,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
