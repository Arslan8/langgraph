# Extending the framework: custom mediator

Run from the repository root:

```bash
libs/prebuilt/.venv/bin/python workspace/08_custom_mediator/demo.py
```

Demo 06 uses the built-in SQLite mediator. This demo implements a new counter API,
backend, and mediator in the application itself.

- [mediators/api.py](mediators/api.py) defines `CounterAPI.increment(amount)`, the
  resource contract, and its generated client. It creates no backend state.
- [mediators/counter.py](mediators/counter.py) implements the counter and its
  mediator. The backend changes the value; `validate` accepts only amounts 1–3.
- [demo.py](demo.py) binds the implementation and mediator to `COUNTER`, registers
  that resource, and runs the tool in an OS sandbox.

```python
resource = COUNTER.bind(
    implementation=CounterBackend(),
    mediator=CounterMediator(),
)
dispatcher = ObjectBrokerDispatcher(
    worker_specs,
    runtime_roots=runtime_roots,
    resources=(resource,),
)
# cedar_security derives the class declaration from registered resources:
manifest = "runs linux\n" + resource.permission("increment")
```

The tool calls `counter.increment(amount)`. There is no `"jobs"` selector or
`counter_id` argument. The framework gives each resource object an internal
identity; `.bind(...)` preserves that identity and existing clients. Construct a
separate contract for a separate counter. The constructor also accepts
`implementation=` and `mediator=` together, as shown by `counter_resource(...)`.

## Where checks happen

| Stage | Responsible code | Check |
| --- | --- | --- |
| Authorization | Framework DAC, then MAC | May this principal increment this exact object? |
| Policy lowering | Framework calls `CounterMediator.assess` | Can this implementation enforce the permission with this host's protections? |
| Request routing | Framework broker and typed binding | Does the invocation's grant permit this object and operation? Do arguments match the API? |
| Custom validation | `CounterMediator.validate` | Is the amount between 1 and 3? |
| Operation | `CounterBackend.increment` | Update the value and return it. |

`assess(line, host)` reports support and required host protections. It does not
identify a counter by an application string, allocate the counter, or check an
individual amount. The framework already matched the bound object before calling
it. This demo requires a spawn-bound broker and seccomp; the framework checks
those requirements. Unsupported required permissions stop execution. In the OS
lowering path, unsupported optional permissions are removed. Assessment can be
rechecked and must not mutate resource state.

A custom mediator is optional; without one, supply an explicit `assess=` callback.
Grant checks, typed dispatch, and resource identity enforcement still apply.

The demo prints an allowed increment of 2 and a denied increment of -1. The value
stays 2. Requires Linux Landlock, libseccomp, and the Cedar CLI.

See the [mediator developer guide](../../libs/prebuilt/langgraph/prebuilt/security/mediators/README.md)
for in-process use, raw broker clients, and the empty tutorial template.

[All demos and setup notes](../README.md)
