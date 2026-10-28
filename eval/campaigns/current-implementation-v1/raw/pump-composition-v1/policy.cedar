
// There is deliberately no caller-side Action::"call" permit here. For this
// resource-bearing tool, permission to invoke is derived from whether the
// selected manifest operation is authorized for the principal.

// Alice: inspect, start, stop, and set flow.
permit (
  principal == slangGraph::User::"alice",
  action in [
    slangGraph::Action::"pump::inspect",
    slangGraph::Action::"pump::start",
    slangGraph::Action::"pump::stop",
    slangGraph::Action::"pump::set_flow"
  ],
  resource
) when {
  resource.selector == "pump-1"
};

// Bob: inspect and calibrate.
permit (
  principal == slangGraph::User::"bob",
  action in [
    slangGraph::Action::"pump::inspect",
    slangGraph::Action::"pump::calibrate"
  ],
  resource
) when {
  resource.selector == "pump-1"
};

// Charlie: inspect only.
permit (
  principal == slangGraph::User::"charlie",
  action == slangGraph::Action::"pump::inspect",
  resource
) when {
  resource.selector == "pump-1"
};
