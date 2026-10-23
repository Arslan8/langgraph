// Operator-owned MAC policy, loaded independently of the tool's declarations.
// Deny every principal and destination for this application's internet class.
forbid (
    principal,
    action == slangGraph::Action::"internet::connect",
    resource
);
