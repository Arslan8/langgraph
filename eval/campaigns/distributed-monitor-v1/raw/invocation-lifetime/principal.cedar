permit(principal == slangGraph::User::"alice", action == slangGraph::Action::"db_record::read", resource) when { resource.selector == "notes/alice" };
permit(principal == slangGraph::User::"bob", action == slangGraph::Action::"db_record::read", resource) when { resource.selector == "notes/bob" };
