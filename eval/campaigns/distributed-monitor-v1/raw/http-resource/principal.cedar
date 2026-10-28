permit(principal == slangGraph::User::"alice", action == slangGraph::Action::"http_record::read", resource) when { resource.selector == "alice" };
permit(principal == slangGraph::User::"admin", action in [slangGraph::Action::"http_record::read", slangGraph::Action::"http_record::modify"], resource) when { resource.selector == "alice" };
