"""Source-only verification fixture; policy/legacy imports name terminal contracts."""

from policy import permission, apermission, Verdict
from legacy import dispatch, adispatch

def decision_for(principal, request):
    return permission(principal, request)

def execute(principal, request):
    decision = decision_for(principal, request)
    if decision.verdict is not Verdict.ALLOW:
        raise PermissionError('denied')
    return dispatch(principal, request)

class Tool:
    def invoke(self, principal, request):
        return execute(principal, request)

    def run(self, principal, request):
        alias = self.invoke
        return alias(principal, request)

    async def ainvoke(self, principal, request):
        decision = await apermission(principal, request)
        if decision.verdict is not Verdict.ALLOW:
            raise PermissionError('denied')
        return await adispatch(principal, request)

class Child(Tool):
    async def arun(self, principal, request):
        return await self.ainvoke(principal, request)
