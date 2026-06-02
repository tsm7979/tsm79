"""
TSM Gateway
===========
The AI control plane (Product 1) running on the Trust Fabric (Product 2).

    from tsm.gateway import Gateway, AIRequest

    gw = Gateway(forwarder=my_llm_call)
    resp = gw.handle(AIRequest.from_openai(body, principal_id="agent:1"))
    if resp.status == "blocked":
        ...
"""
from tsm.gateway.gateway import AIRequest, Gateway, GatewayResponse

__all__ = ["Gateway", "AIRequest", "GatewayResponse"]
