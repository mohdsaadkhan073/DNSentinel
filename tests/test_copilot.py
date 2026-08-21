import pytest
from copilot.copilot_manager import CopilotManager

@pytest.mark.asyncio
async def test_copilot_fallback_evaluate():
    manager = CopilotManager()
    res = await manager.chat(
        message="Evaluate bad-c2.com",
        history=[],
        model="llama3:latest",
        context={"total_queries": 100, "blocked_queries": 10}
    )
    assert res is not None
    assert "reply" in res
    assert "action" in res
    if not res["online"]:
        assert res["action"] is not None
        assert res["action"]["type"] == "EVALUATE"
        assert res["action"]["domain"] == "bad-c2.com"

@pytest.mark.asyncio
async def test_copilot_fallback_navigate():
    manager = CopilotManager()
    res = await manager.chat(
        message="Show threat analytics",
        history=[],
        model="llama3:latest",
        context={}
    )
    assert res is not None
    if not res["online"]:
        assert res["action"] is not None
        assert res["action"]["type"] == "NAVIGATE"
        assert res["action"]["tab"] == "ANALYTICS"
