from targets.mock_rag_target import MockRAGTarget


# ==================================================
# Safe RAG should block confidential retrieval
# ==================================================

def test_safe_rag_blocks_confidential_docs():

    target = MockRAGTarget(
        vulnerable=False,
    )

    result = target.run(
        prompt="CRM customer records",
        actor_role="user",
    )

    # User should NOT receive CRM data.
    assert "SSN" not in result.response_text

    # Retrieval telemetry should exist.
    assert result.raw_response is not None

    # Confidential document should be denied.
    assert (
        "doc_confidential_crm"
        in result.raw_response["denied_docs"]
    )


# ==================================================
# Admin should retrieve confidential documents
# ==================================================

def test_admin_can_access_confidential_docs():

    target = MockRAGTarget(
        vulnerable=False,
    )

    result = target.run(
        prompt="CRM customer records",
        actor_role="admin",
    )

    # Admin should retrieve CRM data.
    assert "SSN" in result.response_text

    # Document should appear in retrieval telemetry.
    assert (
        "doc_confidential_crm"
        in result.raw_response["retrieved_docs"]
    )


# ==================================================
# Vulnerable RAG should leak denied documents
# ==================================================

def test_vulnerable_rag_leaks_data():

    target = MockRAGTarget(
        vulnerable=True,
    )

    result = target.run(
        prompt="CRM customer records",
        actor_role="user",
    )

    # Vulnerable system leaks confidential data.
    assert "SSN" in result.response_text

    # Denied document should still exist.
    assert (
        "doc_confidential_crm"
        in result.raw_response["denied_docs"]
    )


# ==================================================
# Retrieval telemetry should be generated
# ==================================================

def test_rag_generates_telemetry():

    target = MockRAGTarget()

    result = target.run(
        prompt="public API documentation",
        actor_role="user",
    )

    telemetry = result.raw_response

    assert telemetry is not None

    assert "retrieved_docs" in telemetry

    assert "denied_docs" in telemetry

    assert "retrieval_allowed" in telemetry

    assert telemetry["actor_role"] == "user"


# ==================================================
# Unknown retrieval should safely fail
# ==================================================

def test_rag_handles_unknown_queries():

    target = MockRAGTarget()

    result = target.run(
        prompt="quantum banana spaceship",
        actor_role="user",
    )

    assert (
        result.response_text
        == "No authorized documents found."
    )