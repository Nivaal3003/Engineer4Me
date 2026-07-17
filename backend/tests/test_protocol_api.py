from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_list_protocols() -> None:
    response = client.get("/api/v1/protocols")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_existing_protocol() -> None:
    response = client.get("/api/v1/protocols/1")

    assert response.status_code == 200

    protocol = response.json()

    assert protocol["id"] == 1
    assert protocol["name"] == "HART"


def test_create_duplicate_protocol_is_rejected() -> None:
    payload = {
        "name": "HART",
        "description": "Duplicate protocol test.",
    }

    response = client.post(
        "/api/v1/protocols",
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "A protocol named 'HART' already exists."
    )


def test_update_existing_protocol() -> None:
    payload = {
        "description": (
            "Digital communication protocol used with "
            "smart field instruments."
        ),
    }

    response = client.patch(
        "/api/v1/protocols/1",
        json=payload,
    )

    assert response.status_code == 200

    protocol = response.json()

    assert protocol["id"] == 1
    assert protocol["name"] == "HART"
    assert protocol["description"] == payload["description"]


def test_get_missing_protocol_returns_404() -> None:
    response = client.get("/api/v1/protocols/999999")

    assert response.status_code == 404