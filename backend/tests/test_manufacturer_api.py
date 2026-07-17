from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def unique_name(prefix: str = "Test Manufacturer") -> str:
    return f"{prefix} {uuid4().hex[:8]}"


def create_manufacturer(
    name: str,
    website: str | None = None,
    country: str | None = None,
) -> dict:
    response = client.post(
        "/api/v1/manufacturers",
        json={
            "name": name,
            "website": website,
            "country": country,
        },
    )

    assert response.status_code == 201

    return response.json()


def delete_manufacturer(manufacturer_id: int) -> None:
    response = client.delete(
        f"/api/v1/manufacturers/{manufacturer_id}"
    )

    assert response.status_code == 204


def test_create_and_get_manufacturer() -> None:
    name = unique_name()

    manufacturer = create_manufacturer(
        name=name,
        website="https://example.com",
        country="South Africa",
    )

    manufacturer_id = manufacturer["id"]

    response = client.get(
        f"/api/v1/manufacturers/{manufacturer_id}"
    )

    assert response.status_code == 200
    assert response.json()["name"] == name
    assert response.json()["country"] == "South Africa"

    delete_manufacturer(manufacturer_id)


def test_list_manufacturers() -> None:
    name = unique_name()

    manufacturer = create_manufacturer(name=name)

    response = client.get("/api/v1/manufacturers")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert any(
        item["id"] == manufacturer["id"]
        for item in response.json()
    )

    delete_manufacturer(manufacturer["id"])


def test_update_manufacturer() -> None:
    manufacturer = create_manufacturer(
        name=unique_name(),
        country="United States",
    )

    response = client.patch(
        f"/api/v1/manufacturers/{manufacturer['id']}",
        json={
            "country": "South Africa",
            "website": "https://example.org",
        },
    )

    assert response.status_code == 200
    assert response.json()["country"] == "South Africa"
    assert response.json()["website"] == "https://example.org"

    delete_manufacturer(manufacturer["id"])


def test_duplicate_manufacturer_is_rejected() -> None:
    name = unique_name()

    manufacturer = create_manufacturer(name=name)

    response = client.post(
        "/api/v1/manufacturers",
        json={
            "name": name,
            "country": "South Africa",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        f"A manufacturer named '{name}' already exists."
    )

    delete_manufacturer(manufacturer["id"])


def test_missing_manufacturer_returns_404() -> None:
    response = client.get(
        "/api/v1/manufacturers/999999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Manufacturer not found."