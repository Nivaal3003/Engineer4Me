from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def unique_name(prefix: str) -> str:
    return f"{prefix} {uuid4().hex[:8]}"


def create_manufacturer() -> dict:
    response = client.post(
        "/api/v1/manufacturers",
        json={
            "name": unique_name("Test Manufacturer"),
            "website": "https://example.com",
            "country": "South Africa",
        },
    )

    assert response.status_code == 201

    return response.json()


def create_product_family(
    manufacturer_id: int,
    name: str | None = None,
) -> dict:
    response = client.post(
        "/api/v1/product-families",
        json={
            "manufacturer_id": manufacturer_id,
            "name": name or unique_name("Test Product Family"),
            "description": "Product family created during testing.",
        },
    )

    assert response.status_code == 201

    return response.json()


def delete_product_family(product_family_id: int) -> None:
    response = client.delete(
        f"/api/v1/product-families/{product_family_id}"
    )

    assert response.status_code == 204


def delete_manufacturer(manufacturer_id: int) -> None:
    response = client.delete(
        f"/api/v1/manufacturers/{manufacturer_id}"
    )

    assert response.status_code == 204


def test_create_and_get_product_family() -> None:
    manufacturer = create_manufacturer()

    product_family = create_product_family(
        manufacturer["id"],
    )

    response = client.get(
        f"/api/v1/product-families/{product_family['id']}"
    )

    assert response.status_code == 200
    assert response.json()["id"] == product_family["id"]
    assert response.json()["manufacturer_id"] == manufacturer["id"]

    delete_product_family(product_family["id"])
    delete_manufacturer(manufacturer["id"])


def test_list_product_families() -> None:
    manufacturer = create_manufacturer()

    product_family = create_product_family(
        manufacturer["id"],
    )

    response = client.get(
        "/api/v1/product-families"
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert any(
        item["id"] == product_family["id"]
        for item in response.json()
    )

    delete_product_family(product_family["id"])
    delete_manufacturer(manufacturer["id"])


def test_filter_product_families_by_manufacturer() -> None:
    manufacturer = create_manufacturer()

    product_family = create_product_family(
        manufacturer["id"],
    )

    response = client.get(
        "/api/v1/product-families",
        params={
            "manufacturer_id": manufacturer["id"],
        },
    )

    assert response.status_code == 200
    assert len(response.json()) >= 1
    assert all(
        item["manufacturer_id"] == manufacturer["id"]
        for item in response.json()
    )
    assert any(
        item["id"] == product_family["id"]
        for item in response.json()
    )

    delete_product_family(product_family["id"])
    delete_manufacturer(manufacturer["id"])


def test_update_product_family() -> None:
    manufacturer = create_manufacturer()

    product_family = create_product_family(
        manufacturer["id"],
    )

    updated_name = unique_name("Updated Product Family")

    response = client.patch(
        f"/api/v1/product-families/{product_family['id']}",
        json={
            "name": updated_name,
            "description": "Updated product family description.",
        },
    )

    assert response.status_code == 200
    assert response.json()["name"] == updated_name
    assert (
        response.json()["description"]
        == "Updated product family description."
    )

    delete_product_family(product_family["id"])
    delete_manufacturer(manufacturer["id"])


def test_duplicate_product_family_is_rejected() -> None:
    manufacturer = create_manufacturer()

    family_name = unique_name("Duplicate Family")

    first_product_family = create_product_family(
        manufacturer["id"],
        family_name,
    )

    response = client.post(
        "/api/v1/product-families",
        json={
            "manufacturer_id": manufacturer["id"],
            "name": family_name,
            "description": "Duplicate family.",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        f"A product family named '{family_name}' "
        f"already exists for this manufacturer."
    )

    delete_product_family(first_product_family["id"])
    delete_manufacturer(manufacturer["id"])


def test_missing_manufacturer_is_rejected() -> None:
    response = client.post(
        "/api/v1/product-families",
        json={
            "manufacturer_id": 999999999,
            "name": unique_name("Missing Manufacturer Family"),
            "description": None,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Manufacturer not found."


def test_missing_product_family_returns_404() -> None:
    response = client.get(
        "/api/v1/product-families/999999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Product family not found."
    )