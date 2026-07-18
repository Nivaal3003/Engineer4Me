from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.database import SessionLocal
from app.main import app
from app.models.application import Application
from app.models.measurement import Measurement
from app.models.protocol import Protocol
from app.models.technology import Technology


client = TestClient(app)


def unique_name(prefix: str) -> str:
    return f"{prefix} {uuid4().hex[:8]}"


def get_or_create_reference_record(
    model_class,
    name: str,
    description: str,
):
    with SessionLocal() as db:
        record = db.scalar(
            select(model_class).where(
                model_class.name == name
            )
        )

        if record is None:
            record = model_class(
                name=name,
                description=description,
            )

            db.add(record)
            db.commit()
            db.refresh(record)

        return {
            "id": record.id,
            "name": record.name,
        }


def get_reference_data() -> dict:
    measurement = get_or_create_reference_record(
        Measurement,
        "Product API Test Measurement",
        "Measurement used by Product API tests.",
    )

    application = get_or_create_reference_record(
        Application,
        "Product API Test Application",
        "Application used by Product API tests.",
    )

    technology = get_or_create_reference_record(
        Technology,
        "Product API Test Technology",
        "Technology used by Product API tests.",
    )

    protocol_one = get_or_create_reference_record(
        Protocol,
        "Product API Test Protocol One",
        "First protocol used by Product API tests.",
    )

    protocol_two = get_or_create_reference_record(
        Protocol,
        "Product API Test Protocol Two",
        "Second protocol used by Product API tests.",
    )

    return {
        "measurement": measurement,
        "application": application,
        "technology": technology,
        "protocol_one": protocol_one,
        "protocol_two": protocol_two,
    }


def create_manufacturer() -> dict:
    response = client.post(
        "/api/v1/manufacturers",
        json={
            "name": unique_name("Product Test Manufacturer"),
            "website": "https://example.com",
            "country": "South Africa",
        },
    )

    assert response.status_code == 201

    return response.json()


def create_product_family(
    manufacturer_id: int,
) -> dict:
    response = client.post(
        "/api/v1/product-families",
        json={
            "manufacturer_id": manufacturer_id,
            "name": unique_name("Product Test Family"),
            "description": (
                "Product family created during Product API testing."
            ),
        },
    )

    assert response.status_code == 201

    return response.json()


def build_product_payload(
    manufacturer_id: int,
    family_id: int,
    reference_data: dict,
    model: str | None = None,
    protocol_ids: list[int] | None = None,
) -> dict:
    return {
        "manufacturer_id": manufacturer_id,
        "measurement_id": reference_data["measurement"]["id"],
        "family_id": family_id,
        "application_id": reference_data["application"]["id"],
        "technology_id": reference_data["technology"]["id"],
        "model": model or unique_name("Test Product Model"),
        "description": "Product created during API testing.",
        "protocol_ids": (
            protocol_ids
            if protocol_ids is not None
            else [reference_data["protocol_one"]["id"]]
        ),
    }


def create_product(
    manufacturer_id: int,
    family_id: int,
    reference_data: dict,
    model: str | None = None,
    protocol_ids: list[int] | None = None,
) -> dict:
    payload = build_product_payload(
        manufacturer_id=manufacturer_id,
        family_id=family_id,
        reference_data=reference_data,
        model=model,
        protocol_ids=protocol_ids,
    )

    response = client.post(
        "/api/v1/products",
        json=payload,
    )

    assert response.status_code == 201, response.text

    return response.json()


def delete_product(product_id: int) -> None:
    response = client.delete(
        f"/api/v1/products/{product_id}"
    )

    assert response.status_code == 204


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


def test_create_and_get_product() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.get(
        f"/api/v1/products/{product['id']}"
    )

    assert response.status_code == 200

    response_data = response.json()

    assert response_data["id"] == product["id"]
    assert response_data["manufacturer_id"] == manufacturer["id"]
    assert response_data["family_id"] == family["id"]
    assert response_data["manufacturer"]["id"] == manufacturer["id"]
    assert response_data["family"]["id"] == family["id"]
    assert (
        response_data["measurement"]["id"]
        == reference_data["measurement"]["id"]
    )
    assert (
        response_data["application"]["id"]
        == reference_data["application"]["id"]
    )
    assert (
        response_data["technology"]["id"]
        == reference_data["technology"]["id"]
    )
    assert len(response_data["protocols"]) == 1

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_list_products() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.get("/api/v1/products")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert any(
        item["id"] == product["id"]
        for item in response.json()
    )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_filter_products_by_manufacturer() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.get(
        "/api/v1/products",
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
        item["id"] == product["id"]
        for item in response.json()
    )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_filter_products_by_measurement() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.get(
        "/api/v1/products",
        params={
            "measurement_id": reference_data["measurement"]["id"],
        },
    )

    assert response.status_code == 200
    assert any(
        item["id"] == product["id"]
        for item in response.json()
    )
    assert all(
        item["measurement_id"]
        == reference_data["measurement"]["id"]
        for item in response.json()
    )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_filter_products_by_protocol() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    protocol_id = reference_data["protocol_one"]["id"]

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
        protocol_ids=[protocol_id],
    )

    response = client.get(
        "/api/v1/products",
        params={
            "protocol_id": protocol_id,
        },
    )

    assert response.status_code == 200
    assert any(
        item["id"] == product["id"]
        for item in response.json()
    )

    for item in response.json():
        assert any(
            protocol["id"] == protocol_id
            for protocol in item["protocols"]
        )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_update_product() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    updated_model = unique_name("Updated Product Model")

    response = client.patch(
        f"/api/v1/products/{product['id']}",
        json={
            "model": updated_model,
            "description": "Updated Product API description.",
        },
    )

    assert response.status_code == 200
    assert response.json()["model"] == updated_model
    assert response.json()["description"] == (
        "Updated Product API description."
    )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_update_product_protocols() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    first_protocol_id = reference_data["protocol_one"]["id"]
    second_protocol_id = reference_data["protocol_two"]["id"]

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
        protocol_ids=[first_protocol_id],
    )

    response = client.patch(
        f"/api/v1/products/{product['id']}",
        json={
            "protocol_ids": [
                second_protocol_id,
                second_protocol_id,
            ],
        },
    )

    assert response.status_code == 200

    protocols = response.json()["protocols"]

    assert len(protocols) == 1
    assert protocols[0]["id"] == second_protocol_id
    assert all(
        protocol["id"] != first_protocol_id
        for protocol in protocols
    )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_duplicate_product_model_is_rejected() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    model_name = unique_name("Duplicate Product Model")

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
        model=model_name,
    )

    response = client.post(
        "/api/v1/products",
        json=build_product_payload(
            manufacturer_id=manufacturer["id"],
            family_id=family["id"],
            reference_data=reference_data,
            model=model_name.lower(),
        ),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "A product with this model already exists "
        "for the selected manufacturer."
    )

    delete_product(product["id"])
    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_missing_manufacturer_is_rejected() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    payload = build_product_payload(
        manufacturer_id=999999999,
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.post(
        "/api/v1/products",
        json=payload,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Manufacturer does not exist."
    )

    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_family_must_belong_to_manufacturer() -> None:
    reference_data = get_reference_data()

    first_manufacturer = create_manufacturer()
    second_manufacturer = create_manufacturer()

    family = create_product_family(
        first_manufacturer["id"]
    )

    payload = build_product_payload(
        manufacturer_id=second_manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.post(
        "/api/v1/products",
        json=payload,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Product family does not belong to "
        "the selected manufacturer."
    )

    delete_product_family(family["id"])
    delete_manufacturer(first_manufacturer["id"])
    delete_manufacturer(second_manufacturer["id"])


def test_missing_protocol_is_rejected() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    payload = build_product_payload(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
        protocol_ids=[999999999],
    )

    response = client.post(
        "/api/v1/products",
        json=payload,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The following protocols do not exist: "
        "999999999."
    )

    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_missing_product_returns_404() -> None:
    response = client.get(
        "/api/v1/products/999999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Product not found."


def test_delete_product() -> None:
    reference_data = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_product_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        reference_data=reference_data,
    )

    response = client.delete(
        f"/api/v1/products/{product['id']}"
    )

    assert response.status_code == 204

    get_response = client.get(
        f"/api/v1/products/{product['id']}"
    )

    assert get_response.status_code == 404

    delete_product_family(family["id"])
    delete_manufacturer(manufacturer["id"])
