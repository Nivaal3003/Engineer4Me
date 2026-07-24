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
) -> dict:
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
    return {
        "measurement": get_or_create_reference_record(
            Measurement,
            unique_name("Selection Measurement"),
            "Measurement used by selection tests.",
        ),
        "application": get_or_create_reference_record(
            Application,
            unique_name("Selection Application"),
            "Application used by selection tests.",
        ),
        "technology": get_or_create_reference_record(
            Technology,
            unique_name("Selection Technology"),
            "Technology used by selection tests.",
        ),
        "protocol_one": get_or_create_reference_record(
            Protocol,
            unique_name("Selection Protocol One"),
            "First protocol used by selection tests.",
        ),
        "protocol_two": get_or_create_reference_record(
            Protocol,
            unique_name("Selection Protocol Two"),
            "Second protocol used by selection tests.",
        ),
    }


def create_manufacturer() -> dict:
    response = client.post(
        "/api/v1/manufacturers",
        json={
            "name": unique_name("Selection Manufacturer"),
            "website": "https://example.com",
            "country": "South Africa",
        },
    )

    assert response.status_code == 201, response.text
    return response.json()


def create_family(manufacturer_id: int) -> dict:
    response = client.post(
        "/api/v1/product-families",
        json={
            "manufacturer_id": manufacturer_id,
            "name": unique_name("Selection Family"),
            "description": "Selection test family.",
        },
    )

    assert response.status_code == 201, response.text
    return response.json()


def create_product(
    manufacturer_id: int,
    family_id: int,
    references: dict,
    model: str,
    protocol_ids: list[int],
) -> dict:
    response = client.post(
        "/api/v1/products",
        json={
            "manufacturer_id": manufacturer_id,
            "measurement_id": references["measurement"]["id"],
            "family_id": family_id,
            "application_id": references["application"]["id"],
            "technology_id": references["technology"]["id"],
            "model": model,
            "description": "Selection test product.",
            "protocol_ids": protocol_ids,
        },
    )

    assert response.status_code == 201, response.text
    return response.json()


def delete_product(product_id: int) -> None:
    response = client.delete(
        f"/api/v1/products/{product_id}"
    )
    assert response.status_code == 204


def delete_family(family_id: int) -> None:
    response = client.delete(
        f"/api/v1/product-families/{family_id}"
    )
    assert response.status_code == 204


def delete_manufacturer(manufacturer_id: int) -> None:
    response = client.delete(
        f"/api/v1/manufacturers/{manufacturer_id}"
    )
    assert response.status_code == 204


def test_selection_returns_matching_product() -> None:
    references = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_family(manufacturer["id"])

    product = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        references=references,
        model=unique_name("Selection Model"),
        protocol_ids=[
            references["protocol_one"]["id"],
        ],
    )

    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": references["measurement"]["id"],
            "manufacturer_id": manufacturer["id"],
            "family_id": family["id"],
            "application_id": references["application"]["id"],
            "technology_id": references["technology"]["id"],
            "protocol_ids": [
                references["protocol_one"]["id"],
            ],
            "minimum_score": 0,
            "limit": 10,
        },
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total_candidates"] >= 1
    assert data["total_recommendations"] >= 1
    assert data["recommendations"][0]["product_id"] == product["id"]
    assert data["recommendations"][0]["match_percentage"] > 0
    assert data["recommendations"][0]["reasons"]

    delete_product(product["id"])
    delete_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_selection_ranks_better_protocol_match_first() -> None:
    references = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_family(manufacturer["id"])

    full_match = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        references=references,
        model=unique_name("Full Protocol Match"),
        protocol_ids=[
            references["protocol_one"]["id"],
            references["protocol_two"]["id"],
        ],
    )

    partial_match = create_product(
        manufacturer_id=manufacturer["id"],
        family_id=family["id"],
        references=references,
        model=unique_name("Partial Protocol Match"),
        protocol_ids=[
            references["protocol_one"]["id"],
        ],
    )

    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": references["measurement"]["id"],
            "protocol_ids": [
                references["protocol_one"]["id"],
                references["protocol_two"]["id"],
            ],
            "minimum_score": 0,
            "limit": 10,
        },
    )

    assert response.status_code == 200, response.text

    recommendation_ids = [
        recommendation["product_id"]
        for recommendation in response.json()["recommendations"]
    ]

    assert full_match["id"] in recommendation_ids
    assert partial_match["id"] in recommendation_ids
    assert recommendation_ids.index(
        full_match["id"]
    ) < recommendation_ids.index(
        partial_match["id"]
    )

    delete_product(full_match["id"])
    delete_product(partial_match["id"])
    delete_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_selection_respects_limit() -> None:
    references = get_reference_data()
    manufacturer = create_manufacturer()
    family = create_family(manufacturer["id"])

    products = [
        create_product(
            manufacturer_id=manufacturer["id"],
            family_id=family["id"],
            references=references,
            model=unique_name(f"Limited Model {index}"),
            protocol_ids=[
                references["protocol_one"]["id"],
            ],
        )
        for index in range(3)
    ]

    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": references["measurement"]["id"],
            "minimum_score": 0,
            "limit": 2,
        },
    )

    assert response.status_code == 200, response.text
    assert len(response.json()["recommendations"]) == 2
    assert response.json()["total_recommendations"] == 2

    for product in products:
        delete_product(product["id"])

    delete_family(family["id"])
    delete_manufacturer(manufacturer["id"])


def test_selection_invalid_measurement_is_rejected() -> None:
    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": 999999999,
            "minimum_score": 0,
            "limit": 5,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Measurement does not exist."
    )


def test_selection_invalid_protocol_is_rejected() -> None:
    references = get_reference_data()

    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": references["measurement"]["id"],
            "protocol_ids": [999999999],
            "minimum_score": 0,
            "limit": 5,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The following protocols do not exist: 999999999."
    )


def test_selection_family_must_match_manufacturer() -> None:
    references = get_reference_data()
    first_manufacturer = create_manufacturer()
    second_manufacturer = create_manufacturer()
    family = create_family(first_manufacturer["id"])

    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": references["measurement"]["id"],
            "manufacturer_id": second_manufacturer["id"],
            "family_id": family["id"],
            "minimum_score": 0,
            "limit": 5,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Product family does not belong to "
        "the selected manufacturer."
    )

    delete_family(family["id"])
    delete_manufacturer(first_manufacturer["id"])
    delete_manufacturer(second_manufacturer["id"])


def test_selection_returns_empty_results() -> None:
    references = get_reference_data()

    response = client.post(
        "/api/v1/selections",
        json={
            "measurement_id": references["measurement"]["id"],
            "minimum_score": 0,
            "limit": 5,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total_candidates"] == 0
    assert data["total_recommendations"] == 0
    assert data["recommendations"] == []
