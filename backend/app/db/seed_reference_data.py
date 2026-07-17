from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models import Manufacturer
from app.models import Measurement


def seed_manufacturers(db: Session):

    manufacturers = [
        ("Emerson", "https://www.emerson.com", "USA"),
        ("Endress+Hauser", "https://www.endress.com", "Switzerland"),
        ("Yokogawa", "https://www.yokogawa.com", "Japan"),
        ("Siemens", "https://www.siemens.com", "Germany"),
        ("ABB", "https://global.abb", "Switzerland"),
        ("VEGA", "https://www.vega.com", "Germany"),
        ("Krohne", "https://www.krohne.com", "Germany"),
        ("Honeywell", "https://www.honeywell.com", "USA"),
        ("Schneider Electric", "https://www.se.com", "France"),
        ("Fuji Electric", "https://www.fujielectric.com", "Japan"),
    ]

    for name, website, country in manufacturers:

        exists = db.query(Manufacturer).filter_by(name=name).first()

        if not exists:
            db.add(
                Manufacturer(
                    name=name,
                    website=website,
                    country=country,
                )
            )

    db.commit()


def seed_measurements(db: Session):

    measurements = [

        "Pressure",
        "Temperature",
        "Flow",
        "Level",
        "Tank Gauging",
        "Analytical",
        "Flame & Gas Detection",
        "Condition Monitoring",
        "Valve Automation",
        "Control Systems",

    ]

    for measurement in measurements:

        exists = db.query(Measurement).filter_by(name=measurement).first()

        if not exists:
            db.add(
                Measurement(
                    name=measurement
                )
            )

    db.commit()


def main():

    db = SessionLocal()

    seed_manufacturers(db)
    seed_measurements(db)

    db.close()

    print("Reference data loaded successfully.")


if __name__ == "__main__":
    main()