from db.database import engine, Base
from db.models import Vulnerability, VulnAnalysis, VulnHistory, UploadLog


def create_tables():
    Base.metadata.create_all(bind=engine)
    print("All tables created successfully.")


if __name__ == "__main__":
    create_tables()
