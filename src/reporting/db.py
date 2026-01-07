from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class ScanResult(Base):
    """Model for a scan result."""
    __tablename__ = 'scan_results'

    id = Column(Integer, primary_key=True)
    target = Column(String)
    share = Column(String)
    file_path = Column(String)
    file_name = Column(String)
    is_directory = Column(Boolean)
    size = Column(Integer)
    findings = Column(JSON)  # List of dictionaries from analyzers
    created_at = Column(DateTime, default=datetime.utcnow)

class DBManager:
    """Manages SQLite database operations."""
    
    def __init__(self, db_path: str = "smbseeker.db"):
        self.engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def save_result(self, result_data: dict):
        """Saves a single scan result to the database."""
        session = self.Session()
        try:
            result = ScanResult(**result_data)
            session.add(result)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_results(self):
        """Retrieves all scan results."""
        session = self.Session()
        results = session.query(ScanResult).all()
        session.close()
        return results
