import os
from datetime import timedelta


class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///pdf_archive.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File Upload
    MAX_CONTENT_LENGTH = 900 * 1024 * 1024  # 900MB max file size
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'pdf'}

    # Security Settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)  # Token expires in 24 hours
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    RATE_LIMIT_STORAGE_URI = "memory://"

    # CORS
    CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:5000"]

    # Redis (for rate limiting and caching)
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Use environment variables in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'