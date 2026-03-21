import os

os.environ.setdefault("MINIO_ALIAS", "test")
os.environ.setdefault("MINIO_ENDPOINT", "http://localhost:9000")
os.environ.setdefault("MINIO_ACCESS_KEY", "testkey")
os.environ.setdefault("MINIO_SECRET_KEY", "testsecret")
