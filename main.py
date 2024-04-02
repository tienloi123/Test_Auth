from fastapi import FastAPI
from app.endpoints.auth import router as auth_router

app = FastAPI()

app.include_router(auth_router, prefix="/api")
