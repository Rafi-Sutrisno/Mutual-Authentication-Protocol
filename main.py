from fastapi import FastAPI
from api.calculator import router as calculator_router
from auth.protocol import router as auth_router

app = FastAPI()

app.include_router(calculator_router, prefix="/calc")
app.include_router(auth_router, prefix="/auth")

@app.get("/")
def hello():
    return {"message": "Hello from my FastAPI app with calculator and mutual authentication!"}
