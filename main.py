from fastapi import FastAPI
import authentication
import keepers

app = FastAPI()
app.include_router(authentication.router)
app.include_router(keepers.router)