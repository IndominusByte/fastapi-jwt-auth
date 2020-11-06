from fastapi import FastAPI, WebSocket, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel

app = FastAPI()

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_token_location: set = {"cookies"}

@AuthJWT.load_config
def get_config():
    return Settings()


html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Authorize</title>
    </head>
    <body>
        <h1>WebSocket Authorize</h1>
        <button onclick="websocketfun()">Send</button>
        <ul id='messages'>
        </ul>
        <script>
            const getCookie = (name) => {
                const value = `; ${document.cookie}`;
                const parts = value.split(`; ${name}=`);
                if (parts.length === 2) return parts.pop().split(';').shift();
            }

            const websocketfun = () => {
                let csrf_token = getCookie("csrf_access_token")

                let ws = new WebSocket(`ws://192.168.18.202:8000/ws?csrf_token=${csrf_token}`)
                ws.onmessage = (event) => {
                    let messages = document.getElementById('messages')
                    let message = document.createElement('li')
                    let content = document.createTextNode(event.data)
                    message.appendChild(content)
                    messages.appendChild(message)
                }
            }
        </script>
    </body>
</html>
"""

@app.get("/")
async def get():
    return HTMLResponse(html)

@app.websocket('/ws')
async def websocket(websocket: WebSocket, csrf_token: str = Query(...), Authorize: AuthJWT = Depends()):
    await websocket.accept()
    try:
        Authorize.jwt_required("websocket",websocket=websocket,csrf_token=csrf_token)
        # Authorize.jwt_optional("websocket",websocket=websocket,csrf_token=csrf_token)
        # Authorize.jwt_refresh_token_required("websocket",websocket=websocket,csrf_token=csrf_token)
        # Authorize.fresh_jwt_required("websocket",websocket=websocket,csrf_token=csrf_token)
        await websocket.send_text("Successfully Login!")
        decoded_token = Authorize.get_raw_jwt()
        await websocket.send_text(f"Here your decoded token: {decoded_token}")
    except AuthJWTException as err:
        await websocket.send_text(err.message)
        await websocket.close()

@app.get('/get-cookie')
def get_cookie(Authorize: AuthJWT = Depends()):
    access_token = Authorize.create_access_token(subject='test',fresh=True)
    refresh_token = Authorize.create_refresh_token(subject='test')

    Authorize.set_access_cookies(access_token)
    Authorize.set_refresh_cookies(refresh_token)
    return {"msg":"Successfully login"}
