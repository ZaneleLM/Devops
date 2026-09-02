"""
AI Agent - Identity & Privilege Abuse Lab
=========================================

This service simulates an AI agent that can call a banking tool.

We deliberately keep the "AI" deterministic because this exercise is about
authorization, not model behaviour.

Two execution paths are provided:

VULNERABLE:
    The agent receives the user's request, but drops the user's identity
    before calling the banking backend.

SECURE:
    The agent forwards the user's identity to the banking backend so the
    backend can check the human user's permissions.
"""

# --------------------------------------------------------
# IMPORTS
# --------------------------------------------------------

import requests

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel


# --------------------------------------------------------
# CREATE FASTAPI APPLICATION
# --------------------------------------------------------

app = FastAPI(
    title="Identity and Privilege Abuse Agent"
)


# --------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------

# The banking backend is running locally on port 8001.
BACKEND_URL = "http://127.0.0.1:8001"

# This represents the AI agent's own non-human identity.
AGENT_IDENTITY = "Agent_Service_Account"


# --------------------------------------------------------
# REQUEST FORMAT
# --------------------------------------------------------

class FreezeRequest(BaseModel):
    """
    The user tells the agent which card should be frozen.
    """
    card_id: str = "CARD-1001"


# --------------------------------------------------------
# TOOL FUNCTION
# --------------------------------------------------------

def freeze_card(
    card_id: str,
    user_authorization: str | None = None,
    secure: bool = False
):
    """
    Call the banking backend's freeze-card endpoint.

    vulnerable mode:
        Send only the agent's identity.

    secure mode:
        Send the agent's identity AND the human user's token.
    """

    # Start with the agent identity.
    headers = {
        "X-Agent-Identity": AGENT_IDENTITY
    }

    # Choose which backend authorization path to call.
    mode = "vulnerable"

    if secure:
        mode = "secure"

        # SECURITY FIX:
        #
        # Preserve the originating user's identity.
        # This lets the banking backend make the final authorization decision.
        if user_authorization:
            headers["X-User-Authorization"] = user_authorization

    # Call the banking backend.
    response = requests.post(
        f"{BACKEND_URL}/cards/freeze",
        params={"mode": mode},
        headers=headers,
        json={
            "card_id": card_id
        },
        timeout=10
    )

    # Convert the backend response into Python data.
    try:
        body = response.json()

    except ValueError:
        body = {
            "detail": response.text
        }

    return response.status_code, body


# --------------------------------------------------------
# VULNERABLE AGENT PATH
# --------------------------------------------------------

@app.post("/agent/freeze/vulnerable")
def vulnerable_agent(
    request: FreezeRequest,

    # The human may send a token to the agent...
    x_user_authorization: str | None = Header(default=None)
):
    """
    Vulnerable behaviour.

    The agent receives the user's Authorization token,
    but deliberately DOES NOT forward it to the backend.

    The backend therefore sees only:

        Agent_Service_Account

    This is the confused deputy flaw.
    """

    # We intentionally ignore the human user's token.
    _ = x_user_authorization

    status_code, body = freeze_card(
        card_id=request.card_id,
        secure=False
    )

    return JSONResponse(
        status_code=status_code,
        content=body
    )


# --------------------------------------------------------
# SECURE AGENT PATH
# --------------------------------------------------------

@app.post("/agent/freeze/secure")
def secure_agent(
    request: FreezeRequest,

    # The human user's token enters the agent here.
    x_user_authorization: str | None = Header(default=None)
):
    
    """
    Secure behaviour.

    The agent keeps the human user's identity
    and forwards it to the backend.

    The backend then validates:

    1. Agent identity
    2. Human identity
    3. Human role
    """

    status_code, body = freeze_card(
        card_id=request.card_id,
        user_authorization=x_user_authorization,
        secure=True
    )

    return JSONResponse(
        status_code=status_code,
        content=body
    )


# --------------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok"
    }