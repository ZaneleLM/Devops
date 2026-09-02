"""
Identity & Privilege Abuse Lab
==============================

This backend simulates a small banking API.

We have two human users:

1. analyst_bob
   - Role: READ_ONLY
   - Should NOT be able to freeze cards

2. admin_alice
   - Role: CARD_ADMIN
   - IS allowed to freeze cards

The lab contains two authorization paths:

VULNERABLE:
The backend checks only whether the request came from the AI agent.

SECURE:
The backend checks:
1. the AI agent identity
2. the human user's identity
3. the human user's role
"""


# --------------------------------------------------------
# IMPORTS
# --------------------------------------------------------

from datetime import datetime, timedelta, timezone

import jwt

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel


# --------------------------------------------------------
# CREATE FASTAPI APPLICATION
# --------------------------------------------------------

app = FastAPI(
    title="Identity and Privilege Abuse Lab"
)


# --------------------------------------------------------
# SIMPLE LAB CONFIGURATION
# --------------------------------------------------------

# This secret is used to sign our demo user tokens.
#
# This is acceptable for a local teaching lab.
# In a real system, secrets should never be hardcoded like this.

JWT_SECRET = "vroomi-training-secret"


# This represents the trusted non-human identity used by
# the AI agent.

EXPECTED_AGENT_IDENTITY = "Agent_Service_Account"


# --------------------------------------------------------
# DUMMY USERS
# --------------------------------------------------------

# Bob has read-only permissions.
# Alice has permission to freeze cards.

USERS = {
    "analyst_bob": {
        "role": "READ_ONLY"
    },

    "admin_alice": {
        "role": "CARD_ADMIN"
    }
}


# --------------------------------------------------------
# DUMMY CARD DATA
# --------------------------------------------------------

CARDS = {
    "CARD-1001": {
        "owner": "Customer-001",
        "status": "ACTIVE"
    }
}


# --------------------------------------------------------
# REQUEST FORMAT
# --------------------------------------------------------

class FreezeRequest(BaseModel):
    """
    Defines the information required when requesting
    that a card be frozen.
    """

    card_id: str


# --------------------------------------------------------
# CREATE USER TOKEN
# --------------------------------------------------------

def create_user_token(username: str):
    """
    Create a short-lived JWT for one of our demo users.

    The token represents the identity of the HUMAN
    who is requesting an action.
    """

    if username not in USERS:

        raise HTTPException(
            status_code=404,
            detail="Unknown user"
        )

    payload = {

        # "sub" identifies the user.
        "sub": username,

        # Token expires after one hour.
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    return token


# --------------------------------------------------------
# VALIDATE USER TOKEN
# --------------------------------------------------------

def validate_user_token(user_authorization):
    """
    Validate the human user's token.

    Expected format:

    Bearer eyJhbGciOi...
    """

    if not user_authorization:

        raise HTTPException(
            status_code=401,
            detail="Missing user authorization"
        )


    if not user_authorization.startswith("Bearer "):

        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format"
        )


    # Remove "Bearer " so we are left with the JWT.

    token = user_authorization.replace(
        "Bearer ",
        "",
        1
    ).strip()


    try:

        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail="Invalid user token"
        )


    username = payload.get("sub")


    if username not in USERS:

        raise HTTPException(
            status_code=401,
            detail="Unknown user"
        )


    return username


# --------------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------------

@app.get("/health")
def health():
    """
    Simple endpoint used to confirm that the API
    is running correctly.
    """

    return {
        "status": "ok"
    }


# --------------------------------------------------------
# GET DEMO USER TOKEN
# --------------------------------------------------------

@app.get("/demo/token/{username}")
def get_demo_token(username: str):
    """
    Generate a token for Bob or Alice.

    This endpoint exists ONLY for the training lab.
    """

    token = create_user_token(username)


    return {

        "username": username,

        "role": USERS[username]["role"],

        "token": token
    }


# --------------------------------------------------------
# VIEW CARD
# --------------------------------------------------------

@app.get("/cards/{card_id}")
def get_card(card_id: str):
    """
    View the current status of a card.
    """

    if card_id not in CARDS:

        raise HTTPException(
            status_code=404,
            detail="Card not found"
        )


    return CARDS[card_id]


# --------------------------------------------------------
# RESET LAB
# --------------------------------------------------------

@app.post("/demo/reset")
def reset_lab():
    """
    Reset the card back to ACTIVE.

    This allows learners to repeat the attack
    and defence exercises.
    """

    CARDS["CARD-1001"]["status"] = "ACTIVE"


    return {

        "message": "Lab reset",

        "card": CARDS["CARD-1001"]
    }


# --------------------------------------------------------
# FREEZE CARD
# --------------------------------------------------------

@app.post("/cards/freeze")
def freeze_card(

    request: FreezeRequest,

    # Learners choose either:
    #
    # mode=vulnerable
    #
    # or
    #
    # mode=secure

    mode: str = Query(...),


    # Identity of the AI agent.

    x_agent_identity: str | None = Header(
        default=None
    ),


    # Identity information belonging to the HUMAN
    # who asked the AI agent to perform the action.

    x_user_authorization: str | None = Header(
        default=None
    )
):

    """
    Freeze a card.

    This endpoint contains both the vulnerable
    and secure authorization behaviour.
    """


    # ----------------------------------------------------
    # CHECK CARD EXISTS
    # ----------------------------------------------------

    if request.card_id not in CARDS:

        raise HTTPException(
            status_code=404,
            detail="Card not found"
        )


    # ----------------------------------------------------
    # CHECK AGENT IDENTITY
    # ----------------------------------------------------

    if x_agent_identity != EXPECTED_AGENT_IDENTITY:

        raise HTTPException(
            status_code=403,
            detail="Invalid agent identity"
        )


    # ----------------------------------------------------
    # VULNERABLE PATH
    # ----------------------------------------------------

    if mode == "vulnerable":

        # SECURITY PROBLEM:
        #
        # The backend only asks:
        #
        # "Is the AI agent trusted?"
        #
        # It does NOT ask:
        #
        # "Which human asked the AI agent to do this?"
        #
        # Therefore a low-privilege user can indirectly
        # use the AI agent's higher privileges.


        CARDS[request.card_id]["status"] = "FROZEN"


        return {

            "authorized": True,

            "mode": "vulnerable",

            "reason": "Agent identity accepted",

            "card_id": request.card_id,

            "status": "FROZEN"
        }


    # ----------------------------------------------------
    # SECURE PATH
    # ----------------------------------------------------

    if mode == "secure":

        # First identify the HUMAN who requested
        # the action.

        username = validate_user_token(
            x_user_authorization
        )


        # Look up their role in the trusted user database.

        user_role = USERS[username]["role"]


        # Only CARD_ADMIN users are allowed
        # to freeze cards.

        if user_role != "CARD_ADMIN":

            raise HTTPException(

                status_code=403,

                detail=(
                    f"User {username} has role {user_role} "
                    "and is not authorized to freeze cards"
                )
            )


        # Both identities have now been checked:
        #
        # 1. AI agent identity
        # 2. Human user identity and permissions


        CARDS[request.card_id]["status"] = "FROZEN"


        return {

            "authorized": True,

            "mode": "secure",

            "agent_identity": x_agent_identity,

            "human_identity": username,

            "human_role": user_role,

            "card_id": request.card_id,

            "status": "FROZEN"
        }


    # ----------------------------------------------------
    # INVALID MODE
    # ----------------------------------------------------

    raise HTTPException(

        status_code=400,

        detail="Mode must be 'vulnerable' or 'secure'"
    )