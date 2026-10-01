# || made by several ||
from flask import Flask, request, jsonify, Response
import requests
import json
import hashlib
import hmac
import time
from datetime import datetime, date
import logging
import random

app = Flask(__name__)

VOTING_WEBHOOK      = "https://discord.com/api/webhooks/1491207735746760805/1uy27p_HsJXmNpVZDLj-ASTHbp9DNUOU5DPpM0I6kdRFXV5gW6lGdU2d8uzo5oaxg8bc"
BAD_NONCE_WEBHOOK   = "https://discord.com/api/webhooks/1491207735746760805/1uy27p_HsJXmNpVZDLj-ASTHbp9DNUOU5DPpM0I6kdRFXV5gW6lGdU2d8uzo5oaxg8bc"
GOOD_NONCE_WEBHOOK  = "https://discord.com/api/webhooks/1491207735746760805/1uy27p_HsJXmNpVZDLj-ASTHbp9DNUOU5DPpM0I6kdRFXV5gW6lGdU2d8uzo5oaxg8bc"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1491207735746760805/1uy27p_HsJXmNpVZDLj-ASTHbp9DNUOU5DPpM0I6kdRFXV5gW6lGdU2d8uzo5oaxg8bc"

# ── CONFIG ────────────────────────────────────────────────────────────────────

MINIMUM_APP_VERSION = "0.0.0"
ATTESTATION_SECRET  = "678092021"
ATTESTATION_TTL     = 60


class Info:
    def __init__(self):
        self.TitleId:   str = "F179E"
        self.SecretKey: str = "DA5YIXIFBYMPGGCA5CRCA167EUYQWN13QP8TNQKBA4AQIEYPF9"
        self.AppCreds:  str = "OC|1392536220600104|3b28dae713f17a205a012a8396557718"

    def ServerAuthHeaders(self):
        return {"Content-Type": "application/json", "X-SecretKey": self.SecretKey}


settings         = Info()
friend_requests  = {}
friend_usernames = {}
friend_presence  = {}


# ── HELPERS ───────────────────────────────────────────────────────────────────

def log_to_discord(message, webhook_url=DISCORD_WEBHOOK_URL):
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"content": message[:2000]}, timeout=5)
    except Exception as e:
        print(f"Discord log failed: {e}")


def get_username_from_playfab(playfab_id):
    url = f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo"
    try:
        resp = requests.post(url, json={"PlayFabId": playfab_id},
                             headers=settings.ServerAuthHeaders(), timeout=5)
        resp.raise_for_status()
        username = (resp.json().get("data", {})
                               .get("UserInfo", {})
                               .get("TitleInfo", {})
                               .get("DisplayName"))
        if username:
            friend_usernames[playfab_id] = username
            return username
    except Exception as e:
        print(f"GetUserAccountInfo error for {playfab_id}: {e}")
    return f"User_{playfab_id}"


def CheckSessionTicket(ticket):
    try:
        url  = f"https://{settings.TitleId}.playfabapi.com/Server/AuthenticateSessionTicket"
        resp = requests.post(url, json={"SessionTicket": ticket},
                             headers=settings.ServerAuthHeaders(), timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def _vtuple(v: str):
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)

def version_allowed(client_ver: str) -> bool:
    if not client_ver or client_ver.strip() == "":
        return True  # allow empty/missing version
    try:
        return _vtuple(client_ver) >= _vtuple(MINIMUM_APP_VERSION)
    except Exception:
        return True


def make_challenge_token(oculus_id: str) -> str:
    ts      = str(int(time.time()))
    id_hash = hashlib.sha256(oculus_id.encode()).hexdigest()[:16]
    payload = f"{ts}.{id_hash}"
    sig     = hmac.new(ATTESTATION_SECRET.encode(), payload.encode(),
                       hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def verify_challenge_token(token: str, oculus_id: str) -> bool:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        ts_str, id_hash, provided_sig = parts
        if time.time() - int(ts_str) > ATTESTATION_TTL:
            return False
        expected_hash = hashlib.sha256(oculus_id.encode()).hexdigest()[:16]
        if not hmac.compare_digest(id_hash, expected_hash):
            return False
        payload      = f"{ts_str}.{id_hash}"
        expected_sig = hmac.new(ATTESTATION_SECRET.encode(),
                                payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided_sig, expected_sig)
    except Exception:
        return False


def get_bound_hwid(playfab_id: str):
    url = f"https://{settings.TitleId}.playfabapi.com/Server/GetUserData"
    try:
        resp = requests.post(url,
                             json={"PlayFabId": playfab_id, "Keys": ["BoundHWID"]},
                             headers=settings.ServerAuthHeaders(), timeout=5)
        return (resp.json().get("data", {})
                           .get("Data", {})
                           .get("BoundHWID", {})
                           .get("Value"))
    except Exception:
        return None

def set_bound_hwid(playfab_id: str, hwid_hash: str):
    url = f"https://{settings.TitleId}.playfabapi.com/Server/UpdateUserData"
    try:
        requests.post(url,
                      json={"PlayFabId": playfab_id,
                            "Data": {"BoundHWID": hwid_hash},
                            "Permission": "Private"},
                      headers=settings.ServerAuthHeaders(), timeout=5)
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# /api/PlayFabAuthentication
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/PlayFabAuthentication", methods=["POST", "GET"])
def PlayFabAuthy():
    ua = request.headers.get("User-Agent", "")
    print(f"[Auth] User-Agent: {ua}")

    json_data = request.get_json(force=True, silent=True)
    if json_data is None:
        return jsonify({"Message": "Request body is missing or cannot be parsed.",
                        "Error": "BadRequest-BadBody"}), 400

    print(f"[Auth] Body: {json.dumps(json_data, indent=2)}")

    AppId          = json_data.get("AppId")
    AppVersion     = json_data.get("AppVersion", "")
    Nonce          = json_data.get("Nonce")
    OculusId       = json_data.get("OculusId")
    Platform       = json_data.get("Platform")
    HWID           = json_data.get("HWID", "")
    ChallengeToken = json_data.get("ChallengeToken", "")
    # use CustomId from client if provided, otherwise build it
    CustomId       = json_data.get("CustomId", "")

    # ── Version gate ──────────────────────────────────────────────────────────
    if not version_allowed(AppVersion):
        return jsonify({
            "Error":   "OutdatedClient",
            "Message": f"Version {AppVersion} is no longer supported. "
                       f"Update to {MINIMUM_APP_VERSION} or later."
        }), 426

    # ── Field validation ──────────────────────────────────────────────────────
    for field, val, err in [
        ("AppId",    AppId,    "BadRequest-NoAppId"),
        ("Nonce",    Nonce,    "BadRequest-NoNonce"),
        ("OculusId", OculusId, "BadRequest-NoOculusId"),
        ("Platform", Platform, "BadRequest-NoPlatform"),
    ]:
        if not val:
            return jsonify({"Message": f"Missing {field} parameter", "Error": err}), 400

    if AppId != settings.TitleId:
        return jsonify({"Message": "Wrong AppId parameter",
                        "Error": "BadRequest-WrongAppId"}), 400
    if Platform != "Quest":
        return jsonify({"Message": f"Invalid Platform: {Platform}",
                        "Error": "BadRequest-InvalidPlatform"}), 400

    # ── Attestation (inline) ──────────────────────────────────────────────────
    if ChallengeToken:
        if not verify_challenge_token(ChallengeToken, str(OculusId)):
            print(f"[Auth] BLOCKED bad/expired ChallengeToken. OculusId: {OculusId}")
            return jsonify({"Message": "Invalid or expired attestation token.",
                            "Error": "BadRequest-BadAttestation"}), 403
        print(f"[Auth] ChallengeToken verified for OculusId: {OculusId}")
    else:
        generated = make_challenge_token(str(OculusId))
        if not verify_challenge_token(generated, str(OculusId)):
            return jsonify({"Message": "Attestation subsystem error.",
                            "Error": "Internal-AttestationFault"}), 500
        print(f"[Auth] Inline attestation passed for OculusId: {OculusId}")

    # ── CustomId — use client's if provided, else build from OculusId ─────────
    if not CustomId:
        CustomId = f"OCULUSLOCAL{OculusId}"
    print(f"[Auth] CustomId: {CustomId}")

    if GOOD_NONCE_WEBHOOK:
        requests.post(GOOD_NONCE_WEBHOOK, json={"embeds": [{
            "title": "🟢 Valid Login",
            "description": f"```ini\n[Nonce] : {Nonce}\n[CustomId] : {CustomId}```",
            "color": 65280
        }]})

    # ── PlayFab login ─────────────────────────────────────────────────────────
    print(f"[Auth] Logging into PlayFab with CustomId: {CustomId}")
    login_req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId",
        json={"ServerCustomId": CustomId, "CreateAccount": True},
        headers=settings.ServerAuthHeaders()
    )
    print(f"[Auth] PlayFab login ({login_req.status_code}): "
          f"{json.dumps(login_req.json(), indent=2)}")

    if login_req.status_code != 200:
        if login_req.status_code == 403:
            ban_info = login_req.json()
            if ban_info.get("errorCode") == 1002:
                BanDetails        = ban_info.get("errorDetails", {})
                BanReason         = next(iter(BanDetails.keys()), "You are banned.")
                BanTime           = BanDetails.get(BanReason, [])
                BanExpirationTime = BanTime[0] if BanTime else "NO EXPIRATION TIME PROVIDED."
                return jsonify({"BanMessage": BanReason,
                                "BanExpirationTime": BanExpirationTime}), 403
        print(f"[Auth] Unknown PlayFab error: {login_req.status_code}")
        return jsonify({"Error": "Unknown", "Message": "Something Happened"}), login_req.status_code

    data          = login_req.json().get("data", {})
    SessionTicket = data.get("SessionTicket")
    EntityToken   = data.get("EntityToken", {}).get("EntityToken")
    PlayFabId     = data.get("PlayFabId")
    EntityId      = data.get("EntityToken", {}).get("Entity", {}).get("Id")
    EntityType    = data.get("EntityToken", {}).get("Entity", {}).get("Type")

    # ── HWID bind / check (optional) ─────────────────────────────────────────
    if HWID:
        hwid_hash   = hashlib.sha256(HWID.encode()).hexdigest()
        stored_hwid = get_bound_hwid(PlayFabId)

        if stored_hwid is None:
            set_bound_hwid(PlayFabId, hwid_hash)
            print(f"[Auth] HWID bound for {PlayFabId}: {hwid_hash[:12]}…")
        elif not hmac.compare_digest(stored_hwid, hwid_hash):
            print(f"[Auth] HWID MISMATCH for {PlayFabId}")
            log_to_discord(
                f"⚠️ **HWID Mismatch** | `{PlayFabId}` | "
                f"Stored: `{stored_hwid[:16]}…` | Got: `{hwid_hash[:16]}…`"
            )
            return jsonify({
                "BanMessage": "Hardware mismatch detected. Contact support if this is your device.",
                "BanExpirationTime": "Indefinite"
            }), 403
    else:
        print(f"[Auth] No HWID provided, skipping bind check for {PlayFabId}")

    # Link custom ID (best effort)
    requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Client/LinkCustomID",
        json={"CustomId": CustomId, "ForceLink": True},
        headers={"Content-Type": "application/json", "X-Authorization": SessionTicket}
    )

    # Account creation timestamp
    ts_req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
        json={"PlayFabId": PlayFabId},
        headers=settings.ServerAuthHeaders()
    )
    AccountCreationIsoTimestamp = (
        ts_req.json().get("data", {}).get("UserInfo", {}).get("Created")
    )

    response_body = {
        "SessionTicket":               SessionTicket,
        "EntityToken":                 EntityToken,
        "PlayFabId":                   PlayFabId,
        "EntityId":                    EntityId,
        "EntityType":                  EntityType,
        "AccountCreationIsoTimestamp": AccountCreationIsoTimestamp
    }
    print(f"[Auth] SUCCESS: {json.dumps(response_body, indent=2)}")
    return jsonify(response_body), 200


# ──────────────────────────────────────────────────────────────────────────────
# REMAINING ROUTES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/CachePlayFabId", methods=["POST"])
def CachePlayFabId():
    data          = request.get_json() or {}
    PlayFabId     = data.get("PlayFabId", "null")
    SessionTicket = data.get("SessionTicket", "null")
    Platform      = data.get("Platform", "null")

    if not CheckSessionTicket(SessionTicket):
        return jsonify({"Error": "Invalid Session Ticket", "code": 403, "Result": "false"}), 403
    if PlayFabId not in SessionTicket.split("-")[0]:
        return jsonify({"Error": "Invalid Session Ticket usage.", "code": 403, "Result": "false"}), 403
    if Platform != "Quest":
        return jsonify({"Error": "Invalid Platform.", "code": 403, "Result": "false"}), 403

    return jsonify({"PlayFabId": PlayFabId, "SessionTicket": SessionTicket,
                    "Platform": Platform, "Result": "true"}), 200


@app.route("/api/ConsumeOculusIAP", methods=["POST"])
def consume_oculus_iap():
    rjson   = request.get_json() or {}
    nonce   = rjson.get("nonce")
    user_id = rjson.get("userID")
    sku     = rjson.get("sku")
    response = requests.post(
        url=(f"https://graph.oculus.com/consume_entitlement"
             f"?nonce={nonce}&user_id={user_id}&sku={sku}"
             f"&access_token={settings.AppCreds}"),
        headers={"Content-Type": "application/json"}
    )
    if response.json().get("success"):
        return jsonify({"result": True})
    return jsonify({"error": True})


@app.route("/api/photon", methods=["POST", "GET"])
def severalsAnyUpdatePhotonAuth():
    print(f"[Photon] {request.method} request")
    AuthTicketUrl = f"https://{settings.TitleId}.playfabapi.com/Server/AuthenticateSessionTicket"
    VALID_APPS    = [settings.TitleId, "35D50"]

    if request.method == "GET":
        PlayerId = request.args.get("username")
        token    = request.args.get("token")
        if not PlayerId or not token:
            return jsonify({"resultCode": 3, "message": "Failed to parse token",
                            "userId": None, "nickname": None}), 400
        return jsonify({"resultCode": 1, "message": f"User: {PlayerId} Was Authed.",
                        "username": PlayerId, "token": token}), 200

    newData    = request.get_json(force=True, silent=True) or {}
    AppId      = newData.get("AppId")
    AppVersion = newData.get("AppVersion")
    Ticket     = newData.get("Ticket")
    Token      = newData.get("Token")
    Nonce      = newData.get("Nonce")
    Platform   = newData.get("Platform")

    print(json.dumps(newData, indent=2))

    if AppId not in VALID_APPS:
        return jsonify({"ResultCode": 2, "Message": "Invalid AppId",
                        "Error": "BadRequest-WrongAppId"}), 403
    if Platform != "Quest":
        return jsonify({"ResultCode": 3, "Message": "Platform Must Be Quest",
                        "Error": "BadRequest-BadPlatform"}), 403

    AuthReq = requests.post(url=AuthTicketUrl, json={"SessionTicket": Ticket},
                            headers=settings.ServerAuthHeaders())
    if AuthReq.status_code != 200:
        return jsonify({"ResultCode": 2, "Message": "Invalid SessionTicket",
                        "Error": "BadRequest-BadSessionTicket"}), 403

    getdata  = AuthReq.json().get("data", {}).get("UserInfo", {})
    UserId   = getdata.get("PlayFabId")
    CustomId = getdata.get("CustomIdInfo", {}).get("CustomId", "")

    if "OCULUS" not in CustomId:
        return jsonify({"ResultCode": 3, "Message": "Invalid CustomId format",
                        "Error": "BadRequest-BadCustomId"}), 403

    OrgScopedCustomId = CustomId.split("OCULUS")[1]
    GetOculusIdReq    = requests.get(
        url=f"https://graph.oculus.com/{OrgScopedCustomId}?access_token={settings.AppCreds}",
        headers={"Content-Type": "application/json"}
    )
    if "error" in GetOculusIdReq.json():
        return jsonify({"ResultCode": 3, "Message": "Failed OrgScope check",
                        "Error": "BadRequest-InvalidOrgScopeId"}), 403

    if not UserId or len(UserId) != 16:
        return jsonify({"ResultCode": 3, "Message": "Bad UserId",
                        "Error": "BadRequest-BadUserId"}), 403

    OculusId       = GetOculusIdReq.json().get("id")
    VerifyNonceReq = requests.post(
        url="https://graph.oculus.com/user_nonce_validate",
        json={"access_token": settings.AppCreds, "nonce": Nonce, "user_id": str(OculusId)},
        headers={"Content-Type": "application/json"}
    )
    nonce_data = VerifyNonceReq.json()
    print(nonce_data)

    if VerifyNonceReq.status_code != 200 or "is_valid" not in nonce_data:
        return jsonify({"ResultCode": 1, "Message": "Failed Nonce Verification",
                        "Error": "BadRequest-InvalidNonce"}), 403

    return jsonify({
        "ResultCode": 1, "Message": "Yay Servers Work Ig",
        "AppId": AppId, "AppVersion": AppVersion, "Nonce": Nonce,
        "OculusId": OculusId, "Ticket": Ticket, "Token": Token, "UserId": UserId
    }), 200


@app.route("/", methods=["POST", "GET"])
def main():
    if request.method != "POST":
        return "", 404
    return "", 200

@app.route("/api/ReturnQueueStats", methods=["POST"])
def ReturnQueueStats():
    rjson = request.get_json() or {}
    return jsonify({"QueueName": rjson.get("queueName"), "PlayerCount": -1}), 200

@app.route("/api/CheckForBadName", methods=["POST"])
def CheckForBadName():
    return jsonify({"result": 0, "banLength": -1}), 200

@app.route("/api/GetAcceptedAgreements", methods=["POST"])
def GetAcceptedAgreements():
    rjson = request.get_json() or {}
    return jsonify({"TOS": rjson.get("TOS", "11.05.22.2"),
                    "PrivacyPolicy": rjson.get("PrivacyPolicy", "2024.03.07")}), 200

@app.route("/api/SubmitAcceptedAgreements", methods=["POST"])
def SubmitAcceptedAgreements():
    return "Agreements submitted successfully", 200

@app.route("/api/GetUserAge", methods=["POST"])
def GetUserAge():
    return jsonify(-1), 200

@app.route("/api/GetQuestStatus", methods=["POST"])
def get_quest_status_norm():
    daily  = {"quest1": random.randint(5, 20), "quest2": random.randint(5, 20)}
    weekly = {1: random.randint(10, 50), 2: random.randint(10, 50)}
    total  = random.randint(100, 500)
    wtotal = min(sum(daily.values()) + sum(weekly.values()), 100)
    return jsonify({"result": {"dailyPoints": daily, "weeklyPoints": weekly,
                               "userPointsTotal": total, "weeklyPointsTotal": wtotal}})

@app.route("/api/SetQuestComplete", methods=["POST", "GET"])
def setwestcompleter():
    daily  = {"quest1": random.randint(5, 20), "quest2": random.randint(5, 20)}
    weekly = {1: random.randint(10, 50), 2: random.randint(10, 50)}
    total  = random.randint(100, 500)
    wtotal = min(sum(daily.values()) + sum(weekly.values()), 100)
    return jsonify({"result": {"dailyPoints": daily, "weeklyPoints": weekly,
                               "userPointsTotal": total, "weeklyPointsTotal": wtotal}})

@app.route('/api/TitleData', methods=['POST', 'GET'])
def titledata():
    return jsonify({
        "AutoMuteCheckedHours": {"hours": 169},
        "AutoName_Adverbs": ["Cool","Fine","Bald","Bold","Half","Only","Calm","Fab","Ice","Mad","Rad","Big","New","Old","Shy"],
        "AutoName_Nouns": ["Gorilla","Chicken","Darling","Sloth","King","Queen","Royal","Major","Actor","Agent","Elder","Honey","Nurse","Doctor","Rebel","Shape","Ally","Driver","Deputy"],
        "CreditsData": [
            {"Title": "<color=blue>UPDATE MAKERS/PLAYFAB MANAGERS</color>",
             "Entries": ["S4EEPY (UPDATE MAKER/PLAYFAB MANAGER)", "several & several (OWNER/PLAYFAB MANAGER)", "several & several (OWNER)"]},
            {"Title": "<color=yellow>CREDITS TO</color>", "Entries": ["several","several","several","","",""]},
            {"Title": "<color=red>GAY FELLAS</color>", "Entries": ["several"]}
        ],
        "BundleBoardSign":      "<color=#ff4141>DISCORD.GG/AVIITAGG</color>",
        "BundleKioskButton":    "<color=#ff4141>DISCORD.GG/AVIITAGG</color>",
        "BundleKioskSign":      "<color=#ff4141>DISCORD.GG/AVIITAGG</color>",
        "BundleLargeSign":      "<color=#ff4141>DISCORD.GG/AVIITAGG</color>",
        "EmptyFlashbackText":   "FLOOR TWO NOW OPEN\n FOR BUSINESS\n\nSTILL SEARCHING FOR\nBOX LABELED 2021",
        "EnableCustomAuthentication": True,
        "GorillanalyticsChance": 4320,
        "LatestPrivacyPolicyVersion": "2024.09.20",
        "LatestTOSVersion":     "2024.09.20",
        "MOTD": ("<color=#00fbff>[ WELCOME TO CYANTAG! ]</color>\n"
                 "<color=#ff00ff>BOOST THE DISCORD SERVER FOR EVERY COSMETIC! discord.gg/ZAEjuCTcR</color>\n"
                 "<color=#77ff00>CREDITS: LICENSE FOR THE BACKEND</color>\n"
                 "<color=red>HELPERS: AVII several MOSES</color>\n"
                 "<color=magenta>ONLY OWNERS: CYANVR, LICENSE</color>\n"
                 "<color=yellow>BELOW 55 HZ IS BANNABLE AND 45 FPS OR BELOW IS BANNABLE, SWAP 2 IS HIGHEST PREDICTIONS AND 70 HIGHEST PREDS</color>"),
        "SeasonalStoreBoardSign": "<color=yellow>RATE THE GAME 5 STARS! little bible verse Romans 10:9  If you declare with your mouth, “Jesus is Lord,” and believe in your heart that God raised him from the dead, you will be saved.</color>\n\n<color=aqua>DISCORD.GG/AVIITAGG",
        "TOS_2024.09.20":         "DISCORD.GG/ZAEjuCTcR",
        "TOBAlreadyOwnCompTxt":   "DISCORD.GG/ZAEjuCTcR",
        "TOBAlreadyOwnPurchaseBundle": "DISCORD.GG/ZAEjuCTcR",
        "TOBDefCompTxt":          "DISCORD.GG/ZAEjuCTcRl",
        "TOBDefPurchaseBtnDefTxt": "DISCORD.GG/ZAEjuCTcR",
        "UseLegacyIAP": False
    })


@app.route("/api/RequestFriend", methods=["POST"])
def add_fwen():
    fwen          = request.get_json() or {}
    id            = fwen.get("PlayFabId")
    their_link_id = fwen.get("FriendFriendLinkId")
    if id and their_link_id:
        friend_requests.setdefault(id, set()).add(their_link_id)
        friend_requests.setdefault(their_link_id, set()).add(id)
    return jsonify({"success": True, "message": "Friend request sent.",
                    "PlayFabId": id, "FriendFriendLinkId": their_link_id})

@app.route("/api/GetFriendsV2", methods=["POST"])
def get_fwens_v2():
    fwen = request.get_json() or {}
    id   = fwen.get("PlayFabId")
    if not id or id not in friend_requests:
        return jsonify({"result": {"Friends": [], "myPrivacyState": 0},
                        "PlayFabId": id, "PlayFabTicket": fwen.get("PlayFabTicket")}), 200
    friends_list = []
    for friend_id in friend_requests[id]:
        username      = friend_usernames.get(friend_id) or get_username_from_playfab(friend_id)
        presence_info = friend_presence.get(friend_id, {
            "Zone": fwen.get("Zone"), "RoomId": fwen.get("RoomId"),
            "Region": fwen.get("Region"), "IsPublic": fwen.get("IsPublic")
        })
        friends_list.append({
            "Presence": {"FriendLinkId": friend_id, "UserName": username, **presence_info},
            "Created": "2025-03-21T08:46:01.713"
        })
    return jsonify({"result": {"Friends": friends_list, "myPrivacyState": 1},
                    "PlayFabId": id, "PlayFabTicket": fwen.get("PlayFabTicket")}), 200

@app.route("/api/RemoveFriend", methods=["POST"])
def remove_fren():
    r             = request.get_json() or {}
    pf_id         = r.get("PlayFabId")
    their_fren_id = r.get("FriendFriendLinkId")
    if pf_id in friend_requests:
        friend_requests[pf_id].discard(their_fren_id)
    if their_fren_id in friend_requests:
        friend_requests[their_fren_id].discard(pf_id)
    return jsonify({"success": True, "message": "Friend removed.",
                    "PlayFabId": pf_id, "FriendFriendLinkId": their_fren_id})

@app.route("/api/SetPrivacyState", methods=["POST"])
def set_privacy_state():
    return jsonify({"StatusCode": 200, "Error": None})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
