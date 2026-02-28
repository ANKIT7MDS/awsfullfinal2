"""
EventLens Political Forms API — Lambda Patch
Function: eventlens-political-forms-api
 
इस file में सिर्फ नए/updated actions हैं।
Existing lambda_handler के if/elif chain में ये actions ADD करो।
Table: political_admin_config  (PK: collection_id, SK: config_type)
S3 Bucket: selfie-project-photos-anu-25092025
S3 Prefix: political/{cid}/admin/assets/
"""

import os, json, uuid, boto3, hmac, hashlib, time
from datetime import datetime, timezone
from decimal import Decimal
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# ── Env vars (already in Lambda) ──────────────────────────────────────────────
S3_BUCKET       = os.environ.get("S3_BUCKET", "selfie-project-photos-anu-25092025")
ADMIN_PREFIX    = os.environ.get("ADMIN_ASSET_PREFIX", "political/admin-assets/")
TABLE_CFG       = os.environ.get("TABLE_ADMIN_CONFIG", "political_admin_config")
LINK_SECRET     = os.environ.get("POLITICAL_LINK_SECRET", "")

dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
s3       = boto3.client("s3",         region_name="ap-south-1")

# ──────────────────────────────────────────────────────────────────────────────
# HELPER: verify admin JWT / political_admin claim
# ──────────────────────────────────────────────────────────────────────────────
def _require_admin(event):
    """
    Raise PermissionError if caller is not authenticated admin.
    API Gateway Cognito Authorizer already validates the JWT;
    claims arrive in event['requestContext']['authorizer']['claims'].
    For /political/forms route (Cognito-protected) this is sufficient.
    """
    try:
        claims = (
            event.get("requestContext", {})
                 .get("authorizer", {})
                 .get("claims", {})
        )
        groups = claims.get("cognito:groups", "")
        email  = claims.get("email", "")
        is_admin = (
            "political_admin" in str(groups)
            or "admin"        in str(groups).lower()
            or email in ["anusonimds@gmail.com"]
        )
        if not is_admin:
            raise PermissionError("Admin access required")
    except PermissionError:
        raise
    except Exception:
        pass  # If claims not available, allow (route-level auth handles it)


# ──────────────────────────────────────────────────────────────────────────────
# ACTION: admin_get_config
# ──────────────────────────────────────────────────────────────────────────────
def handle_admin_get_config(payload, event):
    """
    GET branding/programs/levels config for a collection.
    Payload: { collection_id, config_type? }
    Returns: { config: {...}, settings: {...} }
    """
    cid         = str(payload.get("collection_id") or payload.get("cid") or "").strip()
    config_type = str(payload.get("config_type") or "political_forms").strip()

    if not cid:
        return {"statusCode": 400, "body": json.dumps({"message": "collection_id required"})}

    table = dynamodb.Table(TABLE_CFG)
    try:
        resp = table.get_item(Key={"collection_id": cid, "config_type": config_type})
    except ClientError as e:
        return {"statusCode": 500, "body": json.dumps({"message": str(e)})}

    item = resp.get("Item") or {}
    # settings field holds the actual config object
    settings = _ddb_to_python(item.get("settings") or item.get("config") or {})

    # Regenerate presigned URLs for any S3 keys stored in config
    settings = _refresh_presigned_urls(settings, cid)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "config":   settings,
            "settings": settings,
            "collection_id": cid,
            "config_type": config_type
        })
    }


# ──────────────────────────────────────────────────────────────────────────────
# ACTION: admin_save_config  (also aliased as admin_save_settings)
# ──────────────────────────────────────────────────────────────────────────────
def handle_admin_save_config(payload, event):
    """
    SAVE full branding config for a collection.
    Payload: { collection_id, config_type?, config?, settings? }
    """
    _require_admin(event)

    cid         = str(payload.get("collection_id") or payload.get("cid") or "").strip()
    config_type = str(payload.get("config_type") or "political_forms").strip()
    cfg         = payload.get("config") or payload.get("settings") or {}

    if not cid:
        return {"statusCode": 400, "body": json.dumps({"message": "collection_id required"})}
    if not isinstance(cfg, dict):
        return {"statusCode": 400, "body": json.dumps({"message": "config must be an object"})}

    now_iso = datetime.now(timezone.utc).isoformat()
    now_ms  = str(int(time.time() * 1000))

    # Inject timestamps inside settings
    cfg["updated_at_iso"] = now_iso
    cfg["updated_at_ms"]  = now_ms

    table = dynamodb.Table(TABLE_CFG)
    try:
        table.put_item(Item={
            "collection_id": cid,
            "config_type":   config_type,
            "settings":      _python_to_ddb_safe(cfg),
            "updated_at":    now_iso
        })
    except ClientError as e:
        return {"statusCode": 500, "body": json.dumps({"message": str(e)})}

    return {
        "statusCode": 200,
        "body": json.dumps({"success": True, "updated_at": now_iso})
    }


# ──────────────────────────────────────────────────────────────────────────────
# ACTION: public_get_config  (called by public forms via token)
# ──────────────────────────────────────────────────────────────────────────────
def handle_public_get_config(payload):
    """
    Public forms (visitor, attendance etc.) call this with their token.
    Verifies token, extracts cid, returns config.
    Payload: { token, form_type? }
    """
    token     = str(payload.get("token") or "").strip()
    form_type = str(payload.get("form_type") or "").strip()
    cid       = str(payload.get("collection_id") or "").strip()

    # Extract cid from token if not directly given
    if token and not cid:
        cid = _cid_from_token(token)

    if not cid:
        return {"statusCode": 400, "body": json.dumps({"message": "token or collection_id required"})}

    table = dynamodb.Table(TABLE_CFG)
    try:
        resp = table.get_item(Key={"collection_id": cid, "config_type": "political_forms"})
    except ClientError as e:
        return {"statusCode": 500, "body": json.dumps({"message": str(e)})}

    item     = resp.get("Item") or {}
    settings = _ddb_to_python(item.get("settings") or item.get("config") or {})
    settings = _refresh_presigned_urls(settings, cid)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "config":        settings,
            "settings":      settings,
            "form_type":     form_type,
            "collection_id": cid
        })
    }


# ──────────────────────────────────────────────────────────────────────────────
# ACTION: admin_init_asset_upload
# Returns presigned PUT URL for logo/header/background upload
# ──────────────────────────────────────────────────────────────────────────────
def handle_admin_init_asset_upload(payload, event):
    """
    Payload: { collection_id, file_name, mime_type, asset_kind? }
    Returns: { upload_url, s3_key, get_url }
    """
    _require_admin(event)

    cid       = str(payload.get("collection_id") or "").strip()
    file_name = str(payload.get("file_name") or "asset.jpg").strip()
    mime      = str(payload.get("mime_type") or "image/jpeg").strip()

    if not cid:
        return {"statusCode": 400, "body": json.dumps({"message": "collection_id required"})}

    # Build S3 key
    ext = _ext_from_mime(mime)
    uid = uuid.uuid4().hex
    s3_key = f"political/{cid}/admin/assets/{uid}.{ext}"

    try:
        upload_url = s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket":      S3_BUCKET,
                "Key":         s3_key,
                "ContentType": mime
            },
            ExpiresIn=900  # 15 min
        )
        get_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": s3_key},
            ExpiresIn=3600
        )
    except ClientError as e:
        return {"statusCode": 500, "body": json.dumps({"message": str(e)})}

    return {
        "statusCode": 200,
        "body": json.dumps({
            "upload_url": upload_url,
            "s3_key":     s3_key,
            "get_url":    get_url
        })
    }


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: Refresh presigned URLs in config tree
# ──────────────────────────────────────────────────────────────────────────────
def _refresh_presigned_urls(obj, cid, expiry=3600):
    """Walk config dict, find any s3_key fields, regenerate presigned URLs."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("logo_key", "header_key", "background_key") and isinstance(v, str) and v:
                out[k] = v
                url_key = k.replace("_key", "_url")
                try:
                    out[url_key] = s3.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": S3_BUCKET, "Key": v},
                        ExpiresIn=expiry
                    )
                except Exception:
                    out[url_key] = ""
            elif k == "key" and isinstance(v, str) and v.startswith("political/"):
                out[k] = v
                try:
                    out["url"] = s3.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": S3_BUCKET, "Key": v},
                        ExpiresIn=expiry
                    )
                except Exception:
                    out["url"] = obj.get("url", "")
            else:
                out[k] = _refresh_presigned_urls(v, cid, expiry)
        return out
    elif isinstance(obj, list):
        return [_refresh_presigned_urls(i, cid, expiry) for i in obj]
    return obj


def _cid_from_token(token):
    """Extract collection_id from HMAC-signed token (same logic as generate_form_link)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return ""
        import base64
        payload_b64 = parts[1]
        # add padding
        payload_b64 += "=" * (-len(payload_b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload_b64))
        return str(data.get("cid") or data.get("collection_id") or "")
    except Exception:
        return ""


def _ext_from_mime(mime):
    return {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp",
            "image/gif": "gif"}.get(mime.lower(), "jpg")


def _ddb_to_python(obj):
    """Convert DynamoDB Decimal to float/int for JSON serialization."""
    if isinstance(obj, dict):
        return {k: _ddb_to_python(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_ddb_to_python(i) for i in obj]
    if isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    return obj


def _python_to_ddb_safe(obj):
    """Ensure floats become Decimal for DynamoDB."""
    if isinstance(obj, dict):
        return {k: _python_to_ddb_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_python_to_ddb_safe(i) for i in obj]
    if isinstance(obj, float):
        return Decimal(str(obj))
    return obj


# ──────────────────────────────────────────────────────────────────────────────
# ROUTING — add these lines to your existing lambda_handler if/elif chain
# ──────────────────────────────────────────────────────────────────────────────
"""
EXISTING lambda_handler में यह block ADD करो:

    elif action in ("admin_get_config", "admin_get_settings"):
        return handle_admin_get_config(payload, event)

    elif action in ("admin_save_config", "admin_save_settings"):
        return handle_admin_save_config(payload, event)

    elif action == "public_get_config":
        return handle_public_get_config(payload)

    elif action == "admin_init_asset_upload":
        return handle_admin_init_asset_upload(payload, event)
"""


# ──────────────────────────────────────────────────────────────────────────────
# COMPLETE lambda_handler TEMPLATE (अगर पूरी file replace करनी हो)
# ──────────────────────────────────────────────────────────────────────────────
def lambda_handler(event, context):
    CORS_HEADERS = {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Content-Type":                 "application/json"
    }

    if event.get("httpMethod") == "OPTIONS" or event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": "{}"}

    try:
        body    = json.loads(event.get("body") or "{}")
        action  = str(body.get("action") or "").strip()
        payload = body.get("payload") or {}

        # ── Config actions ─────────────────────────────────────────────────────
        if action in ("admin_get_config", "admin_get_settings"):
            result = handle_admin_get_config(payload, event)

        elif action in ("admin_save_config", "admin_save_settings"):
            result = handle_admin_save_config(payload, event)

        elif action == "public_get_config":
            result = handle_public_get_config(payload)

        elif action == "admin_init_asset_upload":
            result = handle_admin_init_asset_upload(payload, event)

        # ── Delegate to existing handlers ──────────────────────────────────────
        else:
            # Import your existing handler modules here
            # from political_forms import forms_handler
            # result = forms_handler(action, payload, event)
            result = {"statusCode": 404, "body": json.dumps({"message": f"Unknown action: {action}"})}

        # Ensure CORS headers on all responses
        if isinstance(result, dict):
            result.setdefault("headers", {})
            result["headers"].update(CORS_HEADERS)
        return result

    except PermissionError as e:
        return {"statusCode": 403, "headers": CORS_HEADERS, "body": json.dumps({"message": str(e)})}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"statusCode": 500, "headers": CORS_HEADERS, "body": json.dumps({"message": str(e)})}
