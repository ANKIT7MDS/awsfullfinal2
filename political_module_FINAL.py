# EventLens Political Module - Unified Lambda (forms + search)
# Runtime: python3.12
# Handlers:
#   - political_module.forms_handler
#   - political_module.search_handler
#
# HYBRID v2 FIX:
# - per_collection: choose match that exists in DDB for same CID (prevents timeline shrinking to 1 entry)
# - expand face_ids with rek.search_faces threshold 90
# - finalize: try match existing faces with threshold 90 before indexing (prevents new face_id for same person)
#
# ADMIN v1 ADDITIONS (non-breaking):
# - DynamoDB table for per-collection admin settings (branding, program lists, fixed level)
# - Actions: admin_get_settings, admin_save_settings (alias: save_admin_config), admin_init_asset_upload
# - Aliases: admin_list_entries -> admin_list
# - Public helper: public_get_settings (token-based) for forms to fetch branding/program options safely
#
# PATCH v3 (this file):
# - Fix DynamoDB key schema for TABLE_ADMIN_CONFIG: PK=collection_id, SK=config_type
# - Add aliases expected by UI: public_get_config, admin_get_config, admin_save_config
# - Make public_get_config/settings accept cid passed directly (for admin preview) even if token invalid/missing
# - Also try to extract cid from API querystring/header as last resort
# - Support POLITICAL_FINALIZE_SECRET env var (if present) alongside POLITICAL_LINK_SECRET/POLITICAL_API_SECRET
#
# PERF v1 (this version) — NO LOGIC CHANGES, only faster:
# - _faces_batch_get(): NEW helper — BatchGetItem replaces N individual _faces_get() calls
# - _pick_best_match_for_cid(): uses _faces_batch_get() instead of loop of _faces_get()
# - _enrich_events_with_labels(): uses _faces_batch_get() instead of loop of _faces_get()
# - action_public_search(): removed duplicate _group_timeline_by_event() call (was called twice, same result)
# - _action_build_search_response(): same duplicate removal
# All other logic, return values, field names — UNCHANGED
#
import os
import json
import time
import uuid
import base64
import hmac
import hashlib
import re
import copy
from decimal import Decimal
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List, Set

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "ap-south-1"

S3_BUCKET = os.environ.get("S3_BUCKET", "")
S3_PREFIX = os.environ.get("S3_PREFIX", "political/")

REK_COLLECTION = os.environ.get("REK_COLLECTION", "")
REK_COLLECTION_MODE = (os.environ.get("REK_COLLECTION_MODE", "per_collection") or "single").strip().lower()

TABLE_FORMS = os.environ.get("TABLE_FORMS", "political-forms")
TABLE_PHOTOS = os.environ.get("TABLE_PHOTOS", "political-photos")
TABLE_FACES = os.environ.get("TABLE_FACES", "political-faces")
TABLE_ADMIN_CONFIG = os.environ.get("TABLE_ADMIN_CONFIG", "political_admin_config")

POLITICAL_LINK_SECRET = os.environ.get("POLITICAL_LINK_SECRET", "")
POLITICAL_API_SECRET = os.environ.get("POLITICAL_API_SECRET", "")
POLITICAL_FINALIZE_SECRET = os.environ.get("POLITICAL_FINALIZE_SECRET", "")

DEFAULT_ADMIN_CONFIG_TYPE = os.environ.get("POLITICAL_ADMIN_CONFIG_TYPE", "political_forms")

s3 = boto3.client("s3", region_name=AWS_REGION)
rek = boto3.client("rekognition", region_name=AWS_REGION)
ddb = boto3.resource("dynamodb", region_name=AWS_REGION)

forms_table = ddb.Table(TABLE_FORMS)
photos_table = ddb.Table(TABLE_PHOTOS)
faces_table = ddb.Table(TABLE_FACES)
admin_config_table = ddb.Table(TABLE_ADMIN_CONFIG)

_ddb_client = boto3.client("dynamodb", region_name=AWS_REGION)
_deserializer = boto3.dynamodb.types.TypeDeserializer()

DEBUG_LOGS = (os.environ.get("DEBUG_LOGS", "1").strip().lower() not in ("0","false","no","off"))

def _req_id(event):
    try:
        rc = event.get("requestContext") or {}
        rid = rc.get("requestId")
        if isinstance(rid, str) and rid:
            return rid
        rid2 = rc.get("requestId") or (rc.get("http") or {}).get("requestId")
        if isinstance(rid2, str) and rid2:
            return rid2
    except Exception:
        pass
    return ""

def _log(event, stage, **fields):
    if not DEBUG_LOGS:
        return
    try:
        base = {"ts": _now_iso(), "stage": stage, "rid": _req_id(event) if isinstance(event, dict) else ""}
        base.update({k: v for k, v in fields.items() if v is not None})
        print(json.dumps(base, ensure_ascii=False, default=str))
    except Exception:
        try:
            print("LOG_FAIL", stage)
        except Exception:
            pass

def _now_ms():
    return int(time.time() * 1000)

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _json_load(s):
    if isinstance(s, (dict, list)):
        return s
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}

def _jsonable(obj):
    if isinstance(obj, Decimal):
        try:
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        except Exception:
            return float(obj)
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj

def _resp(status, body, headers=None):
    h = {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "*",
        "access-control-allow-methods": "*",
    }
    if headers:
        h.update(headers)
    return {"statusCode": status, "headers": h, "body": json.dumps(body, ensure_ascii=False, default=str)}

def _b64url(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _b64url_decode(s):
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _sha256_hex(s):
    try:
        return hashlib.sha256((s or "").encode("utf-8")).hexdigest()
    except Exception:
        return ""

def _token_secret():
    return (POLITICAL_LINK_SECRET or POLITICAL_FINALIZE_SECRET or POLITICAL_API_SECRET or "MISSING_SECRET").strip()

def _sign_token(payload, secret, exp_seconds=3600):
    if not secret:
        secret = "MISSING_SECRET"
    payload = dict(payload)
    payload["exp"] = time.time() + exp_seconds
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64url(raw)}.{_b64url(sig)}"

def _verify_token(token, secret):
    try:
        if not token or "." not in token:
            return False, {}, "missing token"
        if not secret:
            secret = "MISSING_SECRET"
        a, b = token.split(".", 1)
        raw = _b64url_decode(a)
        sig = _b64url_decode(b)
        expect = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return False, {}, "bad signature"
        payload = json.loads(raw.decode("utf-8"))
        if float(payload.get("exp", 0)) < time.time():
            return False, {}, "expired"
        return True, payload, ""
    except Exception as e:
        return False, {}, f"token error: {e}"

def _try_decode_unverified_jwt(token):
    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        raw = _b64url_decode(payload_b64)
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}

def _ns_photo_hash(cid, raw_hash):
    cid = (cid or "").strip()
    raw_hash = (raw_hash or "").strip()
    if not raw_hash:
        return ""
    if raw_hash.startswith("cid:"):
        return raw_hash
    h = hashlib.sha256(f"{cid}#{raw_hash}".encode("utf-8")).hexdigest()
    return h

def _ext_from_filename(name):
    name = (name or "").strip()
    if "." in name:
        return name.rsplit(".", 1)[-1].lower()[:10]
    return "jpg"

def _is_per_collection_mode():
    return REK_COLLECTION_MODE in ("per_collection", "per-collection", "per_cid", "cid", "percid")

def _primary_rek_collection_for(cid):
    cid = (cid or "").strip()
    if _is_per_collection_mode():
        return cid or (REK_COLLECTION or "")
    return (REK_COLLECTION or cid).strip()

def _global_rek_collection():
    return (REK_COLLECTION or "").strip()

def _is_public_path(event):
    path = (event.get("rawPath") or event.get("path") or "").lower()
    if "/political/public/" in path:
        return True
    p2 = ((event.get("requestContext") or {}).get("http") or {}).get("path") or ""
    if "/political/public/" in str(p2).lower():
        return True
    return False

def _extract_cid_from_event(event):
    try:
        q = event.get("queryStringParameters") or {}
        if isinstance(q, dict):
            for k in ("collection_id", "cid", "collectionId"):
                v = q.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        raw_qs = event.get("rawQueryString") or ""
        if isinstance(raw_qs, str) and raw_qs.strip():
            parsed = urllib.parse.parse_qs(raw_qs, keep_blank_values=True)
            for k in ("collection_id", "cid", "collectionId"):
                arr = parsed.get(k)
                if arr and isinstance(arr, list) and isinstance(arr[0], str) and arr[0].strip():
                    return arr[0].strip()
        h = event.get("headers") or {}
        if isinstance(h, dict):
            for k in ("x-cid", "x-collection-id", "X-Cid", "X-Collection-Id"):
                v = h.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    except Exception:
        pass
    return ""

# ------------------- DynamoDB helpers -------------------

def _photos_get_by_hash(photo_hash):
    if not photo_hash:
        return None
    try:
        return photos_table.get_item(Key={"photo_hash": photo_hash}).get("Item")
    except Exception:
        return None

def _photos_put_if_new(photo_hash, item):
    try:
        photos_table.put_item(
            Item={"photo_hash": photo_hash, **item},
            ConditionExpression="attribute_not_exists(photo_hash)"
        )
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise

def _photos_update(photo_hash, updates):
    if not photo_hash or not updates:
        return
    names = {}
    vals = {}
    sets = []
    for k, v in updates.items():
        nk = f"#{k}"
        vk = f":{k}"
        names[nk] = k
        vals[vk] = v
        sets.append(f"{nk}={vk}")
    photos_table.update_item(
        Key={"photo_hash": photo_hash},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )

def _faces_get(face_id):
    try:
        return faces_table.get_item(Key={"face_id": face_id}).get("Item")
    except Exception:
        return None

def _faces_batch_get(face_ids):
    if not face_ids:
        return {}
    seen = set()
    unique_ids = []
    for fid in face_ids:
        if fid and fid not in seen:
            unique_ids.append(fid)
            seen.add(fid)
    if not unique_ids:
        return {}
    result = {}
    for i in range(0, len(unique_ids), 100):
        chunk = unique_ids[i:i + 100]
        try:
            resp = _ddb_client.batch_get_item(
                RequestItems={TABLE_FACES: {"Keys": [{"face_id": {"S": fid}} for fid in chunk]}}
            )
            for raw in (resp.get("Responses") or {}).get(TABLE_FACES, []):
                item = {k: _deserializer.deserialize(v) for k, v in raw.items()}
                fid = item.get("face_id")
                if fid:
                    result[fid] = item
            unprocessed = (resp.get("UnprocessedKeys") or {}).get(TABLE_FACES)
            if unprocessed:
                try:
                    resp2 = _ddb_client.batch_get_item(RequestItems={TABLE_FACES: unprocessed})
                    for raw in (resp2.get("Responses") or {}).get(TABLE_FACES, []):
                        item = {k: _deserializer.deserialize(v) for k, v in raw.items()}
                        fid = item.get("face_id")
                        if fid:
                            result[fid] = item
                except Exception:
                    pass
        except Exception as e:
            print("_faces_batch_get error", {"chunk_start": i, "error": str(e)})
            for fid in chunk:
                item = _faces_get(fid)
                if item:
                    result[fid] = item
    return result

def _faces_upsert(face_id, collection_id, entry_id, s3_key, photo_hash, profile):
    if not face_id:
        return
    now_ms = str(_now_ms())
    now_iso = _now_iso()
    new_name = (profile or {}).get("name") or ""
    new_mobile = (profile or {}).get("mobile") or ""
    existing = {}
    try:
        existing = faces_table.get_item(Key={"face_id": face_id}).get("Item") or {}
    except Exception:
        existing = {}
    name_to_set = new_name if new_name else (existing.get("name") or "")
    mobile_to_set = new_mobile if new_mobile else (existing.get("mobile") or "")
    try:
        faces_table.update_item(
            Key={"face_id": face_id},
            UpdateExpression=(
                "SET #cid=:cid, #updated_at_ms=:u_ms, #updated_at_iso=:u_iso, #name=:name, #mobile=:mobile "
                "ADD #entry_count :one"
            ),
            ExpressionAttributeNames={
                "#cid": "collection_id", "#updated_at_ms": "updated_at_ms",
                "#updated_at_iso": "updated_at_iso", "#name": "name",
                "#mobile": "mobile", "#entry_count": "entry_count",
            },
            ExpressionAttributeValues={
                ":cid": collection_id, ":u_ms": now_ms, ":u_iso": now_iso,
                ":name": name_to_set, ":mobile": mobile_to_set, ":one": 1,
            },
        )
    except Exception:
        pass
    try:
        faces_table.update_item(
            Key={"face_id": face_id},
            UpdateExpression=(
                "SET #entry_ids = list_append(if_not_exists(#entry_ids, :empty), :eid), "
                "#photo_hashes = list_append(if_not_exists(#photo_hashes, :empty), :ph), "
                "#photo_keys = list_append(if_not_exists(#photo_keys, :empty), :pk) "
            ),
            ExpressionAttributeNames={
                "#entry_ids": "entry_ids", "#photo_hashes": "photo_hashes", "#photo_keys": "photo_keys",
            },
            ExpressionAttributeValues={
                ":empty": [], ":eid": [entry_id],
                ":ph": [photo_hash] if photo_hash else [],
                ":pk": [s3_key] if s3_key else [],
            },
        )
    except Exception:
        pass

def _faces_fill_identity(face_id, cid, name="", mobile=""):
    if not face_id:
        return
    name = (name or "").strip()
    mobile = (mobile or "").strip()
    if not (name or mobile):
        return
    try:
        existing = faces_table.get_item(Key={"face_id": face_id}).get("Item") or {}
    except Exception:
        existing = {}
    name_to_set = name if name else (existing.get("name") or "")
    mobile_to_set = mobile if mobile else (existing.get("mobile") or "")
    try:
        faces_table.update_item(
            Key={"face_id": face_id},
            UpdateExpression="SET #cid=:cid, #updated_at_ms=:u_ms, #updated_at_iso=:u_iso, #name=:name, #mobile=:mobile",
            ExpressionAttributeNames={
                "#cid": "collection_id", "#updated_at_ms": "updated_at_ms",
                "#updated_at_iso": "updated_at_iso", "#name": "name", "#mobile": "mobile",
            },
            ExpressionAttributeValues={
                ":cid": cid, ":u_ms": str(_now_ms()), ":u_iso": _now_iso(),
                ":name": name_to_set, ":mobile": mobile_to_set,
            },
        )
    except Exception:
        pass

# ------------------- Rekognition helpers -------------------

def _count_faces_in_s3(bucket, key):
    try:
        if not (bucket and key):
            return 0
        resp = rek.detect_faces(Image={"S3Object": {"Bucket": bucket, "Name": key}}, Attributes=["DEFAULT"])
        return int(len(resp.get("FaceDetails") or []))
    except Exception:
        return 0

def _search_faces_by_image_in_collection(collection_id, bucket, key, threshold, max_faces):
    if not (collection_id and bucket and key):
        return []
    try:
        resp = rek.search_faces_by_image(
            CollectionId=collection_id,
            Image={"S3Object": {"Bucket": bucket, "Name": key}},
            FaceMatchThreshold=float(threshold),
            MaxFaces=int(max_faces),
        )
        return resp.get("FaceMatches") or []
    except Exception as e:
        print("REK search_faces_by_image error", {"collection_id": collection_id, "error": str(e)})
        return []

def _pick_best_match_for_cid(face_matches, cid):
    if not face_matches:
        return None
    fids_ordered = []
    sim_map = {}
    for m in face_matches:
        fid = ((m.get("Face") or {}) or {}).get("FaceId")
        sim = float(m.get("Similarity", 0) or 0)
        if fid and fid not in sim_map:
            fids_ordered.append(fid)
            sim_map[fid] = sim
    if not fids_ordered:
        return None
    face_map = _faces_batch_get(fids_ordered)
    for fid in fids_ordered:
        fi = face_map.get(fid)
        if fi and (fi.get("collection_id") or "") == cid:
            return fid, sim_map[fid]
    return None

def _index_face_from_s3(cid, bucket, key, external_id):
    col = _primary_rek_collection_for(cid)
    if not (col and bucket and key):
        return None
    try:
        resp = rek.index_faces(
            CollectionId=col,
            Image={"S3Object": {"Bucket": bucket, "Name": key}},
            ExternalImageId=(external_id or "")[:255],
            DetectionAttributes=["DEFAULT"],
            MaxFaces=1,
            QualityFilter="AUTO",
        )
        fr = resp.get("FaceRecords") or []
        if not fr:
            return None
        face = fr[0].get("Face") or {}
        return face.get("FaceId")
    except Exception as e:
        print("REK index_faces error", {"collection_id": col, "error": str(e)})
        return None

def _index_faces_from_s3(cid, bucket, key, external_id, max_faces=10, quality_filter="AUTO"):
    col = _primary_rek_collection_for(cid)
    if not (col and bucket and key):
        return []
    try:
        resp = rek.index_faces(
            CollectionId=col,
            Image={"S3Object": {"Bucket": bucket, "Name": key}},
            ExternalImageId=(external_id or "")[:255],
            DetectionAttributes=["DEFAULT"],
            MaxFaces=int(max_faces or 10),
            QualityFilter=str(quality_filter or "AUTO"),
        )
        face_ids = []
        for fr in (resp.get("FaceRecords") or []):
            fid = (fr.get("Face") or {}).get("FaceId")
            if fid:
                face_ids.append(fid)
        seen = set()
        uniq = []
        for fid in face_ids:
            if fid not in seen:
                uniq.append(fid)
                seen.add(fid)
        return uniq
    except Exception as e:
        print("REK index_faces(multi) error", {"cid": cid, "key": key, "error": str(e)})
        return []

def _expand_similar_face_ids(rek_collection_id, face_id, threshold=90.0, max_faces=50):
    if not (rek_collection_id and face_id):
        return [face_id] if face_id else []
    out = [face_id]
    seen = {face_id}
    try:
        resp = rek.search_faces(CollectionId=rek_collection_id, FaceId=face_id, FaceMatchThreshold=float(threshold), MaxFaces=int(max_faces))
        for m in resp.get("FaceMatches") or []:
            fid = ((m.get("Face") or {}) or {}).get("FaceId")
            if fid and fid not in seen:
                out.append(fid)
                seen.add(fid)
    except Exception as e:
        print("REK search_faces error", {"collection_id": rek_collection_id, "error": str(e)})
    return out[:max(1, min(200, max_faces + 1))]

# ------------------- Presign helpers -------------------

def _make_presigned_put(bucket, key, content_type, expires=900):
    return s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": key, "ContentType": content_type or "application/octet-stream"},
        ExpiresIn=expires,
    )

def _presign_get(bucket, key, exp=600):
    try:
        if not (bucket and key):
            return None
        return s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=int(exp))
    except Exception:
        return None

def _entry_s3_key(collection_id, form_type, entry_id, filename):
    ext = _ext_from_filename(filename)
    return f"{S3_PREFIX}{collection_id}/forms/{form_type}/{entry_id}/{uuid.uuid4().hex}.{ext}"

# ------------------- Event helpers -------------------

_DEDUPE_FORMS = set([
    "president_tour_form", "president_tour", "president_tour_form_v2", "president_tour_form_v3",
    "mandal_reporting", "mandal_reporting_form",
])

def _norm_str(v):
    s = str(v or "").strip()
    s = re.sub(r"\s+", " ", s)
    return s

def _pick_first(payload, keys):
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def _compute_event_id(form_type, payload):
    ft = (form_type or "").strip()
    level = _pick_first(payload, ["level", "program_level", "कार्यक्रम_स्तर", "कार्यक्रम_का_स्तर", "programLevel"])
    district = _pick_first(payload, ["district", "जिला"])
    vidhansabha = _pick_first(payload, ["vidhansabha", "विधानसभा"])
    mandal = _pick_first(payload, ["mandal", "मंडल"])
    date = _pick_first(payload, ["date", "दिनांक", "program_date", "कार्यक्रम_दिनांक"])
    place = _pick_first(payload, ["place", "स्थान", "location", "program_place"])
    program_type = _pick_first(payload, ["program_type", "कार्यक्रम_का_प्रकार", "type"])
    program_name = _pick_first(payload, ["program_name", "कार्यक्रम_का_नाम", "name_of_program"])
    slot = _pick_first(payload, ["time", "समय", "session", "slot", "unique_tag", "event_tag"])
    raw = "|".join([
        _norm_str(ft).lower(), _norm_str(level).lower(), _norm_str(district).lower(),
        _norm_str(vidhansabha).lower(), _norm_str(mandal).lower(), _norm_str(date).lower(),
        _norm_str(place).lower(), _norm_str(program_type).lower(), _norm_str(program_name).lower(),
        _norm_str(slot).lower(),
    ]).strip("|")
    if not raw.strip("|"):
        return ""
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

def _group_timeline_by_event(cid, timeline_raw, max_photos_per_event=30):
    groups = {}
    order = []
    for it in (timeline_raw or []):
        ft = (it.get("form_type") or it.get("ft") or "").strip()
        event_id = (it.get("event_id") or "").strip()
        key = ""
        if ft in _DEDUPE_FORMS and event_id:
            key = event_id
        else:
            key = (it.get("entry_id") or "").strip() or event_id or str(uuid.uuid4())
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(it)

    out = []
    for k in order:
        items = groups.get(k) or []
        if not items:
            continue
        items.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
        rep = dict(items[0])
        photo_urls = []
        seen = set()
        for it in items:
            sk = (it.get("s3_key") or "").strip()
            if sk and sk not in seen:
                seen.add(sk)
                u = _presign_get(S3_BUCKET, sk)
                if u:
                    photo_urls.append(u)
            if len(photo_urls) >= max_photos_per_event:
                break
        face_ids_set = set()
        for i in items:
            for fid in (i.get("face_ids") or []):
                if fid:
                    face_ids_set.add(fid)
            if i.get("face_id"):
                face_ids_set.add(i.get("face_id"))
        rep["face_ids"] = list(face_ids_set)[:200]
        rep["group_key"] = k
        rep["group_count"] = len(items)
        rep["photos"] = photo_urls
        rep["entries"] = [{"entry_id": i.get("entry_id"), "s3_key": i.get("s3_key")} for i in items[:50]]
        out.append(rep)
    return out

# ------------------- Forms actions -------------------

def action_public_create_entry(body, event=None):
    ev = event or {}
    token = body.get("token")
    collection_id = ""
    if token:
        ok, tok_data, _ = _verify_token(token, _token_secret())
        if ok:
            collection_id = tok_data.get("collection_id") or tok_data.get("cid") or ""
        else:
            jwt = _try_decode_unverified_jwt(token)
            collection_id = (jwt.get("collection_id") or jwt.get("cid") or "").strip()

    payload = body.get("payload") or {}
    if not collection_id:
        collection_id = body.get("collection_id") or body.get("cid") or payload.get("collection_id") or payload.get("cid") or ""
    if not collection_id:
        return _resp(400, {"message": "missing collection_id"})

    file_name = body.get("file_name") or payload.get("file_name") or ""
    mime_type = body.get("mime_type") or payload.get("mime_type") or ""
    form_type = body.get("form_type") or payload.get("form_type") or payload.get("ft") or "visitor_form"
    no_photo = bool(body.get("no_photo") or payload.get("no_photo"))
    if form_type in ("coordinator_form", "coordinator_entry"):
        no_photo = True

    photo_hash_raw = body.get("sha256") or payload.get("sha256") or ""
    photo_hash = _ns_photo_hash(collection_id, photo_hash_raw) if photo_hash_raw else ""

    if no_photo:
        file_name = ""
        mime_type = ""

    _log(ev, "public_create_entry.start", cid=collection_id, form_type=form_type, photo_hash=photo_hash, file_name=file_name, mime_type=mime_type)

    entry_id = str(uuid.uuid4())
    now_ms = str(_now_ms())
    now_iso = _now_iso()

    duplicate = False
    upload_url = None
    s3_key = _entry_s3_key(collection_id, form_type, entry_id, file_name)

    if no_photo:
        s3_key = ""
        photo_hash = ""
        duplicate = False
        upload_url = None
    else:
        existing_photo = _photos_get_by_hash(photo_hash) if photo_hash else None
        if existing_photo and existing_photo.get("s3_key"):
            if existing_photo.get("collection_id") == collection_id and str(existing_photo.get("s3_key","")).startswith(f"{S3_PREFIX}{collection_id}/"):
                duplicate = True
                s3_key = existing_photo["s3_key"]
            else:
                duplicate = False
        upload_url = None
        if not duplicate:
            upload_url = _make_presigned_put(S3_BUCKET, s3_key, mime_type)

    final_data = payload if isinstance(payload, dict) else {}
    entry_item = {
        "entry_id": entry_id, "collection_id": collection_id, "cid": collection_id,
        "form_type": form_type, "ft": form_type, "file_name": file_name, "mime_type": mime_type,
        "photo_hash": photo_hash, "s3_key": s3_key, "status": "created",
        "duplicate": bool(duplicate), "created_at": now_ms, "created_at_iso": now_iso, "payload": final_data,
    }
    forms_table.put_item(Item=entry_item)

    finalize_token = _sign_token(
        {"v": 2, "entry_id": entry_id, "collection_id": collection_id, "cid": collection_id,
         "form_type": form_type, "ft": form_type, "photo_hash": photo_hash, "s3_key": s3_key},
        _token_secret(), exp_seconds=86400 * 7,
    )
    _log(ev, "public_create_entry.done", cid=collection_id, form_type=form_type, entry_id=entry_id, s3_key=s3_key, duplicate=bool(duplicate))
    return _resp(200, {"entry_id": entry_id, "s3_key": s3_key, "upload_url": upload_url, "duplicate": bool(duplicate), "finalize_token": finalize_token})

def action_public_finalize_entry(body, event=None):
    ev = event or {}
    token = body.get("finalize_token") or body.get("token") or ""
    ok, tok, err = _verify_token(token, _token_secret())
    if not ok:
        return _resp(401, {"message": "Unauthorized", "error": err})

    entry_id = tok.get("entry_id", "")
    cid = tok.get("collection_id") or tok.get("cid") or ""
    form_type = tok.get("form_type") or tok.get("ft") or ""
    s3_key = tok.get("s3_key") or ""
    photo_hash = tok.get("photo_hash") or ""

    _log(ev, "public_finalize_entry.start", cid=cid, form_type=form_type, entry_id=entry_id, s3_key=s3_key, photo_hash=photo_hash)

    if not entry_id:
        return _resp(400, {"message": "missing entry_id"})

    entry = forms_table.get_item(Key={"entry_id": entry_id}).get("Item")
    if not entry:
        return _resp(404, {"message": "entry not found", "entry_id": entry_id})

    p = entry.get("payload") or {}
    profile = {"name": "", "mobile": ""}
    if isinstance(p, dict):
        profile["name"] = p.get("name") or ""
        profile["mobile"] = p.get("mobile") or ""

    event_id = _compute_event_id(form_type, p if isinstance(p, dict) else {})

    face_id = None
    face_ids = []
    dbg_face_count = 0
    dbg_should_index_multi = None
    dbg_indexed_ids = []
    dbg_used_max_faces = None
    dbg_used_quality = None

    allow_multi_face = (form_type in ("president_tour_form", "president_tour", "mandal_reporting", "mandal_reporting_form"))

    if S3_BUCKET and s3_key:
        if allow_multi_face:
            face_count = _count_faces_in_s3(S3_BUCKET, s3_key)
            should_index_multi = (face_count != 1)
            if should_index_multi:
                dbg_used_max_faces = 10
                dbg_used_quality = "AUTO"
                indexed_ids = _index_faces_from_s3(cid, S3_BUCKET, s3_key, external_id=entry_id, max_faces=10, quality_filter="AUTO")
                if not indexed_ids:
                    dbg_used_max_faces = 50
                    dbg_used_quality = "NONE"
                    indexed_ids = _index_faces_from_s3(cid, S3_BUCKET, s3_key, external_id=entry_id, max_faces=50, quality_filter="NONE")
                dbg_indexed_ids = indexed_ids or []
                merged = []
                if face_id:
                    merged.append(face_id)
                if indexed_ids:
                    merged.extend(indexed_ids)
                seen = set()
                face_ids = []
                for fid in merged:
                    if fid and fid not in seen:
                        face_ids.append(fid)
                        seen.add(fid)
                if (not face_id) and face_ids:
                    face_id = face_ids[0]
            else:
                if not face_id:
                    face_id = _index_face_from_s3(cid, S3_BUCKET, s3_key, external_id=entry_id)
                if face_id and not face_ids:
                    face_ids = [face_id]
        else:
            if not face_id:
                face_id = _index_face_from_s3(cid, S3_BUCKET, s3_key, external_id=entry_id)
            if face_id and not face_ids:
                face_ids = [face_id]

    _log(ev, "public_finalize_entry.indexed", cid=cid, form_type=form_type, entry_id=entry_id,
         s3_key=s3_key, face_id=face_id, face_ids=(face_ids or []), face_ids_count=len(face_ids or []),
         detected_faces=dbg_face_count, should_index_multi=dbg_should_index_multi,
         indexed_ids_count=len(dbg_indexed_ids or []), used_max_faces=dbg_used_max_faces, used_quality=dbg_used_quality)

    entry["face_id"] = face_id
    if event_id:
        entry["event_id"] = event_id
    if face_ids:
        entry["face_ids"] = face_ids
    entry["updated_at"] = _now_iso()
    forms_table.put_item(Item={k: v for k, v in entry.items() if v is not None})

    if photo_hash:
        base_item = {
            "collection_id": cid, "s3_key": s3_key, "entry_id": entry_id,
            "form_type": form_type, "event_id": event_id if event_id else "",
            "created_at": entry.get("created_at") or str(_now_ms()),
            "created_at_iso": entry.get("created_at_iso") or _now_iso(),
        }
        try:
            _photos_put_if_new(photo_hash, base_item)
        except Exception:
            pass
        try:
            updates = {"collection_id": cid, "s3_key": s3_key, "event_id": event_id if event_id else ""}
            if face_id:
                updates["face_id"] = face_id
            if face_ids:
                updates["face_ids"] = face_ids
            _photos_update(photo_hash, updates)
        except Exception:
            pass

    if face_ids:
        for fid in face_ids:
            _faces_upsert(fid, cid, entry_id, s3_key, photo_hash, profile)
    elif face_id:
        _faces_upsert(face_id, cid, entry_id, s3_key, photo_hash, profile)

    if profile.get("name") or profile.get("mobile"):
        primary_face = face_id or (face_ids[0] if face_ids else None)
        if primary_face:
            try:
                used_col = _primary_rek_collection_for(cid)
                all_cluster_ids = _expand_similar_face_ids(used_col, primary_face, threshold=85.0, max_faces=200) if used_col else [primary_face]
                for cfid in all_cluster_ids:
                    if cfid and cfid not in (face_ids or []):
                        _faces_fill_identity(cfid, cid, name=profile.get("name", ""), mobile=profile.get("mobile", ""))
                _log(ev, "public_finalize_entry.identity_spread", cid=cid, face_id=primary_face,
                     cluster_size=len(all_cluster_ids), name_set=bool(profile.get("name")))
            except Exception as ex:
                _log(ev, "public_finalize_entry.identity_spread_error", error=str(ex))

    _log(ev, "public_finalize_entry.done", cid=cid, form_type=form_type, entry_id=entry_id,
         face_id=face_id, face_ids_count=len(face_ids or []))
    return _resp(200, {"message": "OK", "entry_id": entry_id, "face_id": face_id, "s3_key": s3_key})

# ------------------- Search -------------------

def _parse_body(event):
    body = event.get("body")
    if not body:
        return {}
    if isinstance(body, dict):
        return body
    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return _json_load(body)

def _extract_photo_keys(face_item):
    keys = []
    if isinstance(face_item.get("photo_keys"), list):
        keys.extend([k for k in face_item["photo_keys"] if isinstance(k, str)])
    return keys[:500]

def _enrich_events_with_labels(events, selected_face_id, ev=None):
    try:
        all_other_face_ids = []
        seen_fids = set()
        for e2 in events:
            for fid in (e2.get("face_ids") or []):
                if fid and fid != selected_face_id and fid not in seen_fids:
                    all_other_face_ids.append(fid)
                    seen_fids.add(fid)
                    if len(all_other_face_ids) >= 300:
                        break
            if len(all_other_face_ids) >= 300:
                break

        batch_result = _faces_batch_get(all_other_face_ids)

        face_meta = {}
        for fid in all_other_face_ids:
            it = batch_result.get(fid)
            if it:
                nm = (it.get("name") or it.get("person_name") or "").strip()
                mob = (it.get("mobile") or "").strip()
                if nm or mob:
                    face_meta[fid] = {"name": nm, "mobile": mob}

        for e2 in events:
            ev_face_ids = [f for f in (e2.get("face_ids") or []) if f and f != selected_face_id]
            ev_face_ids = list(dict.fromkeys(ev_face_ids))
            total_others = len(set(ev_face_ids))
            e2["face_count"] = total_others + 1

            named = []
            for fid in ev_face_ids:
                fm = face_meta.get(fid)
                if fm and fm.get("name") and fm["name"] not in named:
                    named.append(fm["name"])
                if len(named) >= 3:
                    break

            named_count = len([f for f in ev_face_ids if face_meta.get(f, {}).get("name")])
            unnamed_count = max(0, total_others - named_count)

            e2["with_names"] = named
            e2["with_more"] = unnamed_count

            if named:
                suffix = (f" and {unnamed_count} other" if unnamed_count == 1
                          else (f" and {unnamed_count} others" if unnamed_count > 1 else ""))
                e2["with_label"] = "with " + ", ".join(named) + suffix
            elif total_others > 0:
                e2["with_label"] = f"with {total_others} others"
            else:
                e2["with_label"] = ""
    except Exception as ex:
        _log(ev or {}, "enrich_events_error", error=str(ex))

def _format_timeline_item(item):
    payload = item.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}
    return {
        "entry_id": item.get("entry_id"),
        "form_type": item.get("form_type") or item.get("ft"),
        "created_at": item.get("created_at"),
        "created_at_iso": item.get("created_at_iso"),
        "event_id": item.get("event_id") or payload.get("event_id") or "",
        "name": payload.get("name") or "",
        "mobile": payload.get("mobile") or "",
        "district": payload.get("district") or "",
        "vidhansabha": payload.get("vidhansabha") or "",
        "mandal": payload.get("mandal") or "",
        "reason": payload.get("reason") or payload.get("visit_reason") or "",
        "s3_key": item.get("s3_key"),
        "duplicate": bool(item.get("duplicate", False)),
        "data": payload,
    }

def _fetch_timeline(cid, face_ids, days=30):
    face_set = set([f for f in (face_ids or []) if f])
    if not face_set:
        return []

    face_map = _faces_batch_get(list(face_set))

    all_entry_ids = []
    seen_eids = set()
    for fid in face_set:
        fi = face_map.get(fid)
        if not fi:
            continue
        eids = fi.get("entry_ids") or []
        if isinstance(eids, list):
            for eid in eids:
                if eid and eid not in seen_eids:
                    all_entry_ids.append(str(eid))
                    seen_eids.add(eid)

    if all_entry_ids:
        items = []
        for i in range(0, len(all_entry_ids), 100):
            chunk = all_entry_ids[i:i + 100]
            try:
                resp = _ddb_client.batch_get_item(
                    RequestItems={TABLE_FORMS: {"Keys": [{"entry_id": {"S": eid}} for eid in chunk]}}
                )
                for raw in ((resp.get("Responses") or {}).get(TABLE_FORMS) or []):
                    items.append({k: _deserializer.deserialize(v) for k, v in raw.items()})
                unprocessed = (resp.get("UnprocessedKeys") or {}).get(TABLE_FORMS)
                if unprocessed:
                    try:
                        resp2 = _ddb_client.batch_get_item(RequestItems={TABLE_FORMS: unprocessed})
                        for raw in ((resp2.get("Responses") or {}).get(TABLE_FORMS) or []):
                            items.append({k: _deserializer.deserialize(v) for k, v in raw.items()})
                    except Exception:
                        pass
            except Exception:
                pass

        out = []
        for it in items:
            if (it.get("collection_id") or it.get("cid") or "") != cid:
                continue
            out.append(_format_timeline_item(it))
        out.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
        return out

    fallback_items = []
    try:
        last_key = None
        pages = 0
        while pages < 20:
            kwargs = {
                "IndexName": "collection_id-created_at-index",
                "KeyConditionExpression": Key("collection_id").eq(cid),
                "ScanIndexForward": False,
                "Limit": 500,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = forms_table.query(**kwargs)
            for it in (resp.get("Items") or []):
                fid = it.get("face_id")
                item_face_ids = it.get("face_ids") if isinstance(it.get("face_ids"), list) else []
                if fid and fid in face_set:
                    fallback_items.append(_format_timeline_item(it))
                elif item_face_ids:
                    for x in item_face_ids:
                        if isinstance(x, str) and x in face_set:
                            fallback_items.append(_format_timeline_item(it))
                            break
            last_key = resp.get("LastEvaluatedKey")
            pages += 1
            if not last_key:
                break
    except Exception:
        pass

    fallback_items.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    return fallback_items

# ─────────────── Admin Gallery APIs ───────────────

def action_admin_list_faces(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "collection_id required"})
    limit = int(body.get("limit") or 200)
    last_key = body.get("last_key")
    show_unnamed = bool(body.get("show_unnamed", True))
    try:
        filter_exp = boto3.dynamodb.conditions.Attr("collection_id").eq(cid)
        if not show_unnamed:
            filter_exp = filter_exp & boto3.dynamodb.conditions.Attr("name").exists()
        scan_kwargs = {"FilterExpression": filter_exp, "Limit": limit}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = faces_table.scan(**scan_kwargs)
        items = resp.get("Items") or []
        faces_out = []
        for it in items:
            photo_keys = it.get("photo_keys") or []
            thumb_url = ""
            if photo_keys:
                pk = photo_keys[0] if isinstance(photo_keys[0], str) else ""
                if pk:
                    thumb_url = _presign_get(S3_BUCKET, pk, exp=3600)
            faces_out.append({
                "face_id": it.get("face_id", ""),
                "name": (it.get("name") or "").strip(),
                "mobile": (it.get("mobile") or "").strip(),
                "entry_count": int(it.get("entry_count") or 0),
                "thumb_url": thumb_url,
                "photo_key": photo_keys[0] if photo_keys else "",
                "updated_at_iso": it.get("updated_at_iso") or "",
            })
        faces_out.sort(key=lambda x: (0 if x["name"] else 1, -x["entry_count"]))
        return _resp(200, {"message": "OK", "faces": faces_out, "count": len(faces_out), "last_key": resp.get("LastEvaluatedKey")})
    except Exception as ex:
        return _resp(500, {"message": str(ex)})

def action_admin_list_photos(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "collection_id required"})
    limit = min(int(body.get("limit") or 100), 200)
    last_key = body.get("last_key")
    try:
        collected = []
        seen_keys = set()
        cur_key = last_key
        for _page in range(10):
            q = {
                "IndexName": "collection_id-created_at-index",
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("collection_id").eq(cid),
                "ScanIndexForward": False, "Limit": 200,
            }
            if cur_key:
                q["ExclusiveStartKey"] = cur_key
            r = forms_table.query(**q)
            for it in (r.get("Items") or []):
                sk = it.get("s3_key") or ""
                if not sk or sk in seen_keys:
                    continue
                seen_keys.add(sk)
                collected.append(it)
                if len(collected) >= limit:
                    break
            cur_key = r.get("LastEvaluatedKey")
            if len(collected) >= limit or not cur_key:
                break
        next_key = cur_key if len(collected) >= limit else None
        photos_out = []
        for it in collected:
            sk = it.get("s3_key") or ""
            url = _presign_get(S3_BUCKET, sk, exp=3600) or ""
            if not url:
                continue
            p = it.get("payload") or {}
            if not isinstance(p, dict):
                p = {}
            ft = it.get("form_type") or it.get("ft") or ""
            fd = ""
            if ft == "president_tour_form":
                fd = p.get("tour_date") or ""
            elif ft in ("mandal_reporting", "mandal_reporting_form"):
                fd = p.get("report_date") or p.get("event_date") or ""
            elif ft == "party_attendance":
                fd = p.get("attendance_date") or ""
            if not fd:
                fd = p.get("दिनांक") or p.get("date") or ""
            photos_out.append({
                "entry_id": it.get("entry_id") or "", "s3_key": sk, "url": url,
                "form_type": ft, "form_date": fd, "created_at_iso": it.get("created_at_iso") or "",
                "face_id": it.get("face_id") or "", "face_ids": it.get("face_ids") or [],
                "district": p.get("district") or p.get("जिला") or "",
                "program_name": p.get("program_name") or p.get("कार्यक्रम_का_नाम") or "",
            })
        return _resp(200, {"message": "OK", "photos": photos_out, "count": len(photos_out), "last_key": next_key})
    except Exception as ex:
        return _resp(500, {"message": str(ex)})

def action_admin_set_face_name(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    face_id = (body.get("face_id") or "").strip()
    name = (body.get("name") or "").strip()
    mobile = (body.get("mobile") or "").strip()
    spread_cluster = bool(body.get("spread_cluster", True))
    if not (cid and face_id):
        return _resp(400, {"message": "collection_id and face_id required"})
    try:
        _faces_fill_identity(face_id, cid, name=name, mobile=mobile)
        spread_count = 1
        if spread_cluster:
            used_col = _primary_rek_collection_for(cid)
            cluster_ids = _expand_similar_face_ids(used_col, face_id, threshold=85.0, max_faces=200) if used_col else [face_id]
            for cfid in cluster_ids:
                if cfid != face_id:
                    _faces_fill_identity(cfid, cid, name=name, mobile=mobile)
            spread_count = len(cluster_ids)
        return _resp(200, {"message": "OK", "face_id": face_id, "name": name, "mobile": mobile, "spread_count": spread_count})
    except Exception as ex:
        return _resp(500, {"message": str(ex)})

def action_admin_backfill_identities(payload, event=None):
    ev = event or {}
    cid = (payload.get("cid") or payload.get("collection_id") or "").strip()
    if not cid:
        return _resp(400, {"message": "cid required"})
    dry_run = bool(payload.get("dry_run", False))
    limit = int(payload.get("limit") or 500)
    form_types_to_scan = payload.get("form_types") or ["visitor_form", "party_attendance", "coordinator_entry", "coordinator_form"]
    filled = 0
    skipped = 0
    errors = 0
    processed = 0
    try:
        last_key = None
        while processed < limit:
            scan_kwargs = {
                "FilterExpression": (
                    boto3.dynamodb.conditions.Attr("collection_id").eq(cid) &
                    boto3.dynamodb.conditions.Attr("face_id").exists()
                ),
                "Limit": min(200, limit - processed),
            }
            if last_key:
                scan_kwargs["ExclusiveStartKey"] = last_key
            resp = forms_table.scan(**scan_kwargs)
            items = resp.get("Items") or []
            for it in items:
                ft = it.get("form_type") or it.get("ft") or ""
                if form_types_to_scan and ft not in form_types_to_scan:
                    continue
                p = it.get("payload") or {}
                if not isinstance(p, dict):
                    continue
                name = (p.get("name") or "").strip()
                mobile = (p.get("mobile") or "").strip()
                if not (name or mobile):
                    skipped += 1
                    continue
                face_id = it.get("face_id") or ""
                if not face_id:
                    skipped += 1
                    continue
                processed += 1
                if dry_run:
                    filled += 1
                    continue
                try:
                    used_col = _primary_rek_collection_for(cid)
                    cluster_ids = _expand_similar_face_ids(used_col, face_id, threshold=85.0, max_faces=200) if used_col else [face_id]
                    for cfid in cluster_ids:
                        _faces_fill_identity(cfid, cid, name=name, mobile=mobile)
                    filled += 1
                except Exception as ex:
                    errors += 1
                    _log(ev, "backfill.error", face_id=face_id, error=str(ex))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or processed >= limit:
                break
    except Exception as ex:
        return _resp(500, {"message": "scan error", "error": str(ex)})
    return _resp(200, {"message": "OK", "dry_run": dry_run, "processed": processed, "filled": filled, "skipped": skipped, "errors": errors})

# ── Search Cache helpers ──
SEARCH_CACHE_TTL = int(os.environ.get("SEARCH_CACHE_TTL_DAYS", "7")) * 86400

def _search_cache_key(cid, photo_sha256):
    return f"_sc_{cid}_{photo_sha256}"

def _search_cache_get(cid, photo_sha256):
    if not (cid and photo_sha256):
        return None
    try:
        eid = _search_cache_key(cid, photo_sha256)
        it = forms_table.get_item(Key={"entry_id": eid}).get("Item")
        if not it:
            return None
        ttl = int(it.get("ttl_epoch") or 0)
        if ttl and time.time() > ttl:
            return None
        return it
    except Exception:
        return None

def _search_cache_put(cid, photo_sha256, face_id, face_ids, similarity):
    if not (cid and photo_sha256 and face_id):
        return
    try:
        eid = _search_cache_key(cid, photo_sha256)
        forms_table.put_item(Item={
            "entry_id": eid, "collection_id": cid, "form_type": "_search_cache",
            "face_id": face_id, "face_ids": face_ids or [face_id], "similarity": str(similarity),
            "created_at": str(_now_ms()), "ttl_epoch": int(time.time()) + SEARCH_CACHE_TTL,
        })
    except Exception:
        pass

def action_init_search(body):
    token = body.get("token") or (body.get("payload") or {}).get("token") or ""
    ok, tok, err = _verify_token(token, _token_secret())
    if not ok:
        return _resp(401, {"message": "Unauthorized", "error": err})
    cid = tok.get("collection_id") or tok.get("cid") or ""
    if not cid:
        return _resp(400, {"message": "missing collection_id in token"})
    mime_type = body.get("mime_type") or (body.get("payload") or {}).get("mime_type") or "image/jpeg"
    ext = "png" if "png" in (mime_type or "") else "jpg"
    photo_sha256 = (body.get("sha256") or "").strip().lower()
    if photo_sha256:
        cached = _search_cache_get(cid, photo_sha256)
        if cached:
            search_id = _sign_token({
                "v": 3, "cid": cid, "collection_id": cid,
                "face_id": cached.get("face_id", ""),
                "face_ids": cached.get("face_ids") or [],
                "similarity": float(cached.get("similarity") or 0),
                "cache_hit": True,
            }, _token_secret(), exp_seconds=86400)
            return _resp(200, {"message": "OK", "search_id": search_id, "upload_url": None, "s3_key": None, "cache_hit": True})
    s3_key = f"{S3_PREFIX}search/{cid}/{uuid.uuid4().hex}.{ext}"
    upload_url = _make_presigned_put(S3_BUCKET, s3_key, mime_type, expires=900)
    search_id = _sign_token({
        "v": 2, "cid": cid, "collection_id": cid, "s3_key": s3_key, "sha256": photo_sha256,
    }, _token_secret(), exp_seconds=1800)
    return _resp(200, {"message": "OK", "search_id": search_id, "upload_url": upload_url, "s3_key": s3_key, "cache_hit": False})

def action_run_search(body, event):
    token = body.get("token") or (body.get("payload") or {}).get("token") or ""
    ok, tok, err = _verify_token(token, _token_secret())
    if not ok:
        return _resp(401, {"message": "Unauthorized", "error": err})
    search_id = body.get("search_id") or (body.get("payload") or {}).get("search_id") or ""
    ok2, sid, err2 = _verify_token(search_id, _token_secret())
    if not ok2:
        return _resp(401, {"message": "Unauthorized", "error": err2})
    cid = tok.get("collection_id") or tok.get("cid") or sid.get("collection_id") or sid.get("cid") or ""
    if sid.get("cache_hit"):
        cached_face_id  = sid.get("face_id") or ""
        cached_face_ids = sid.get("face_ids") or ([cached_face_id] if cached_face_id else [])
        cached_sim      = float(sid.get("similarity") or 0)
        if cached_face_id:
            return _action_build_search_response(
                cid=cid, selected_face_id=cached_face_id, face_ids=cached_face_ids,
                similarity=cached_sim, s3_key="", used_col="", primary_col="",
                matches_primary=[], used_fallback=False, payload={}, event=event, from_cache=True,
            )
    s3_key = sid.get("s3_key") or ""
    sha256 = sid.get("sha256") or ""
    return action_public_search({"collection_id": cid, "s3_key": s3_key, "sha256": sha256}, event=event)

def action_public_search(payload, event=None):
    ev = event or {}
    cid = payload.get("collection_id") or payload.get("cid") or ""
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    s3_key = payload.get("s3_key") or payload.get("key") or ""
    if not s3_key:
        return _resp(400, {"message": "missing s3_key"})

    _log(ev, "public_search.start", cid=cid, s3_key=s3_key)

    threshold = float(payload.get("threshold", 85))
    max_faces = int(payload.get("max_faces", 200))
    max_faces = max(1, min(max_faces, 4096))

    primary_col = _primary_rek_collection_for(cid)
    matches_primary = _search_faces_by_image_in_collection(primary_col, S3_BUCKET, s3_key, threshold=threshold, max_faces=max_faces)

    used_col = primary_col
    used_fallback = False
    selected_face_id = None
    similarity = 0.0
    selected_matches = matches_primary or []

    if matches_primary:
        picked = _pick_best_match_for_cid(matches_primary, cid)
        if picked:
            selected_face_id, similarity = picked
        else:
            best = matches_primary[0]
            selected_face_id = (best.get("Face") or {}).get("FaceId")
            similarity = float(best.get("Similarity") or 0.0)
    elif _is_per_collection_mode():
        global_col = _global_rek_collection()
        if global_col and global_col != primary_col:
            matches_global = _search_faces_by_image_in_collection(global_col, S3_BUCKET, s3_key, threshold=threshold, max_faces=max(200, max_faces))
            picked2 = _pick_best_match_for_cid(matches_global, cid)
            if picked2:
                selected_face_id, similarity = picked2
                used_col = global_col
                used_fallback = True
                selected_matches = matches_global or []
            else:
                return _resp(200, {"message": "NO_MATCH", "similarity": 0, "timeline": [], "photo_urls": [],
                    "debug": {"used_s3_key": s3_key, "rek_collection_used": primary_col,
                              "fallback_tried": True, "fallback_collection": global_col, "mode": "per_collection"}})
        else:
            return _resp(200, {"message": "NO_MATCH", "similarity": 0, "timeline": [], "photo_urls": [],
                "debug": {"used_s3_key": s3_key, "rek_collection_used": primary_col, "fallback_tried": False, "mode": "per_collection"}})
    else:
        return _resp(200, {"message": "NO_MATCH", "similarity": 0, "timeline": [], "photo_urls": [],
            "debug": {"used_s3_key": s3_key, "rek_collection_used": primary_col, "fallback_tried": False, "mode": "global_only"}})

    face_id_set = set()
    for m0 in selected_matches or []:
        fid0 = (m0.get("Face") or {}).get("FaceId")
        if fid0:
            face_id_set.add(fid0)
    if selected_face_id:
        face_id_set.add(selected_face_id)

    expanded = _expand_similar_face_ids(used_col, selected_face_id, threshold=85.0, max_faces=50) if (selected_face_id and os.environ.get('REK_ENABLE_SEARCH_FACES','0')=='1') else []
    for fid1 in expanded or []:
        face_id_set.add(fid1)

    face_ids = list(face_id_set) if face_id_set else ([selected_face_id] if selected_face_id else [])

    incoming_name = (payload.get("name") or payload.get("user_name") or "").strip()
    incoming_mobile = (payload.get("mobile") or payload.get("phone") or "").strip()
    if incoming_name or incoming_mobile:
        for fid in face_ids:
            _faces_fill_identity(fid, cid, name=incoming_name, mobile=incoming_mobile)

    _log(ev, "public_search.done", cid=cid, selected_face_id=selected_face_id, similarity=similarity,
         primary_matches=len(matches_primary or []), used_collection=used_col, fallback_used=used_fallback)

    sha256 = (payload.get("sha256") or "").strip().lower()
    if sha256 and selected_face_id:
        _search_cache_put(cid, sha256, selected_face_id, face_ids, similarity)

    return _action_build_search_response(
        cid=cid, selected_face_id=selected_face_id, face_ids=face_ids,
        similarity=similarity, s3_key=s3_key, used_col=used_col, primary_col=primary_col,
        matches_primary=matches_primary, used_fallback=used_fallback, payload=payload,
        event=ev, from_cache=False,
    )

def _action_build_search_response(cid, selected_face_id, face_ids, similarity, s3_key, used_col, primary_col, matches_primary, used_fallback, payload, event, from_cache=False):
    ev = event or {}

    incoming_name   = (payload.get("name") or payload.get("user_name") or "").strip()
    incoming_mobile = (payload.get("mobile") or payload.get("phone") or "").strip()
    if incoming_name or incoming_mobile:
        for fid in face_ids:
            _faces_fill_identity(fid, cid, name=incoming_name, mobile=incoming_mobile)

    face_map = _faces_batch_get(face_ids)

    profile = {"name": "", "mobile": ""}
    all_keys = []
    for fid in face_ids:
        fi = face_map.get(fid)
        if not fi or (fi.get("collection_id") or "") != cid:
            continue
        if not profile["name"] and fi.get("name"):
            profile["name"] = fi.get("name") or ""
        if not profile["mobile"] and fi.get("mobile"):
            profile["mobile"] = fi.get("mobile") or ""
        all_keys.extend(_extract_photo_keys(fi))

    photo_urls = []
    seen = set()
    for k in all_keys:
        if k and k not in seen:
            seen.add(k)
            url = _presign_get(S3_BUCKET, k)
            if url:
                photo_urls.append(url)
        if len(photo_urls) >= 500:
            break

    timeline_raw = _fetch_timeline(cid, face_ids, days=int(payload.get("days", 30) or 30))

    dedupe_events = payload.get("dedupe_events")
    if dedupe_events is None:
        dedupe_events = True

    timeline = _group_timeline_by_event(cid, timeline_raw) if dedupe_events else timeline_raw
    events = _group_timeline_by_event(cid, timeline_raw, max_photos_per_event=12)

    _enrich_events_with_labels(events, selected_face_id, ev)

    _log(ev, "search_response.done", cid=cid, face_id=selected_face_id, similarity=similarity,
         timeline_count=len(timeline_raw or []), from_cache=from_cache)

    return _resp(200, {
        "message": "OK", "face_id": selected_face_id, "face_ids": face_ids,
        "similarity": similarity, "profile": profile, "events": events,
        "timeline": timeline, "timeline_raw": timeline_raw, "photo_urls": photo_urls,
        "from_cache": from_cache,
        "debug": {
            "used_s3_key": s3_key, "rek_collection_used": used_col, "primary_collection": primary_col,
            "fallback_used": used_fallback, "mode": REK_COLLECTION_MODE,
            "primary_matches": len(matches_primary or []), "face_ids_count": len(face_ids or []),
            "timeline_count": len(timeline_raw or []), "photo_urls_count": len(photo_urls or []),
            "from_cache": from_cache,
        },
    })

# ------------------- Admin data -------------------

def _safe_json(obj):
    if obj is None:
        return None
    if isinstance(obj, (dict, list)):
        return obj
    if isinstance(obj, str) and obj.strip():
        try:
            return json.loads(obj)
        except Exception:
            return None
    return None

def _ms_str(v):
    try:
        if v is None:
            return ""
        if isinstance(v, (int, float)):
            return str(int(v))
        s = str(v).strip()
        if not s:
            return ""
        if "T" in s and ":" in s:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                return str(int(dt.timestamp() * 1000))
            except Exception:
                pass
        return str(int(float(s)))
    except Exception:
        return ""

def _admin_item_view(item):
    payload = item.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}
    s3_key = item.get("s3_key") or ""
    photo_url = _presign_get(S3_BUCKET, s3_key) if (S3_BUCKET and s3_key) else None
    thumb_key = payload.get("thumb_key") or item.get("thumb_key") or ""
    thumb_url = _presign_get(S3_BUCKET, thumb_key) if (S3_BUCKET and thumb_key) else None
    if not thumb_url:
        thumb_url = photo_url
    out = _format_timeline_item(item)
    out["face_id"] = item.get("face_id") or ""
    out["face_ids"] = item.get("face_ids") if isinstance(item.get("face_ids"), list) else []
    out["photo_url"] = photo_url
    out["thumb_url"] = thumb_url
    return out

def action_admin_list(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    form_type = (body.get("form_type") or body.get("ft") or "all").strip()
    _ft_norm = (form_type or "").strip().lower()
    if _ft_norm in ("", "all", "__all__", "*"):
        form_type = "all"
    limit = int(body.get("limit") or 50)
    limit = max(1, min(limit, 200))
    end_ms = _ms_str(body.get("end_ms")) or str(_now_ms())
    start_ms = _ms_str(body.get("start_ms"))
    if not start_ms:
        start_ms = str(int(end_ms) - 30 * 24 * 3600 * 1000)
    next_key = _safe_json(body.get("next_key") or body.get("next_token") or body.get("nextToken"))
    if not next_key:
        next_key = _safe_json(body.get("next_token"))
    items_out = []
    last_evaluated = None
    pages = 0
    max_pages = 10
    eks = next_key if isinstance(next_key, dict) and next_key else None
    debug_errors = []
    used_source = None
    while len(items_out) < limit and pages < max_pages:
        pages += 1
        raw_items = []
        last_evaluated = None
        for idx_name, pk_name in (("collection_id-created_at-index", "collection_id"), ("cid-created_at-index", "cid")):
            try:
                q = forms_table.query(
                    IndexName=idx_name,
                    KeyConditionExpression=Key(pk_name).eq(cid) & Key("created_at").between(str(start_ms), str(end_ms)),
                    ScanIndexForward=False, Limit=200,
                    **({"ExclusiveStartKey": eks} if (eks and isinstance(eks, dict)) else {}),
                )
                raw_items = q.get("Items") or []
                last_evaluated = q.get("LastEvaluatedKey")
                used_source = idx_name
                if raw_items:
                    break
            except Exception as e:
                debug_errors.append(f"query({idx_name}) failed: {e}")
                raw_items = []
                last_evaluated = None
        if not raw_items:
            try:
                fe_pk = Attr("collection_id").eq(cid) | Attr("cid").eq(cid)
                fe = fe_pk & Attr("created_at").between(str(start_ms), str(end_ms))
                q = forms_table.scan(FilterExpression=fe, Limit=200,
                    **({"ExclusiveStartKey": eks} if (eks and isinstance(eks, dict)) else {}))
                raw_items = q.get("Items") or []
                last_evaluated = q.get("LastEvaluatedKey")
                used_source = "scan(range)"
            except Exception as e3:
                debug_errors.append(f"scan(range filter) failed: {e3}")
                try:
                    fe2 = Attr("collection_id").eq(cid) | Attr("cid").eq(cid)
                    q = forms_table.scan(FilterExpression=fe2, Limit=200,
                        **({"ExclusiveStartKey": eks} if (eks and isinstance(eks, dict)) else {}))
                    raw_items = q.get("Items") or []
                    last_evaluated = q.get("LastEvaluatedKey")
                    used_source = "scan(pk)"
                except Exception as e4:
                    debug_errors.append(f"scan(pk filter) failed: {e4}")
                    raw_items = []
                    last_evaluated = None
        for it in raw_items:
            ft = (it.get("form_type") or it.get("ft") or "").strip()
            if form_type and form_type != "all" and ft != form_type:
                continue
            items_out.append(_admin_item_view(it))
            if len(items_out) >= limit:
                break
        if not last_evaluated:
            break
        eks = last_evaluated
    resp_obj = {
        "message": "OK", "collection_id": cid, "cid": cid, "form_type": form_type,
        "start_ms": str(start_ms), "end_ms": str(end_ms), "items": items_out,
        "count": len(items_out), "next_key": last_evaluated,
    }
    if len(items_out) == 0:
        resp_obj["debug"] = {"table_forms": TABLE_FORMS, "region": AWS_REGION,
            "indexes_tried": ["collection_id-created_at-index", "cid-created_at-index"],
            "used_source": used_source, "start_ms": str(start_ms), "end_ms": str(end_ms)}
        if debug_errors:
            resp_obj["debug"]["errors"] = debug_errors
    return _resp(200, resp_obj)

def action_admin_get_entry(body):
    entry_id = (body.get("entry_id") or "").strip()
    if not entry_id:
        return _resp(400, {"message": "missing entry_id"})
    try:
        it = forms_table.get_item(Key={"entry_id": entry_id}).get("Item")
    except Exception:
        it = None
    if not it:
        return _resp(404, {"message": "not found", "entry_id": entry_id})
    return _resp(200, {"message": "OK", "item": _admin_item_view(it)})

def action_admin_stats(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    end_ms = _ms_str(body.get("end_ms")) or str(_now_ms())
    start_ms = _ms_str(body.get("start_ms"))
    if not start_ms:
        start_ms = str(int(end_ms) - 30 * 24 * 3600 * 1000)
    counts = {}
    total = 0
    eks = None
    pages = 0
    while pages < 15:
        pages += 1
        try:
            q = forms_table.query(
                IndexName="collection_id-created_at-index",
                KeyConditionExpression=Key("collection_id").eq(cid) & Key("created_at").between(str(start_ms), str(end_ms)),
                ScanIndexForward=False, Limit=300,
                **({"ExclusiveStartKey": eks} if isinstance(eks, dict) and eks else {}),
            )
            items = q.get("Items") or []
            eks = q.get("LastEvaluatedKey")
        except Exception:
            items = []
            eks = None
        for it in items:
            ft = (it.get("form_type") or it.get("ft") or "unknown").strip() or "unknown"
            counts[ft] = counts.get(ft, 0) + 1
            total += 1
        if not eks:
            break
    return _resp(200, {"message": "OK", "cid": cid, "start_ms": str(start_ms), "end_ms": str(end_ms), "total": total, "counts": counts})

# ------------------- Admin settings -------------------

def _deep_merge(a, b):
    out = copy.deepcopy(a)
    def _m(dst, src):
        for k, v in (src or {}).items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                _m(dst[k], v)
            else:
                dst[k] = v
    if isinstance(b, dict):
        _m(out, b)
    return out

def _admin_default_settings():
    return {
        "version": 1,
        "global": {
            "tagline": "Powered by EventLens",
            "theme": {"primary": "#f97316", "secondary": "#ef4444", "background": "#0f172a"},
        },
        "forms": {
            "visitor_form": {"title": "कार्यालय आगंतुक फॉर्म", "subtitle": "Visitor Entry System", "tagline": "",
                "theme": {"gradient": "from-orange-500 to-red-500"}, "logo_key": "", "header_key": "", "background_key": ""},
            "party_attendance": {"title": "पार्टी उपस्थिति", "subtitle": "Attendance", "tagline": "",
                "theme": {"gradient": "from-orange-500 to-red-500"}, "logo_key": "", "header_key": "", "background_key": "", "program_options": []},
            "president_tour_form": {"title": "प्रेसिडेंट टूर", "subtitle": "Tour", "tagline": "",
                "theme": {"gradient": "from-orange-500 to-red-500"}, "logo_key": "", "header_key": "", "background_key": ""},
            "mandal_reporting": {"title": "कार्यक्रम रिपोर्टिंग", "subtitle": "Reporting", "tagline": "",
                "theme": {"gradient": "from-orange-500 to-red-500"}, "logo_key": "", "header_key": "", "background_key": "",
                "program_options": [], "fixed_level": ""},
            "coordinator_form": {"title": "संयोजक", "subtitle": "Coordinator", "tagline": "",
                "theme": {"gradient": "from-orange-500 to-red-500"}, "logo_key": "", "header_key": "", "background_key": "",
                "program_options": [], "fixed_level": ""},
            "program_info": {"title": "प्रोग्राम इन्फो", "subtitle": "Program Info", "tagline": "",
                "theme": {"gradient": "from-orange-500 to-red-500"}, "logo_key": "", "header_key": "", "background_key": "",
                "program_options": [], "fixed_level": ""},
        },
        "updated_at_ms": "",
        "updated_at_iso": "",
    }

def _normalize_config_type(v):
    s = str(v or "").strip().lower()
    if not s:
        s = str(DEFAULT_ADMIN_CONFIG_TYPE or "").strip().lower()
    if not s:
        return "political_forms"
    s = s.replace("-", "_")
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^a-z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if s in ("politicalforms", "political_form", "political_forms"):
        return "political_forms"
    return s or "political_forms"

def _admin_cfg_get(cid, config_type):
    config_type = _normalize_config_type(config_type)
    try:
        it = admin_config_table.get_item(Key={"collection_id": cid, "config_type": config_type}).get("Item") or {}
        settings = it.get("settings") if isinstance(it.get("settings"), dict) else {}
        if settings:
            return _jsonable(settings or {})
        alt = config_type.replace("_", "-")
        if alt != config_type:
            it2 = admin_config_table.get_item(Key={"collection_id": cid, "config_type": alt}).get("Item") or {}
            settings2 = it2.get("settings") if isinstance(it2.get("settings"), dict) else {}
            return _jsonable(settings2 or {})
        return {}
    except Exception as e:
        print("admin_cfg_get error", {"cid": cid, "config_type": config_type, "error": str(e)})
        return {}

def _admin_cfg_put(cid, config_type, settings):
    config_type = _normalize_config_type(config_type)
    now_ms = str(_now_ms())
    now_iso = _now_iso()
    admin_config_table.put_item(Item={
        "collection_id": cid, "config_type": config_type,
        "updated_at_ms": now_ms, "updated_at_iso": now_iso, "settings": settings,
    })

def _extract_asset_key(asset):
    if isinstance(asset, str):
        s = asset.strip()
        if not s:
            return ""
        if s.lower().startswith("http://") or s.lower().startswith("https://"):
            return ""
        return s
    if isinstance(asset, dict):
        for fld in ("s3_key", "key", "asset_key", "value"):
            v = asset.get(fld)
            if isinstance(v, str):
                s = v.strip()
                if s and not (s.lower().startswith("http://") or s.lower().startswith("https://")):
                    return s
    return ""

def _resolve_branding_assets_inplace(branding):
    if not isinstance(branding, dict):
        return
    for kind in ("logo", "header", "background"):
        a = branding.get(kind)
        k = _extract_asset_key(a)
        if not k:
            continue
        url = _presign_get(S3_BUCKET, k.strip(), exp=3600) or ""
        if not url:
            continue
        if isinstance(a, dict):
            a["url"] = url
            if not a.get("key"):
                a["key"] = k
            branding[kind] = a
        else:
            branding[kind] = {"key": k, "url": url}

def _resolve_asset_urls(settings):
    out = copy.deepcopy(settings or {})
    defaults = out.get("defaults") if isinstance(out.get("defaults"), dict) else {}
    if isinstance(defaults, dict):
        branding = defaults.get("branding")
        if isinstance(branding, dict):
            _resolve_branding_assets_inplace(branding)
            defaults["branding"] = branding
        out["defaults"] = defaults
    forms = out.get("forms") if isinstance(out.get("forms"), dict) else {}
    for _, cfg in (forms or {}).items():
        if not isinstance(cfg, dict):
            continue
        branding = cfg.get("branding") if isinstance(cfg.get("branding"), dict) else None
        for kind, key_field, url_field in (
            ("logo", "logo_key", "logo_url"), ("header", "header_key", "header_url"),
            ("background", "background_key", "background_url"),
        ):
            k = cfg.get(key_field) or ""
            if (not isinstance(k, str) or not k.strip()) and isinstance(branding, dict):
                k2 = _extract_asset_key(branding.get(kind))
                if k2:
                    cfg[key_field] = k2
                    k = k2
            if isinstance(k, str) and k.strip():
                cfg[url_field] = _presign_get(S3_BUCKET, k.strip(), exp=3600) or ""
            else:
                cfg[url_field] = ""
            if isinstance(branding, dict) and cfg.get(url_field):
                a = branding.get(kind)
                if isinstance(a, dict):
                    a["url"] = cfg[url_field]
                    if not a.get("key"):
                        a["key"] = cfg.get(key_field) or ""
                    branding[kind] = a
                else:
                    branding[kind] = {"key": cfg.get(key_field) or "", "url": cfg[url_field]}
        if isinstance(branding, dict):
            cfg["branding"] = branding
    out["forms"] = forms
    return out

def _ensure_legacy_settings_shape(settings):
    out = copy.deepcopy(settings or {})
    defaults = out.get("defaults")
    if not isinstance(defaults, dict):
        defaults = {}
        out["defaults"] = defaults
    branding = defaults.get("branding")
    if not isinstance(branding, dict):
        branding = {}
        defaults["branding"] = branding
    global_node = out.get("global") if isinstance(out.get("global"), dict) else {}
    theme = global_node.get("theme") if isinstance(global_node.get("theme"), dict) else {}
    if not branding.get("color1"):
        branding["color1"] = theme.get("primary") or "#f97316"
    if not branding.get("color2"):
        branding["color2"] = theme.get("secondary") or "#ef4444"
    if isinstance(global_node.get("tagline"), str) and global_node.get("tagline") and not branding.get("tagline"):
        branding["tagline"] = global_node.get("tagline")
    defaults["branding"] = branding
    out["defaults"] = defaults
    forms = out.get("forms") if isinstance(out.get("forms"), dict) else {}
    for _, cfg in (forms or {}).items():
        if not isinstance(cfg, dict):
            continue
        br = cfg.get("branding")
        if not isinstance(br, dict):
            br = {}
        br.setdefault("color1", branding.get("color1"))
        br.setdefault("color2", branding.get("color2"))
        if isinstance(cfg.get("title"), str) and cfg.get("title") and not br.get("title"):
            br["title"] = cfg.get("title")
        if isinstance(cfg.get("subtitle"), str) and cfg.get("subtitle") and not br.get("subtitle"):
            br["subtitle"] = cfg.get("subtitle")
        if isinstance(cfg.get("tagline"), str) and cfg.get("tagline") and not br.get("tagline"):
            br["tagline"] = cfg.get("tagline")
        for kind, url_field in (("logo", "logo_url"), ("header", "header_url"), ("background", "background_url")):
            u = cfg.get(url_field)
            if isinstance(u, str) and u.strip():
                a = br.get(kind)
                if isinstance(a, dict):
                    a.setdefault("url", u)
                    br[kind] = a
                else:
                    br[kind] = {"url": u}
        cfg["branding"] = br
    out["forms"] = forms
    return out

def _canonicalize_incoming_settings(settings):
    out = copy.deepcopy(settings or {})
    if not isinstance(out.get("global"), dict):
        out["global"] = {}
    if not isinstance(out["global"].get("theme"), dict):
        out["global"]["theme"] = {}
    defaults = out.get("defaults") if isinstance(out.get("defaults"), dict) else {}
    branding = defaults.get("branding") if isinstance(defaults.get("branding"), dict) else {}
    if isinstance(branding, dict):
        c1 = branding.get("color1")
        c2 = branding.get("color2")
        if isinstance(c1, str) and c1 and not out["global"]["theme"].get("primary"):
            out["global"]["theme"]["primary"] = c1
        if isinstance(c2, str) and c2 and not out["global"]["theme"].get("secondary"):
            out["global"]["theme"]["secondary"] = c2
    forms = out.get("forms") if isinstance(out.get("forms"), dict) else {}
    for _, cfg in (forms or {}).items():
        if not isinstance(cfg, dict):
            continue
        br = cfg.get("branding") if isinstance(cfg.get("branding"), dict) else None
        if isinstance(br, dict):
            for fld in ("title", "subtitle", "tagline"):
                v = br.get(fld)
                if isinstance(v, str) and v and not cfg.get(fld):
                    cfg[fld] = v
            for kind, key_field in (("logo", "logo_key"), ("header", "header_key"), ("background", "background_key")):
                if isinstance(cfg.get(key_field), str) and cfg.get(key_field).strip():
                    continue
                k = _extract_asset_key(br.get(kind))
                if k:
                    cfg[key_field] = k
        for kind, key_field in (("logo", "logo_key"), ("header", "header_key"), ("background", "background_key")):
            if isinstance(cfg.get(key_field), str) and cfg.get(key_field).strip():
                continue
            k = _extract_asset_key(cfg.get(kind))
            if k:
                cfg[key_field] = k
    out["forms"] = forms
    return out

def action_admin_get_settings(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    config_type = _normalize_config_type(body.get("config_type") or body.get("configType") or body.get("type"))
    defaults = _admin_default_settings()
    stored = _admin_cfg_get(cid, config_type)
    merged = _deep_merge(defaults, stored)
    merged["updated_at_ms"] = str(_now_ms())
    merged["updated_at_iso"] = _now_iso()
    merged = _canonicalize_incoming_settings(merged)
    resolved = _resolve_asset_urls(merged)
    resolved = _ensure_legacy_settings_shape(resolved)
    return _resp(200, {"message": "OK", "cid": cid, "collection_id": cid, "config_type": config_type,
        "settings": resolved, "config": resolved})

def action_admin_save_settings(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    config_type = _normalize_config_type(body.get("config_type") or body.get("configType") or body.get("type"))
    settings = body.get("settings")
    if not isinstance(settings, dict):
        settings = body.get("config")
    if not isinstance(settings, dict):
        return _resp(400, {"message": "settings must be object"})
    try:
        settings = _canonicalize_incoming_settings(settings)
        _admin_cfg_put(cid, config_type, settings)
    except Exception as e:
        return _resp(500, {"message": "admin_save_settings failed", "error": str(e)})
    return _resp(200, {"message": "OK", "cid": cid, "collection_id": cid, "config_type": config_type})

def action_admin_init_asset_upload(body):
    cid = (body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    file_name = (body.get("file_name") or body.get("filename") or "asset.jpg").strip()
    mime_type = (body.get("mime_type") or "image/jpeg").strip()
    ext = _ext_from_filename(file_name) or ("png" if "png" in mime_type else "jpg")
    key = f"{S3_PREFIX}{cid}/admin/assets/{uuid.uuid4().hex}.{ext}"
    upload_url = _make_presigned_put(S3_BUCKET, key, mime_type, expires=900)
    preview_url = _presign_get(S3_BUCKET, key, exp=900) or ""
    return _resp(200, {"message": "OK", "cid": cid, "collection_id": cid, "s3_key": key,
        "upload_url": upload_url, "preview_url": preview_url})

def action_public_get_settings(event, body, is_public):
    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    token = (payload.get("token") or body.get("token") or "").strip()
    cid = (payload.get("collection_id") or payload.get("cid") or body.get("collection_id") or body.get("cid") or "").strip()
    if not cid:
        cid = _extract_cid_from_event(event)
    tok_data = {}
    if token:
        ok, tok_data, err = _verify_token(token, _token_secret())
        if ok:
            cid = (tok_data.get("collection_id") or tok_data.get("cid") or "").strip()
        else:
            jwt = _try_decode_unverified_jwt(token)
            cid = cid or (jwt.get("collection_id") or jwt.get("cid") or "").strip()
    if is_public and not cid:
        return _resp(400, {"message": "missing collection_id"})
    if not cid:
        return _resp(400, {"message": "missing collection_id"})
    config_type = _normalize_config_type(payload.get("config_type") or payload.get("configType") or body.get("config_type") or body.get("configType") or body.get("type"))
    defaults = _admin_default_settings()
    stored = _admin_cfg_get(cid, config_type)
    merged = _deep_merge(defaults, stored)
    merged = _canonicalize_incoming_settings(merged)
    resolved = _resolve_asset_urls(merged)
    resolved = _ensure_legacy_settings_shape(resolved)
    form_type = (payload.get("form_type") or payload.get("formType") or payload.get("ft") or body.get("form_type") or body.get("ft") or "").strip()
    form_cfg = None
    if form_type and isinstance(resolved.get("forms"), dict):
        form_cfg = resolved["forms"].get(form_type)
    return _resp(200, {"message": "OK", "cid": cid, "collection_id": cid, "config_type": config_type,
        "settings": resolved, "config": resolved, "form_type": form_type, "form": form_cfg})

# ------------------- Dashboard token actions -------------------

def action_generate_form_link(payload):
    payload = payload or {}
    cid = payload.get("collection_id") or payload.get("cid")
    if not cid:
        return _resp(400, {"message": "collection_id_required"})
    days_valid = int(payload.get("days_valid") or 3650)
    days_valid = max(1, min(days_valid, 3650))
    form_type = (payload.get("form_type") or "visitor_form").strip()
    token = _sign_token({"v": 1, "collection_id": cid, "cid": cid, "form_type": form_type, "ft": form_type}, _token_secret(), exp_seconds=days_valid * 86400)
    return _resp(200, {"message": "OK", "token": token})

def action_generate_search_link(payload):
    payload = payload or {}
    cid = payload.get("collection_id") or payload.get("cid")
    if not cid:
        return _resp(400, {"message": "collection_id_required"})
    days_valid = int(payload.get("days_valid") or 3650)
    days_valid = max(1, min(days_valid, 3650))
    token = _sign_token({"v": 1, "collection_id": cid, "cid": cid, "form_type": "search", "ft": "search"}, _token_secret(), exp_seconds=days_valid * 86400)
    return _resp(200, {"message": "OK", "token": token})

# ------------------- Lambda handlers -------------------

def forms_handler(event, context):
    try:
        _log(event, "forms_handler.start",
             path=(event.get("rawPath") or event.get("path") or ""),
             method=((event.get("requestContext") or {}).get("http") or {}).get("method") or event.get("httpMethod"))
        if (event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS") or (event.get("httpMethod") == "OPTIONS"):
            return _resp(200, {"message": "ok"})

        is_public = _is_public_path(event)
        body = _parse_body(event) or {}
        action = body.get("action")
        payload = body.get("payload") or {}

        if not action and payload.get("finalize_token"):
            action = "public_finalize_entry"

        admin_payload = payload if payload else body

        if action in ("admin_get_settings", "admin_get_config"):
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_get_settings(admin_payload)
        if action in ("admin_save_settings", "admin_save_config", "save_admin_config"):
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_save_settings(admin_payload)
        if action in ("admin_init_asset_upload", "admin_get_upload_url", "admin_upload_init"):
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_init_asset_upload(admin_payload)
        if action in ("admin_list", "admin_list_entries"):
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_list(admin_payload)
        if action == "admin_get_entry":
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_get_entry(admin_payload)
        if action == "admin_stats":
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_stats(admin_payload)
        if action == "admin_list_faces":
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_list_faces(admin_payload)
        if action == "admin_list_photos":
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_list_photos(admin_payload)
        if action == "admin_set_face_name":
            if is_public: return _resp(403, {"message": "forbidden"})
            return action_admin_set_face_name(admin_payload)

        if action in ("public_get_settings", "public_get_config", "get_form_settings"):
            return action_public_get_settings(event, body, is_public=is_public)
        if action in ("public_create_entry", "create_entry"):
            return action_public_create_entry(payload, event=event)
        if action in ("public_finalize_entry", "finalize_entry"):
            return action_public_finalize_entry(payload, event=event)
        if action == "generate_form_link":
            return action_generate_form_link(payload)
        if action == "generate_search_link":
            return action_generate_search_link(payload)

        return _resp(400, {"message": "unknown action", "action": action})
    except Exception as e:
        import traceback as _tb
        print('forms_handler unhandled', {'error': str(e)})
        print(_tb.format_exc())
        return _resp(500, {'message': 'Internal Server Error', 'error': str(e), 'where': 'forms_handler'})


def search_handler(event, context):
    try:
        _log(event, "search_handler.start",
             path=(event.get("rawPath") or event.get("path") or ""),
             method=((event.get("requestContext") or {}).get("http") or {}).get("method") or event.get("httpMethod"))
        if (event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS"):
            return _resp(200, {"message": "ok"})
        body = _parse_body(event)
        action = body.get("action") or "public_search"
        payload = body.get("payload") or body
        if action == "init_search":
            return action_init_search(body)
        if action == "run_search":
            return action_run_search(body, event)
        if action == "public_search":
            return action_public_search(payload, event=event)
        if action == "admin_backfill_identities":
            return action_admin_backfill_identities(payload, event=event)
        return _resp(400, {"message": "unknown action", "action": action})
    except Exception as e:
        import traceback as _tb
        print('search_handler unhandled', {'error': str(e)})
        print(_tb.format_exc())
        return _resp(500, {'message': 'Internal Server Error', 'error': str(e), 'where': 'search_handler'})
