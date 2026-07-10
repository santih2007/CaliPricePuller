"""
AWS Lambda: pull alcohol price-posting data from the California ABC public
price-posting site and write it to S3 as a formatted JSON file.

The site at https://priceposting.abc.ca.gov/publicPricePosts is a React single
page app. It has no scrapeable HTML table -- the data is served by a GraphQL
API. This function talks to that API directly, which is far more reliable than
scraping rendered HTML.

Auth model (reverse-engineered from the site's own JavaScript): the public
GraphQL endpoint expects a short-lived HS256 JWT, signed with a shared secret,
carrying a {"code": <operation-name>} claim, sent as an `Authorization: Bearer`
header. This module reproduces exactly what the website's front end does.

No third-party packages are required: JWT signing is done with the standard
library (hmac/hashlib/base64) and HTTP with urllib. boto3 is provided by the
Lambda Python runtime.

--------------------------------------------------------------------------------
Trigger: manual (console "Test", or `aws lambda invoke`).

Event parameters (all optional -- sensible defaults are applied):

    {
      "s3_bucket":   "my-bucket",          # overrides TARGET_S3_BUCKET env var
      "s3_key":      "path/to/out.json",   # default: auto timestamped key
      "max_records": 5000,                 # safety cap; use null/0 for ALL 8.7M
      "page_size":   1000,                 # rows per API call (max 5000)
      "order_by":    "createdAt_DESC",     # or createdAt_ASC
      "where":       { ... },              # GraphQL filter, see FILTERS below
      "pretty":      true                  # indent the JSON output
    }

FILTERS (`where`) -- passed straight through to the API. Supported keys:
    county_in            : ["Los Angeles", "Orange"]
    status_in            : ["Pending", "Approved", ...]
    manufacturerId_in    : [123, 456]
    productId_in         : [ ... ]
    packageId_in         : [ ... ]
    sizeId_in            : [ ... ]
    pricesTo_in          : [ ... ]
    receivingMethod_in   : ["Delivery", ...]
    createdByLicensee_in : [ ... ]
    productName_like     : "Colt 45"
    tradeName_like       : "Pabst"
    name_like            : "..."
    pricePromotion       : true
    productStatus        : "..."
    effectiveDate_gte    : 1784534400000   # epoch milliseconds
    effectiveDate_lte    : 1790000000000
    createdAt_gte        : 1783703403275
    createdAt_lte        : 1790000000000

    Example -- LA county postings effective on/after a date:
    "where": {"county_in": ["Los Angeles"], "effectiveDate_gte": 1784534400000}
--------------------------------------------------------------------------------
"""

import base64
import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration (env vars win; defaults reproduce the live website) --------
GRAPHQL_ENDPOINT = os.environ.get(
    "GRAPHQL_ENDPOINT",
    "https://s7fcylvn8j.execute-api.us-west-2.amazonaws.com/prod/public/graphql",
)
# The signing secret and operation code are embedded in the site's public JS.
# They are exposed as env vars so they can be rotated without a code change if
# the site ever changes them.
JWT_SECRET = os.environ.get("PP_JWT_SECRET", "UYMJB$mk4yJupVkmJ4jLheY!B")
JWT_CODE = os.environ.get("PP_JWT_CODE", "getPublicPricePostsQuery")
COUNT_CODE = os.environ.get("PP_COUNT_CODE", "getPricePostingsTotalCount")

DEFAULT_BUCKET = os.environ.get("TARGET_S3_BUCKET", "")
DEFAULT_KEY_PREFIX = os.environ.get("S3_KEY_PREFIX", "abc-price-posts/")

# Defaults for a manual run. 8.7M+ rows exist; pulling them all in one invoke is
# rarely what you want, so we cap by default. Override via the event.
DEFAULT_MAX_RECORDS = int(os.environ.get("DEFAULT_MAX_RECORDS", "5000"))
DEFAULT_PAGE_SIZE = int(os.environ.get("DEFAULT_PAGE_SIZE", "1000"))
API_PAGE_LIMIT = 5000  # server accepts up to this per request
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
MAX_RETRIES = int(os.environ.get("HTTP_MAX_RETRIES", "4"))

# The GraphQL document, copied from the site's own bundle.
PRICE_POSTINGS_QUERY = """
query PricePostings(
  $where: PricePostingWhereInput
  $orderBy: PricePostingOrderByInput
  $limit: Int
  $offset: Int
) {
  pricePostings(where: $where, orderBy: $orderBy, limit: $limit, offset: $offset) {
    results {
      id
      manufacturer { name }
      product { name tradeName }
      status
      package { package }
      productSize {
        size
        unit { unit }
        containerType { type }
      }
      county
      pricesTo { name }
      receivingMethod
      price
      pricePromotion
      containerCharge
      effectiveDate
      createdAt
      createdByLicensee { id name }
    }
    count
  }
}
""".strip()

COUNT_QUERY = (
    "query PricePostingsCount($where: PricePostingWhereInput) { "
    "pricePostingsCount(where: $where) { count } }"
)


# --- JWT (HS256) --------------------------------------------------------------
def _b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _make_token(code: str, ttl_seconds: int = 20) -> str:
    """Sign the same short-lived JWT the website sends with each API call."""
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    now = int(time.time())
    payload = {"code": code, "iat": now, "exp": now + ttl_seconds}
    payload_b = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header + b"." + payload_b
    signature = _b64url(
        hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    )
    return (signing_input + b"." + signature).decode()


# --- GraphQL transport --------------------------------------------------------
def _graphql(query: str, variables: dict, code: str) -> dict:
    """POST a GraphQL request, re-signing a fresh token, with retry/backoff."""
    body = json.dumps({"query": query, "variables": variables}).encode()
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(
            GRAPHQL_ENDPOINT,
            data=body,
            headers={
                "Authorization": "Bearer " + _make_token(code),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as resp:
                parsed = json.loads(resp.read().decode())
            if parsed.get("errors"):
                # GraphQL-level errors (e.g. bad filter) are not retryable.
                raise RuntimeError(f"GraphQL errors: {parsed['errors']}")
            return parsed["data"]
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")[:500]
            last_err = RuntimeError(f"HTTP {err.code}: {detail}")
            # 4xx (except 429) is a client error -- don't hammer it.
            if err.code < 500 and err.code != 429:
                raise last_err
        except (urllib.error.URLError, TimeoutError) as err:
            last_err = err
        sleep = min(2 ** attempt, 15)
        logger.warning("Request attempt %d failed (%s); retrying in %ds",
                       attempt, last_err, sleep)
        time.sleep(sleep)
    raise RuntimeError(f"GraphQL request failed after {MAX_RETRIES} attempts: {last_err}")


# --- Formatting ---------------------------------------------------------------
def _epoch_ms_to_iso(value):
    """Convert an epoch-millisecond timestamp to an ISO-8601 UTC string."""
    if value in (None, ""):
        return None
    try:
        return _dt.datetime.fromtimestamp(
            int(value) / 1000, tz=_dt.timezone.utc
        ).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _format_record(raw: dict) -> dict:
    """Flatten one nested GraphQL record into a clean, self-describing row."""
    product = raw.get("product") or {}
    size = raw.get("productSize") or {}
    licensee = raw.get("createdByLicensee") or {}
    return {
        "id": raw.get("id"),
        "status": raw.get("status"),
        "manufacturer": (raw.get("manufacturer") or {}).get("name"),
        "product_name": product.get("name"),
        "trade_name": product.get("tradeName"),
        "package": (raw.get("package") or {}).get("package"),
        "size": size.get("size"),
        "size_unit": (size.get("unit") or {}).get("unit"),
        "container_type": (size.get("containerType") or {}).get("type"),
        "county": raw.get("county"),
        "prices_to": (raw.get("pricesTo") or {}).get("name"),
        "receiving_method": raw.get("receivingMethod"),
        "price": raw.get("price"),
        "price_promotion": raw.get("pricePromotion"),
        "container_charge": raw.get("containerCharge"),
        "effective_date": _epoch_ms_to_iso(raw.get("effectiveDate")),
        "effective_date_epoch_ms": raw.get("effectiveDate"),
        "created_at": _epoch_ms_to_iso(raw.get("createdAt")),
        "created_by_licensee_id": licensee.get("id"),
        "created_by_licensee_name": licensee.get("name"),
    }


# --- Fetch loop ---------------------------------------------------------------
def _fetch_records(where, order_by, page_size, max_records):
    """Page through the API, returning a list of formatted records."""
    page_size = max(1, min(page_size, API_PAGE_LIMIT))
    records = []
    offset = 0
    while True:
        if max_records:
            remaining = max_records - len(records)
            if remaining <= 0:
                break
            limit = min(page_size, remaining)
        else:
            limit = page_size

        variables = {"limit": limit, "offset": offset, "orderBy": order_by}
        if where:
            variables["where"] = where

        data = _graphql(PRICE_POSTINGS_QUERY, variables, JWT_CODE)
        page = (data.get("pricePostings") or {}).get("results") or []
        records.extend(_format_record(r) for r in page)
        logger.info("Fetched %d rows (offset %d); running total %d",
                    len(page), offset, len(records))

        if len(page) < limit:
            break  # reached the end of the result set
        offset += limit
    return records


def _total_available(where) -> int:
    """Best-effort total count matching the filter (for the metadata block)."""
    try:
        data = _graphql(COUNT_QUERY, {"where": where or None}, COUNT_CODE)
        return (data.get("pricePostingsCount") or {}).get("count")
    except Exception as err:  # count is informational; never fail the run for it
        logger.warning("Could not fetch total count: %s", err)
        return None


# --- Entry point --------------------------------------------------------------
def lambda_handler(event, context):
    event = event or {}

    bucket = event.get("s3_bucket") or DEFAULT_BUCKET
    if not bucket:
        raise ValueError(
            "No S3 bucket configured. Set the TARGET_S3_BUCKET env var or pass "
            "'s3_bucket' in the event."
        )

    where = event.get("where") or None
    order_by = event.get("order_by", "createdAt_DESC")
    page_size = int(event.get("page_size", DEFAULT_PAGE_SIZE))
    # max_records: absent -> default cap; explicit null/0 -> pull everything.
    if "max_records" in event:
        max_records = int(event["max_records"] or 0)  # 0 == unlimited
    else:
        max_records = DEFAULT_MAX_RECORDS
    pretty = bool(event.get("pretty", True))

    generated_at = _dt.datetime.now(tz=_dt.timezone.utc)
    logger.info("Starting pull: where=%s order_by=%s page_size=%d max_records=%s",
                where, order_by, page_size, max_records or "ALL")

    total_available = _total_available(where)
    records = _fetch_records(where, order_by, page_size, max_records)

    document = {
        "source": "https://priceposting.abc.ca.gov/publicPricePosts",
        "generated_at": generated_at.isoformat(),
        "filter": where,
        "order_by": order_by,
        "total_available": total_available,
        "record_count": len(records),
        "truncated": bool(max_records and total_available and
                          len(records) < total_available),
        "records": records,
    }

    key = event.get("s3_key") or (
        f"{DEFAULT_KEY_PREFIX}price-posts-"
        f"{generated_at.strftime('%Y%m%dT%H%M%SZ')}.json"
    )

    payload = json.dumps(
        document, indent=2 if pretty else None,
        separators=None if pretty else (",", ":"), default=str,
    ).encode()

    boto3.client("s3").put_object(
        Bucket=bucket, Key=key, Body=payload,
        ContentType="application/json",
    )
    logger.info("Wrote %d records (%d bytes) to s3://%s/%s",
                len(records), len(payload), bucket, key)

    return {
        "status": "ok",
        "s3_uri": f"s3://{bucket}/{key}",
        "record_count": len(records),
        "total_available": total_available,
        "truncated": document["truncated"],
        "bytes_written": len(payload),
    }
