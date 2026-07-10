"""
AWS Lambda: pull alcohol price-posting data from the California ABC public
price-posting site, classify each record as beer / wine / spirits, and write the
results to S3 as newline-delimited JSON (NDJSON) -- one record per line, ready to
load into a Postgres JSONB column.

The site at https://priceposting.abc.ca.gov/publicPricePosts is a React single
page app with no scrapeable HTML table -- the data is served by a GraphQL API,
which this function calls directly (far more reliable than scraping rendered
HTML or driving the site's "Export to Excel" button in a headless browser). The
site's Excel export is itself generated in the browser from this same API.

Auth model (reverse-engineered from the site's own JavaScript): the public
GraphQL endpoint expects a short-lived HS256 JWT, signed with a shared secret,
carrying a {"code": <operation-name>} claim, sent as an `Authorization: Bearer`
header. This module reproduces exactly what the website's front end does.

No third-party packages are required: JWT signing uses the standard library;
HTTP uses urllib; boto3 is provided by the Lambda Python runtime.

--------------------------------------------------------------------------------
Output layout (one NDJSON file per category, in its own S3 "folder"/prefix):

    s3://<bucket>/beer/price-posts-<ts>.jsonl
    s3://<bucket>/wine/price-posts-<ts>.jsonl
    s3://<bucket>/spirits/price-posts-<ts>.jsonl
    s3://<bucket>/uncategorized/price-posts-<ts>.jsonl   (records we can't classify)
    s3://<bucket>/_manifests/run-<ts>.json               (run summary; optional)

Each line in a .jsonl file is one complete JSON object -> one row in a JSONB
table. Load with, e.g.:

    COPY price_posts (doc)
    FROM 's3://.../beer/price-posts-<ts>.jsonl'  -- via aws_s3 / a loader
    -- or in Python: for line in file: INSERT ... (jsonb) VALUES (line)

--------------------------------------------------------------------------------
Trigger: manual (console "Test", or `aws lambda invoke`).

Event parameters (all optional):

    {
      "s3_bucket":     "cali-price-deposit",  # or TARGET_S3_BUCKET env var
      "max_records":   5000,                  # safety cap; 0/null = ALL (~8.7M)
      "page_size":     1000,                  # rows per API call (max 5000)
      "order_by":      "createdAt_DESC",      # or createdAt_ASC
      "where":         { ... },               # GraphQL filter, see FILTERS below
      "output_format": "ndjson",              # "ndjson" (default) or "array"
      "write_manifest": true,                 # write the _manifests/ summary file
      "category_prefixes": {                  # override the per-category folders
        "beer": "beer/", "wine": "wine/",
        "spirits": "spirits/", "uncategorized": "uncategorized/"
      }
    }

FILTERS (`where`) -- passed straight through to the API. Supported keys:
    county_in, status_in, manufacturerId_in, productId_in, packageId_in,
    sizeId_in, pricesTo_in, receivingMethod_in, createdByLicensee_in,
    productName_like, tradeName_like, name_like, pricePromotion, productStatus,
    effectiveDate_gte, effectiveDate_lte, createdAt_gte, createdAt_lte
    (the *_gte / *_lte date bounds are epoch milliseconds)
--------------------------------------------------------------------------------
"""

import base64
import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import re
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
JWT_SECRET = os.environ.get("PP_JWT_SECRET", "UYMJB$mk4yJupVkmJ4jLheY!B")
JWT_CODE = os.environ.get("PP_JWT_CODE", "getPublicPricePostsQuery")
COUNT_CODE = os.environ.get("PP_COUNT_CODE", "getPricePostingsTotalCount")

DEFAULT_BUCKET = os.environ.get("TARGET_S3_BUCKET", "")

DEFAULT_MAX_RECORDS = int(os.environ.get("DEFAULT_MAX_RECORDS", "5000"))
DEFAULT_PAGE_SIZE = int(os.environ.get("DEFAULT_PAGE_SIZE", "1000"))
API_PAGE_LIMIT = 5000
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
MAX_RETRIES = int(os.environ.get("HTTP_MAX_RETRIES", "4"))

DEFAULT_CATEGORY_PREFIXES = {
    "beer": os.environ.get("BEER_PREFIX", "beer/"),
    "wine": os.environ.get("WINE_PREFIX", "wine/"),
    "spirits": os.environ.get("SPIRITS_PREFIX", "spirits/"),
    "uncategorized": os.environ.get("UNCATEGORIZED_PREFIX", "uncategorized/"),
}
MANIFEST_PREFIX = os.environ.get("MANIFEST_PREFIX", "_manifests/")

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
      tradingArea
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
                raise RuntimeError(f"GraphQL errors: {parsed['errors']}")
            return parsed["data"]
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")[:500]
            last_err = RuntimeError(f"HTTP {err.code}: {detail}")
            if err.code < 500 and err.code != 429:
                raise last_err
        except (urllib.error.URLError, TimeoutError) as err:
            last_err = err
        sleep = min(2 ** attempt, 15)
        logger.warning("Request attempt %d failed (%s); retrying in %ds",
                       attempt, last_err, sleep)
        time.sleep(sleep)
    raise RuntimeError(
        f"GraphQL request failed after {MAX_RETRIES} attempts: {last_err}")


# --- Classification -----------------------------------------------------------
# Heuristic keyword classifier. The API exposes NO authoritative beverage-type
# field, so we infer beer/wine/spirits from the product name, trade name,
# container, and package. Company-name signals (e.g. "Brewing", "Winery",
# "Distillery") are weighted heavily; product keywords add smaller weights.
# Anything we can't confidently place lands in "uncategorized" so nothing is
# silently mislabeled -- review that bucket before trusting the split downstream.

# Strong signals: words in the *trade name* (the producer's business name).
_COMPANY_SIGNALS = {
    "beer": ["brewing", "brewery", "brewers", "brewer", "brew co", "beer co",
             "ale works", "aleworks", "brewhouse", "bierwerks", "braus"],
    "wine": ["winery", "wineries", "vineyard", "vineyards", "cellars", "cellar",
             "wine co", "wines", "estate", "chateau", "bodega", "vintners"],
    "spirits": ["distillery", "distilleries", "distilling", "distillers",
                "distiller", "spirits", "distilled"],
}

# Product/style keywords.
_KEYWORDS = {
    "beer": ["beer", "lager", "ale", "ipa", "i.p.a", "stout", "porter",
             "pilsner", "pilsener", "pils", "hefeweizen", "hefe", "weizen",
             "witbier", "wheat", "blonde", "amber", "saison", "kolsch", "bock",
             "doppelbock", "dunkel", "marzen", "oktoberfest", "gose", "sour ale",
             "radler", "shandy", "malt liquor", "malt beverage", "hazy",
             "pale ale", "barleywine", "barley wine", "cream ale",
             "blonde ale", "brown ale", "red ale", "lambic", "tripel",
             "dubbel", "helles", "altbier", "kellerbier", "seltzer",
             "hard seltzer", "cider", "hard cider"],
    "wine": ["wine", "vino", "cabernet", "sauvignon", "chardonnay", "merlot",
             "pinot", "noir", "grigio", "gris", "zinfandel", "zin",
             "riesling", "malbec", "syrah", "shiraz", "tempranillo",
             "sangiovese", "grenache", "mourvedre", "viognier",
             "gewurztraminer", "chenin", "moscato", "muscat", "prosecco",
             "champagne", "cava", "spumante", "sangria", "sherry", "madeira",
             "marsala", "chianti", "rioja", "bordeaux", "burgundy",
             "beaujolais", "sparkling wine", "red blend", "white blend",
             "rose wine", "rosé", "sake", "port wine"],
    "spirits": ["vodka", "whiskey", "whisky", "bourbon", "rye whiskey",
                "single malt", "scotch", "tequila", "mezcal", "rum", "gin",
                "brandy", "cognac", "armagnac", "liqueur", "cordial",
                "schnapps", "absinthe", "grappa", "pisco", "soju", "baijiu",
                "aquavit", "everclear", "moonshine", "triple sec", "curacao",
                "amaretto", "sambuca", "ouzo", "aperol", "campari",
                "distilled spirits", "vermouth", "aperitif"],
}

_CATEGORIES = ("beer", "wine", "spirits")

# Well-known brands whose names carry no beverage-type keyword. Checked FIRST and
# treated as decisive. This is the main tuning knob for shrinking the
# "uncategorized" bucket -- add substrings (matched against product + trade name,
# lowercased) as you spot them. Keep entries unambiguous; when a brand spans
# categories (e.g. a vodka seltzer), pick where your boss wants it counted.
_BRAND_MAP = {
    # spirits (incl. flavored-rum / RTD brands that read as spirits)
    "parrot bay": "spirits", "malibu": "spirits", "captain morgan": "spirits",
    "bacardi": "spirits", "smirnoff vodka": "spirits", "absolut": "spirits",
    "tito": "spirits", "grey goose": "spirits", "ketel one": "spirits",
    "svedka": "spirits", "jack daniel": "spirits", "jim beam": "spirits",
    "crown royal": "spirits", "jameson": "spirits", "makers mark": "spirits",
    "fireball": "spirits", "kahlua": "spirits", "baileys": "spirits",
    "jagermeister": "spirits", "hennessy": "spirits", "patron": "spirits",
    "jose cuervo": "spirits", "1800 tequila": "spirits", "high noon": "spirits",
    # beer / malt-based coolers
    "white claw": "beer", "truly": "beer", "bud light": "beer",
    "budweiser": "beer", "coors": "beer", "miller lite": "beer",
    "modelo": "beer", "corona": "beer", "heineken": "beer",
    "stella artois": "beer", "michelob": "beer", "pabst": "beer",
    "twisted tea": "beer", "mike's hard": "beer", "smirnoff ice": "beer",
    "natural light": "beer", "busch": "beer", "guinness": "beer",
    # wine
    "barefoot": "wine", "sutter home": "wine", "yellow tail": "wine",
    "franzia": "wine", "josh cellars": "wine", "kendall-jackson": "wine",
    "apothic": "wine", "19 crimes": "wine", "meiomi": "wine",
    "la marca": "wine", "carlo rossi": "wine", "beringer": "wine",
    "woodbridge": "wine", "andre": "wine", "korbel": "wine",
}


def _score_text(text: str, terms) -> float:
    """Count how many of `terms` appear in `text`.

    Single-word terms match on word boundaries so short tokens like "rum",
    "gin", or "ale" don't match inside unrelated words ("Trumer", "ginger",
    "pale"). Multiword phrases ("pale ale", "malt liquor") match as substrings.
    """
    score = 0.0
    for term in terms:
        if " " in term:
            if term in text:
                score += 1
        elif re.search(r"\b" + re.escape(term) + r"\b", text):
            score += 1
    return score


def classify_record(rec: dict) -> str:
    """Return 'beer' | 'wine' | 'spirits' | 'uncategorized' for a formatted rec."""
    product = (rec.get("product_name") or "").lower()
    trade = (rec.get("trade_name") or "").lower()
    container = (rec.get("container_type") or "").lower()
    package = (rec.get("package") or "").lower()
    haystack = " ".join([product, trade, container, package])

    # Decisive brand lookup first.
    brand_text = product + " " + trade
    for brand, category in _BRAND_MAP.items():
        if brand in brand_text:
            return category

    scores = {c: 0.0 for c in _CATEGORIES}
    for cat in _CATEGORIES:
        scores[cat] += 3.0 * _score_text(trade, _COMPANY_SIGNALS[cat])
        scores[cat] += _score_text(haystack, _KEYWORDS[cat])

    # Weak container nudge: cans/kegs skew heavily toward beer/seltzer. Only
    # enough to break a tie, never to override a real keyword.
    if container in ("can", "keg"):
        scores["beer"] += 0.5

    best = max(scores.values())
    if best <= 0:
        return "uncategorized"
    winners = [c for c, s in scores.items() if s == best]
    if len(winners) != 1:
        return "uncategorized"
    return winners[0]


# --- Formatting ---------------------------------------------------------------
def _epoch_ms_to_iso(value):
    if value in (None, ""):
        return None
    try:
        return _dt.datetime.fromtimestamp(
            int(value) / 1000, tz=_dt.timezone.utc
        ).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _format_record(raw: dict, pulled_at: str) -> dict:
    product = raw.get("product") or {}
    size = raw.get("productSize") or {}
    licensee = raw.get("createdByLicensee") or {}
    rec = {
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
        "trading_area": raw.get("tradingArea"),
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
        "pulled_at": pulled_at,
    }
    rec["category"] = classify_record(rec)
    return rec


# --- Fetch loop ---------------------------------------------------------------
def _iter_records(where, order_by, page_size, max_records, pulled_at):
    """Yield formatted records one page at a time.

    A generator, so the caller never holds the whole result set in memory --
    each page is fetched, formatted, streamed out, then discarded.
    """
    page_size = max(1, min(page_size, API_PAGE_LIMIT))
    fetched = 0
    offset = 0
    while True:
        if max_records:
            remaining = max_records - fetched
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
        for raw in page:
            yield _format_record(raw, pulled_at)
        fetched += len(page)
        logger.info("Fetched %d rows (offset %d); running total %d",
                    len(page), offset, fetched)

        if len(page) < limit:
            break
        offset += limit


def _total_available(where):
    try:
        data = _graphql(COUNT_QUERY, {"where": where or None}, COUNT_CODE)
        return (data.get("pricePostingsCount") or {}).get("count")
    except Exception as err:
        logger.warning("Could not fetch total count: %s", err)
        return None


# --- Streaming S3 writer ------------------------------------------------------
# Minimum S3 multipart part size is 5 MiB (all parts except the last). We buffer
# a bit above that, then flush each chunk as a part -- so peak memory is ~the
# buffer size per open category, not the whole dataset.
_PART_FLUSH_BYTES = 8 * 1024 * 1024


class CategoryWriter:
    """Streams one category's records to a single S3 object.

    Buffers bytes and, once the buffer crosses the flush threshold, uploads it
    as a multipart-upload part. Small categories (never crossing the threshold)
    are written with a single put_object at close(). This keeps memory bounded
    regardless of how many records the category receives.
    """

    def __init__(self, s3, bucket, key, output_format):
        self._s3 = s3
        self._bucket = bucket
        self._key = key
        self._format = output_format
        self._buf = bytearray()
        self._upload_id = None
        self._parts = []
        self._first = True
        self.count = 0
        self.total_bytes = 0
        self._content_type = ("application/x-ndjson" if output_format == "ndjson"
                              else "application/json")
        if output_format == "array":
            self._buf += b"["

    def add(self, record):
        data = json.dumps(record, separators=(",", ":"), default=str).encode()
        if self._format == "ndjson":
            self._buf += data + b"\n"
        else:  # array
            if not self._first:
                self._buf += b","
            self._buf += data
        self._first = False
        self.count += 1
        if len(self._buf) >= _PART_FLUSH_BYTES:
            self._flush_part()

    def _flush_part(self):
        if self._upload_id is None:
            resp = self._s3.create_multipart_upload(
                Bucket=self._bucket, Key=self._key,
                ContentType=self._content_type)
            self._upload_id = resp["UploadId"]
        part_number = len(self._parts) + 1
        chunk = bytes(self._buf)
        resp = self._s3.upload_part(
            Bucket=self._bucket, Key=self._key, PartNumber=part_number,
            UploadId=self._upload_id, Body=chunk)
        self._parts.append({"ETag": resp["ETag"], "PartNumber": part_number})
        self.total_bytes += len(chunk)
        self._buf = bytearray()

    def close(self):
        """Finalize the object. Returns the byte count written."""
        if self._format == "array":
            self._buf += b"]"
        if self._upload_id is None:
            # Small enough to never have flushed -- one plain PutObject.
            body = bytes(self._buf)
            self._s3.put_object(
                Bucket=self._bucket, Key=self._key, Body=body,
                ContentType=self._content_type)
            self.total_bytes += len(body)
        else:
            if self._buf:
                self._flush_part()
            self._s3.complete_multipart_upload(
                Bucket=self._bucket, Key=self._key, UploadId=self._upload_id,
                MultipartUpload={"Parts": self._parts})
        return self.total_bytes

    def abort(self):
        if self._upload_id is not None:
            try:
                self._s3.abort_multipart_upload(
                    Bucket=self._bucket, Key=self._key,
                    UploadId=self._upload_id)
            except Exception as err:
                logger.warning("Failed to abort multipart upload for %s: %s",
                               self._key, err)


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
    if "max_records" in event:
        max_records = int(event["max_records"] or 0)  # 0 == unlimited
    else:
        max_records = DEFAULT_MAX_RECORDS
    output_format = event.get("output_format", "ndjson")
    if output_format not in ("ndjson", "array"):
        raise ValueError("output_format must be 'ndjson' or 'array'")
    write_manifest = bool(event.get("write_manifest", True))
    prefixes = dict(DEFAULT_CATEGORY_PREFIXES)
    prefixes.update(event.get("category_prefixes") or {})

    now = _dt.datetime.now(tz=_dt.timezone.utc)
    pulled_at = now.isoformat()
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    ext = "jsonl" if output_format == "ndjson" else "json"

    logger.info("Starting pull: where=%s order_by=%s page_size=%d max_records=%s "
                "format=%s", where, order_by, page_size, max_records or "ALL",
                output_format)

    total_available = _total_available(where)

    def _key_for(category):
        prefix = prefixes.get(category, f"{category}/")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        return f"{prefix}price-posts-{stamp}.{ext}"

    s3 = boto3.client("s3")
    # Writers are created lazily, so empty categories produce no S3 object.
    writers = {}
    total = 0
    try:
        for rec in _iter_records(where, order_by, page_size, max_records,
                                 pulled_at):
            category = rec["category"]
            writer = writers.get(category)
            if writer is None:
                writer = CategoryWriter(s3, bucket, _key_for(category),
                                        output_format)
                writers[category] = writer
            writer.add(rec)
            total += 1
    except Exception:
        # Don't leave dangling multipart uploads (they incur storage charges).
        for writer in writers.values():
            writer.abort()
        raise

    outputs = {}
    for category, writer in writers.items():
        written = writer.close()
        key = _key_for(category)
        outputs[category] = {
            "s3_uri": f"s3://{bucket}/{key}",
            "record_count": writer.count,
            "bytes": written,
        }
        logger.info("Wrote %d %s records to s3://%s/%s",
                    writer.count, category, bucket, key)

    counts = {cat: writers[cat].count if cat in writers else 0
              for cat in list(_CATEGORIES) + ["uncategorized"]}
    manifest = {
        "source": "https://priceposting.abc.ca.gov/publicPricePosts",
        "generated_at": pulled_at,
        "filter": where,
        "order_by": order_by,
        "output_format": output_format,
        "total_available": total_available,
        "record_count": total,
        "truncated": bool(max_records and total_available
                          and total < total_available),
        "category_counts": counts,
        "outputs": outputs,
    }

    if write_manifest:
        manifest_key = f"{MANIFEST_PREFIX}run-{stamp}.json"
        s3.put_object(
            Bucket=bucket, Key=manifest_key,
            Body=json.dumps(manifest, indent=2, default=str).encode(),
            ContentType="application/json",
        )
        manifest["manifest_uri"] = f"s3://{bucket}/{manifest_key}"

    manifest["status"] = "ok"
    logger.info("Done. %d records: %s", total, counts)
    return manifest

