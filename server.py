import os
import asyncio
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import logging 
import hmac
import hashlib
import json
import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("main-server")

# ============ Configuration ============
class Config:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/marketplace")
    INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "internal_secret_key_change_me")
    OTP_SERVERS = os.getenv("OTP_SERVERS", "http://localhost:8001,http://localhost:8002,http://localhost:8003,http://localhost:8004,http://localhost:8005").split(",")
    OTP_TIMEOUT = int(os.getenv("OTP_TIMEOUT", "300"))
    RESERVATION_TIMEOUT = int(os.getenv("RESERVATION_TIMEOUT", "180"))
    MAIN_SERVER_URL = os.getenv("MAIN_SERVER_URL", "http://localhost:8000")
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
    OTP_SERVER_CAPACITY = int(os.getenv("OTP_SERVER_CAPACITY", "100"))
    MAX_RETRY_ATTEMPTS = int(os.getenv("MAX_RETRY_ATTEMPTS", "3"))
    MAX_OTP_ATTEMPTS = int(os.getenv("MAX_OTP_ATTEMPTS", "5"))
    MAX_DAILY_RETRIES = int(os.getenv("MAX_DAILY_RETRIES", "5"))
    CLEANUP_INTERVAL = int(os.getenv("CLEANUP_INTERVAL", "900"))
    SUPER_ADMIN_KEY = os.getenv("SUPER_ADMIN_KEY", "super_admin_key_123")
    OTP_RETRY_COOLDOWN_SECONDS = int(os.getenv("OTP_RETRY_COOLDOWN_SECONDS", "30"))
    MAX_OTP_RETRIES_AFTER_DETECTION = int(os.getenv("MAX_OTP_RETRIES_AFTER_DETECTION", "2"))
    STRICT_RATE_LIMIT_PER_MINUTE = int(os.getenv("STRICT_RATE_LIMIT_PER_MINUTE", "2"))
    ADMIN_CONTACT = os.getenv("ADMIN_CONTACT", "@your_admin_username")
    PROBLEM_AUTO_EXPIRE_HOURS = int(os.getenv("PROBLEM_AUTO_EXPIRE_HOURS", "24"))
    WEBHOOK_TIMEOUT = int(os.getenv("WEBHOOK_TIMEOUT", "10"))
    WEBHOOK_MAX_ATTEMPTS = int(os.getenv("WEBHOOK_MAX_ATTEMPTS", "4"))
    WEBHOOK_RETRY_BACKOFF = [5, 30, 120, 600]   # seconds, len must be >= MAX-1

config = Config()

# ============ Database Connection ============
class Database:
    pool: asyncpg.Pool = None

    @classmethod
    async def connect(cls):
        if not cls.pool:
            cls.pool = await asyncpg.create_pool(
                config.DATABASE_URL,
                min_size=1,
                max_size=20,
                command_timeout=60
            )
        return cls.pool

    @classmethod
    async def disconnect(cls):
        if cls.pool:
            await cls.pool.close()
            cls.pool = None

    @classmethod
    async def fetch(cls, query: str, *args):
        pool = await cls.connect()
        async with pool.acquire() as conn:
            return await conn.fetch(query, *args)

    @classmethod
    async def fetchrow(cls, query: str, *args):
        pool = await cls.connect()
        async with pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    @classmethod
    async def fetchval(cls, query: str, *args):
        pool = await cls.connect()
        async with pool.acquire() as conn:
            return await conn.fetchval(query, *args)
    @classmethod
    async def execute(cls, query: str, *args):
        pool = await cls.connect()
        async with pool.acquire() as conn:
            return await conn.execute(query, *args)

# ============ Pydantic Models ============
class EndpointRegistrationRequest(BaseModel):
    endpoint_name: str
    admin_telegram_id: int
    bot_token: str
    channel_username: str
    webhook_url: Optional[str] = Field(
        None, description="Per-endpoint webhook URL (https://...)"
    )
    webhook_enabled: Optional[bool] = False


class WebhookConfigUpdateRequest(BaseModel):
    webhook_url: Optional[str] = None       # None দিলে ক্লিয়ার হবে না
    webhook_enabled: Optional[bool] = None
    rotate_secret: Optional[bool] = False   # True দিলে নতুন secret generate হবে
    
class EndpointConfigCreateRequest(BaseModel):
    endpoint_name: str
    admin_api_key: str
    user_api_key: Optional[str] = None
    bot_token: Optional[str] = None
    admin_telegram_id: Optional[int] = None
    channel_username: Optional[str] = None

class UserRegistrationRequest(BaseModel):
    user_identifier: str = Field(..., min_length=1, max_length=255,
                                 description="User ID / Username / Email / etc.")
    user_type: str = Field(..., pattern="^(Id|Username|Email|Telegram|WhatsApp|Phone|Other)$",
                           description="Id, Username, Email, Telegram, etc.")
    initial_balance: Optional[float] = Field(0.0, ge=0,
                                             description="Optional starting balance")
                                             
class PurchaseInitiateRequest(BaseModel):
    country_code: str = Field(..., min_length=2, max_length=2)
    spam_status: str = Field(..., pattern="^(good|limited|bad)$")

class RetryOTPRequest(BaseModel):
    transaction_id: str
    purchase_code: str

class CancelReservationRequest(BaseModel):
    transaction_id: str
    user_identifier: Optional[str] = None

class AccountAddRequest(BaseModel):
    phone_number: str
    country_code: str = Field(..., min_length=2, max_length=2)
    country_name: str
    prefix: str
    spam_status: str = Field(..., pattern="^(good|limited|bad)$")
    session_string: str
    two_fa_password: Optional[str] = None
    price: Optional[float] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    account_age_days: Optional[int] = None
    profile_pic_url: Optional[str] = None
    bio: Optional[str] = None
    is_verified: Optional[bool] = False
    is_business: Optional[bool] = False
    last_active: Optional[datetime] = None
    quality_score: Optional[int] = Field(None, ge=0, le=100)

class BulkAccountsRequest(BaseModel):
    accounts: List[AccountAddRequest]

class PricingRequest(BaseModel):
    country_code: str = Field(..., min_length=2, max_length=2)
    country_name: str
    prefix: str
    base_price: float
    limited_price: float

class BalanceRequest(BaseModel):
    user_id: str
    user_type: str = Field(..., min_length=1, max_length=50)   # flexible
    amount: float

class UserBalanceRequest(BaseModel):
    user_id: str
    user_type: str = Field(..., pattern="^(telegram|bot|api)$")

class OTPServerCallback(BaseModel):
    phone_number: str
    otp_code: Optional[str] = None
    status: str
    transaction_id: Optional[str] = None
    purchase_code: Optional[str] = None
    message: Optional[str] = None

class OTPHealthCheck(BaseModel):
    server_url: str
    status: str
    available_slots: int
    active_requests: int
    last_checked: datetime

# ============ FastAPI App ============
app = FastAPI(
    title="Telegram Account Marketplace - Main Server",
    description="Main orchestration server for Telegram account management",
    version="3.2.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ Helper Functions ============
def _compute_webhook_signature(secret: str, body: bytes) -> str:
    """Returns 'sha256=<hex>'."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


async def fire_webhook(
    endpoint_name: str,
    event_type: str,
    payload: Dict[str, Any],
    transaction_id: Optional[str] = None,
) -> None:
    """
    Queue + fire webhook to the endpoint's configured URL.
    Non-blocking — delivery happens in a background task with retries.
    """
    cfg = await Database.fetchrow(
        """
        SELECT webhook_url, webhook_secret, webhook_enabled
        FROM endpoint_configs WHERE endpoint_name = $1
        """,
        endpoint_name,
    )
    if not cfg or not cfg['webhook_enabled'] or not cfg['webhook_url']:
        return  # endpoint has no webhook — silently skip

    # Ensure timestamp present
    payload = {**payload, 
               "timestamp": payload.get("timestamp") or datetime.now().isoformat(),
               "endpoint_name": payload.get("endpoint_name") or endpoint_name,
               "event": payload.get("event") or event_type}
    payload.setdefault("endpoint_name", endpoint_name)
    payload.setdefault("event", event_type)

    delivery_id = await Database.fetchval(
        """
        INSERT INTO webhook_deliveries
            (endpoint_name, event_type, transaction_id,
             webhook_url, payload, status)
        VALUES ($1, $2, $3, $4, $5::jsonb, 'pending')
        RETURNING delivery_id
        """,
        endpoint_name, event_type,
        transaction_id, cfg['webhook_url'],
        json.dumps(payload, separators=(',', ':'), default=str),
    )
    logger.info(
        "Webhook queued | delivery=%s endpoint=%s event=%s",
        delivery_id, endpoint_name, event_type,
    )
    asyncio.create_task(_deliver_webhook(str(delivery_id)))


async def _deliver_webhook(delivery_id: str) -> None:
    """Deliver a queued webhook with exponential backoff. Idempotent."""
    delivery = await Database.fetchrow(
        "SELECT * FROM webhook_deliveries WHERE delivery_id = $1",
        delivery_id,
    )
    if not delivery or delivery['status'] == 'delivered':
        return

    # recently attempted — skip (protect against duplicate spawn)
    if delivery['last_attempt_at'] and \
       (datetime.now() - delivery['last_attempt_at']).total_seconds() < 30:
        return

    cfg = await Database.fetchrow(
        "SELECT webhook_secret FROM endpoint_configs WHERE endpoint_name = $1",
        delivery['endpoint_name'],
    )
    secret = (cfg['webhook_secret'] if cfg else None) or ""
    if not secret:
        logger.error(
            "Webhook secret missing for endpoint=%s — refusing unsigned delivery | delivery=%s",
            delivery['endpoint_name'], delivery_id,
        )
        await Database.execute(
            """
            UPDATE webhook_deliveries
            SET status='failed', last_error='webhook_secret not configured'
            WHERE delivery_id = $1
            """,
            delivery_id,
        )
        return

    # asyncpg returns JSONB as str — use raw bytes so HMAC matches wire bytes
    raw = delivery['payload']
    if not isinstance(raw, str):
        raw = json.dumps(raw, separators=(',', ':'), default=str)
    body = raw.encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Event": delivery['event_type'],
        "X-Webhook-Delivery": str(delivery['delivery_id']),
        "User-Agent": "Marketplace-Webhook/1.0",
    }
    if secret:
        headers["X-Webhook-Signature"] = _compute_webhook_signature(secret, body)

    max_attempts = config.WEBHOOK_MAX_ATTEMPTS
    backoffs = config.WEBHOOK_RETRY_BACKOFF
    last_error = "unknown"

    for attempt in range(max_attempts):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    delivery['webhook_url'],
                    content=body,
                    headers=headers,
                    timeout=config.WEBHOOK_TIMEOUT,
                )

            code = resp.status_code
            await Database.execute(
                """
                UPDATE webhook_deliveries
                SET attempts = attempts + 1,
                    last_attempt_at = NOW(),
                    response_code = $2
                WHERE delivery_id = $1
                """,
                delivery_id, code,
            )

            if 200 <= code < 300:
                await Database.execute(
                    """
                    UPDATE webhook_deliveries
                    SET status = 'delivered', delivered_at = NOW(),
                        last_error = NULL
                    WHERE delivery_id = $1
                    """,
                    delivery_id,
                )
                logger.info(
                    "Webhook delivered | delivery=%s endpoint=%s event=%s code=%s",
                    delivery_id, delivery['endpoint_name'],
                    delivery['event_type'], code,
                )
                return

            last_error = f"HTTP {code}: {resp.text[:200]}"

        except Exception as e:
            last_error = str(e)[:500]
            await Database.execute(
                """
                UPDATE webhook_deliveries
                SET attempts = attempts + 1,
                    last_attempt_at = NOW(),
                    last_error = $2
                WHERE delivery_id = $1
                """,
                delivery_id, last_error,
            )

        # Not the last attempt — back off
        if attempt < max_attempts - 1:
            delay = backoffs[min(attempt, len(backoffs) - 1)]
            await asyncio.sleep(delay)

    # All attempts failed
    await Database.execute(
        """
        UPDATE webhook_deliveries
        SET status = 'failed', last_error = $2
        WHERE delivery_id = $1
        """,
        delivery_id, last_error,
    )
    logger.error(
        "Webhook FAILED after %d attempts | delivery=%s endpoint=%s err=%s",
        max_attempts, delivery_id, delivery['endpoint_name'], last_error,
    )
    
# ============ NEW: Immediate Balance Deduction ============
async def deduct_balance_immediately(
    transaction_id: str, 
    user_id: str, 
    user_type: str, 
    endpoint_name: str, 
    amount: float
) -> bool:
    """
    Purchase-request-এই balance deduct. 
    Atomic operation — fail হলে transaction fail হবে.
    """
    pool = await Database.connect()   # ✅ Always returns pool (creates if None)
    async with pool.acquire() as conn:   # ✅ Correct variable
        async with conn.transaction():
            # Balance check with row lock
            user_row = await conn.fetchrow(
                """
                SELECT balance FROM users 
                WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $3
                FOR UPDATE
                """,
                user_id, user_type, endpoint_name
            )
            
            if not user_row:
                raise HTTPException(status_code=400, detail="User not found. Contact admin.")
            
            current_balance = float(user_row['balance'])
            if current_balance < amount:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Insufficient balance. Required: {amount}, Available: {current_balance}"
                )
            
            # Deduct
            await conn.execute(
                """
                UPDATE users 
                SET balance = balance - $3, updated_at = NOW()
                WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $4
                """,
                user_id, user_type, amount, endpoint_name
            )
            
            # Mark transaction as deducted
            await conn.execute(
                """
                UPDATE transactions 
                SET balance_deducted = TRUE 
                WHERE transaction_id = $1
                """,
                transaction_id
            )
            
            return True

# ============ NEW: Strict Rate Limit (Post-Detection) ============
rate_limit_cache = {}

async def strict_rate_limit(user_id: str, endpoint_name: str):
    """
    OTP detect হওয়ার পরে এই user-এর জন্য কড়া rate limit।
    প্রতি minute-এ মাত্র 2টি request allowed.
    """
    key = f"strict:{endpoint_name}:{user_id}"
    current_time = datetime.now()
    minute_key = current_time.strftime("%Y%m%d%H%M")
    
    if key not in rate_limit_cache:
        rate_limit_cache[key] = {}
    
    if minute_key not in rate_limit_cache[key]:
        rate_limit_cache[key][minute_key] = 0
    
    rate_limit_cache[key][minute_key] += 1
    
    if rate_limit_cache[key][minute_key] > config.STRICT_RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429, 
            detail=(
                f"Strict rate limit exceeded (post-OTP-detection). "
                f"Max {config.STRICT_RATE_LIMIT_PER_MINUTE} requests/min. "
                f"Wait and try again."
            )
        )
    
    # Cleanup
    if len(rate_limit_cache[key]) > 10:
        sorted_keys = sorted(rate_limit_cache[key].keys())
        for old_key in sorted_keys[:-5]:
            del rate_limit_cache[key][old_key]


# ============ NEW: Cooldown Check ============
async def check_otp_cooldown(transaction_id: str):
    """
    Previous OTP request থেকে কমপক্ষে 30 second gap।
    """
    tx = await Database.fetchrow(
        "SELECT last_otp_request_at FROM transactions WHERE transaction_id = $1",
        transaction_id
    )
    if not tx or not tx['last_otp_request_at']:
        return
    
    elapsed = (datetime.now() - tx['last_otp_request_at']).total_seconds()
    if elapsed < config.OTP_RETRY_COOLDOWN_SECONDS:
        remaining = int(config.OTP_RETRY_COOLDOWN_SECONDS - elapsed)
        raise HTTPException(
            status_code=429, 
            detail=f"Cooldown active. Wait {remaining}s before requesting again."
        )
        
async def authenticate(api_key: str, endpoint_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Authenticate API key. If endpoint_name is provided, ensure the key belongs to that endpoint.
    Otherwise, derive endpoint from the key itself (for admin operations).
    """
    if endpoint_name:
        result = await Database.fetchrow(
            """
            SELECT * FROM endpoint_configs 
            WHERE endpoint_name = $1 
              AND (admin_api_key = $2 OR user_api_key = $2)
              AND is_active = TRUE
            """,
            endpoint_name, api_key
        )
    else:
        # Infer endpoint from the key (first match)
        result = await Database.fetchrow(
            """
            SELECT * FROM endpoint_configs 
            WHERE (admin_api_key = $1 OR user_api_key = $1)
              AND is_active = TRUE
            LIMIT 1
            """,
            api_key
        )
    
    if not result:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    is_admin = result['admin_api_key'] == api_key
    return {
        "is_admin": is_admin,
        "config": result,
        "endpoint_name": result['endpoint_name'],
        "user_type": "admin" if is_admin else "user"
    }

async def authenticate_user(user_api_key: str) -> Dict[str, Any]:
    """
    প্রতি-ইউজার API key verify করে।
    সফল হলে user_id / user_type / endpoint_name / balance সহ dict রিটার্ন করে।
    """
    if not user_api_key or not user_api_key.startswith("usr_"):
        raise HTTPException(status_code=401, detail="Invalid user API key format")

    result = await Database.fetchrow(
        """
        SELECT 
            u.user_id, u.user_type, u.endpoint_name, u.balance,
            ec.bot_token, ec.admin_telegram_id, ec.channel_username,
            ec.endpoint_name AS ec_endpoint, ec.is_active
        FROM users u
        JOIN endpoint_configs ec ON u.endpoint_name = ec.endpoint_name
        WHERE u.user_api_key = $1
          AND ec.is_active = TRUE
        """,
        user_api_key
    )

    if not result:
        raise HTTPException(status_code=401, detail="Invalid or inactive user API key")

    return {
        "is_admin": False,
        "user_id": result['user_id'],
        "user_type": result['user_type'],
        "endpoint_name": result['endpoint_name'],
        "balance": float(result['balance']),
        "config": {
            "endpoint_name": result['endpoint_name'],
            "bot_token": result['bot_token'],
            "admin_telegram_id": result['admin_telegram_id'],
            "channel_username": result['channel_username'],
        },
    }
    
async def get_user_balance(user_id: str, user_type: str, endpoint_name: str) -> float:
    """Get user balance for a specific endpoint"""
    result = await Database.fetchrow(
        """
        SELECT balance FROM users 
        WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $3
        """,
        user_id, user_type, endpoint_name
    )
    return float(result['balance']) if result else 0.0

async def get_pricing(country_code: str, spam_status: str, endpoint_name: str) -> Dict[str, Any]:
    """Get pricing for a specific endpoint"""
    result = await Database.fetchrow(
        """
        SELECT * FROM country_pricing 
        WHERE country_code = $1 AND endpoint_name = $2
        """,
        country_code, endpoint_name
    )
    
    if not result:
        raise HTTPException(status_code=404, detail="Country pricing not found for this endpoint")
    
    price = result['limited_price'] if spam_status == 'limited' else result['base_price']
    return {
        "price": float(price),
        "base_price": float(result['base_price']),
        "limited_price": float(result['limited_price'])
    }

async def reserve_account(country_code: str, spam_status: str, endpoint_name: str) -> Optional[Dict[str, Any]]:
    """Reserve an available account for a specific endpoint"""
    pool = await Database.connect()
    async with pool.acquire() as conn:
        async with conn.transaction():
            result = await conn.fetchrow(
                """
                UPDATE accounts 
                SET status = 'reserved', 
                    reserved_at = CURRENT_TIMESTAMP 
                WHERE account_id = (
                    SELECT account_id 
                    FROM accounts 
                    WHERE country_code = $1 
                      AND spam_status = $2 
                      AND endpoint_name = $3
                      AND status = 'available' 
                      AND (reserved_at IS NULL OR reserved_at < CURRENT_TIMESTAMP - INTERVAL '3 minutes')
                    ORDER BY created_at ASC 
                    LIMIT 1 
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING *
                """,
                country_code, spam_status, endpoint_name
            )
            
            if result:
                asyncio.create_task(auto_release_account(result['account_id']))
                return dict(result)
    return None

async def auto_release_account(account_id: str):
    """Auto release ONLY if balance wasn't deducted (safety for stuck reservations)"""
    await asyncio.sleep(config.RESERVATION_TIMEOUT)
    
    # Check: is there an active transaction with balance already deducted?
    active_tx = await Database.fetchrow(
        """
        SELECT transaction_id FROM transactions 
        WHERE account_id = $1 
          AND balance_deducted = TRUE
          AND status IN ('otp_pending', 'otp_detected')
        LIMIT 1
        """,
        account_id
    )
    
    if active_tx:
        # 🛡️ Balance already deducted — DO NOT release
        # Account will be released only when OTP detected or 24h auto-lock kicks in
        print(f"⏸️ Skipping auto-release: account {account_id} has active paid transaction")
        return
    
    # Safe to release — no money involved
    result = await Database.execute(
        """
        UPDATE accounts 
        SET status = 'available', reserved_at = NULL 
        WHERE account_id = $1 AND status = 'reserved'
        """,
        account_id
    )
    
    if result:
        await Database.execute(
            """
            UPDATE transactions 
            SET status = 'expired', completed_at = CURRENT_TIMESTAMP
            WHERE account_id = $1 AND status = 'pending' AND balance_deducted = FALSE
            """,
            account_id
        )

async def check_otp_server_health(server_url: str) -> Dict[str, Any]:
    """Check OTP server health and capacity"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{server_url}/health",
                timeout=5.0
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "url": server_url,
                    "healthy": True,
                    "available_slots": data.get("available_slots", 0),
                    "active_requests": data.get("active_requests", 0),
                    "capacity": data.get("capacity", config.OTP_SERVER_CAPACITY)
                }
        except:
            pass
    
    return {
        "url": server_url,
        "healthy": False,
        "available_slots": 0,
        "active_requests": 0,
        "capacity": config.OTP_SERVER_CAPACITY
    }

async def get_available_otp_server() -> str:
    """Get least loaded OTP server based on health check"""
    healthy_servers = []
    
    for server in config.OTP_SERVERS:
        health = await check_otp_server_health(server)
        if health["healthy"] and health["available_slots"] > 0:
            healthy_servers.append(health)
    
    if not healthy_servers:
        raise HTTPException(status_code=503, detail="No available OTP servers")
    
    healthy_servers.sort(key=lambda x: x["available_slots"], reverse=True)
    return healthy_servers[0]["url"]

async def send_to_otp_server(
    otp_server: str, 
    account: Dict[str, Any], 
    transaction_id: str, 
    purchase_code: str,
    endpoint_config: Dict[str, Any],
    user_identifier: Optional[str] = None,
    user_type: Optional[str] = None
):
    """Send account to OTP server with full flat payload"""
    async with httpx.AsyncClient() as client:
        try:
            payload = {
                # Account data
                "phone_number": account['phone_number'],
                "session_string": account['session_string'],
                "two_fa_password": account.get('two_fa_password'),
                "account_id": str(account['account_id']),
                "account_price": str(account.get('price', '0')),
                "spam_status": account.get('spam_status', 'unknown'),
                # Transaction data
                "transaction_id": transaction_id,
                "purchase_code": purchase_code,
                # User data (optional but useful for channel posting)
                "buyer_username": user_identifier if user_identifier else "Unknown",
                "buyer_id": user_identifier,
                "user_type": user_type,
                # Endpoint config (flat fields)
                "bot_token": endpoint_config.get('bot_token'),
                "admin_telegram_id": endpoint_config.get('admin_telegram_id'),
                "channel_username": endpoint_config.get('channel_username'),
                "channel_id": endpoint_config.get('channel_id'),  # if exists
                "endpoint_name": endpoint_config.get('endpoint_name'),
                "first_name": account.get('first_name'),
                "last_name": account.get('last_name'),
                "username": account.get('username'),
                "account_age_days": account.get('account_age_days'),
                "profile_pic_url": account.get('profile_pic_url'),
                "bio": account.get('bio'),
                "is_verified": account.get('is_verified', False),
                "is_business": account.get('is_business', False),
                "last_active": account.get('last_active').isoformat() if account.get('last_active') else None,
                "quality_score": account.get('quality_score'),
                # Callback URL
                "callback_url": f"{config.MAIN_SERVER_URL}/api/otp/callback"
            }
            
            response = await client.post(
                f"{otp_server}/api/otp/register",
                json=payload,
                headers={"X-Internal-Key": config.INTERNAL_API_KEY},
                timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            # ⚠️ Do NOT release account here — caller handles it based on balance_deducted
            raise HTTPException(
                status_code=500, 
                detail=f"Failed to register with OTP server: {str(e)}"
            )

async def create_transaction(
    user_identifier: str, 
    user_type: str, 
    account: Dict, 
    amount: float,
    purchase_code: str,
    endpoint_name: str
) -> Dict:
    transaction_id = str(uuid.uuid4())
    await Database.execute(
        """
        INSERT INTO transactions (
            transaction_id, user_id, user_type, account_id, 
            amount, country_code, spam_status, purchase_code, 
            otp_status, endpoint_name, status, balance_deducted,
            last_otp_request_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'none', $9, 'otp_pending', FALSE, NOW())
        """,
        transaction_id,
        user_identifier,
        user_type,
        account['account_id'],
        amount,
        account['country_code'],
        account['spam_status'],
        purchase_code,
        endpoint_name
    )
    
    return {
        "transaction_id": transaction_id,
        "amount": amount,
        "account_id": account['account_id'],
        "purchase_code": purchase_code,
        "endpoint_name": endpoint_name
    }
    
def hide_phone(phone_number: str) -> str:
    """Hide middle digits of phone number"""
    if len(phone_number) <= 6:
        return phone_number[:2] + "***" + phone_number[-2:]
    return phone_number[:3] + "****" + phone_number[-3:]

async def get_daily_retry_count(user_identifier: str, user_type: str, endpoint_name: str) -> int:
    """Get user's retry count for today for a specific endpoint"""
    result = await Database.fetchrow(
        """
        SELECT COUNT(*) as retry_count
        FROM transactions 
        WHERE user_id = $1 
          AND user_type = $2 
          AND endpoint_name = $3
          AND status = 'expired'
          AND created_at >= CURRENT_DATE
          AND created_at < CURRENT_DATE + INTERVAL '1 day'
        """,
        user_identifier, user_type, endpoint_name
    )
    return int(result['retry_count']) if result else 0

async def retry_stuck_webhooks():
    """Retry webhook deliveries stuck in 'pending' (e.g. after restart)."""
    while True:
        try:
            rows = await Database.fetch(
                """
                SELECT delivery_id FROM webhook_deliveries
                WHERE status = 'pending'
                  AND attempts < $1
                  AND (last_attempt_at IS NULL OR last_attempt_at < NOW() - INTERVAL '15 minutes')
                  AND created_at < NOW() - INTERVAL '1 minute'
                LIMIT 20
                """,
                config.WEBHOOK_MAX_ATTEMPTS,
            )
            await Database.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'failed', last_error = 'max_attempts_exhausted'
                WHERE status = 'pending' AND attempts >= $1
                  AND created_at < NOW() - INTERVAL '10 minutes'
                """,
                config.WEBHOOK_MAX_ATTEMPTS,
            )
            for r in rows:
                asyncio.create_task(_deliver_webhook(str(r['delivery_id'])))
        except Exception as e:
            logger.warning("Webhook retry loop error: %s", e)
        await asyncio.sleep(60)
        
async def cleanup_expired_transactions():
    """Cleanup old transactions, but NEVER auto-expire otp_pending"""
    while True:
        try:
            # Only expire truly stuck 'pending' (never sent to OTP server)
            rows = await Database.fetch(
                """
                SELECT t.transaction_id, t.account_id
                FROM transactions t
                WHERE t.status = 'pending'
                  AND t.created_at < CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                """
            )
            
            for row in rows:
                await Database.execute(
                    "UPDATE transactions SET status = 'problem', lock_reason = 'stuck_pending', locked_at = NOW() WHERE transaction_id = $1",
                    row['transaction_id']
                )
                await Database.execute(
                    "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1 AND status = 'reserved'",
                    row['account_id']
                )
            
            # 🔥 NEW: Auto-lock old otp_pending transactions (24h)
            await Database.execute(
                """
                UPDATE transactions 
                SET status = 'locked',
                    locked_at = NOW(),
                    lock_reason = 'auto_lock_after_24h'
                WHERE status IN ('otp_pending', 'otp_detected')
                  AND created_at < NOW() - INTERVAL '24 hours'
                """
            )
            await Database.execute(
                """
                DELETE FROM webhook_deliveries
                WHERE status = 'delivered' 
                  AND delivered_at < NOW() - INTERVAL '7 days'
                """
            )
        except Exception as e:
            print(f"Cleanup error: {e}")
        
        await asyncio.sleep(config.CLEANUP_INTERVAL)
# ============ Rate Limiting ============

async def rate_limit(api_key: str):
    current_time = datetime.now()
    minute_key = current_time.strftime("%Y%m%d%H%M")
    
    if api_key not in rate_limit_cache:
        rate_limit_cache[api_key] = {}
    
    if minute_key not in rate_limit_cache[api_key]:
        rate_limit_cache[api_key][minute_key] = 0   # ✅ এটা ঠিক
    
    rate_limit_cache[api_key][minute_key] += 1
    
    if rate_limit_cache[api_key][minute_key] > config.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Purge old minutes
    if len(rate_limit_cache[api_key]) > 10:
        sorted_keys = sorted(rate_limit_cache[api_key].keys())
        for old_key in sorted_keys[:-5]:
            del rate_limit_cache[api_key][old_key]

# ============ Health Check ============
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "3.2.0",
        "role": "main_server"
    }

# ============ Endpoint Registration (Super Admin) ============
@app.post("/api/admin/endpoint/register")
async def register_endpoint(
    request: EndpointRegistrationRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    if api_key != config.SUPER_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Super admin access required")

    admin_api_key = secrets.token_urlsafe(32)
    user_api_key = secrets.token_urlsafe(32)
    webhook_secret = secrets.token_urlsafe(32) if request.webhook_url else None

    await Database.execute(
        """
        INSERT INTO endpoint_configs 
        (endpoint_name, admin_api_key, user_api_key, bot_token,
         admin_telegram_id, channel_username,
         webhook_url, webhook_secret, webhook_enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (endpoint_name) 
        DO UPDATE SET 
            admin_api_key = $2,
            user_api_key = $3,
            bot_token = $4,
            admin_telegram_id = $5,
            channel_username = $6,
            webhook_url = COALESCE($7, endpoint_configs.webhook_url),
            webhook_enabled = COALESCE($9, endpoint_configs.webhook_enabled),
            webhook_secret = COALESCE(endpoint_configs.webhook_secret, $8),
            is_active = TRUE
        """,
        request.endpoint_name,
        admin_api_key,
        user_api_key,
        request.bot_token,
        request.admin_telegram_id,
        request.channel_username,
        request.webhook_url,
        webhook_secret,
        bool(request.webhook_enabled and request.webhook_url),
    )

    row = await Database.fetchrow(
        "SELECT webhook_secret FROM endpoint_configs WHERE endpoint_name = $1",
        request.endpoint_name,
    )

    return {
        "success": True,
        "endpoint": {
            "endpoint_name": request.endpoint_name,
            "admin_api_key": admin_api_key,
            "user_api_key": user_api_key,
            "webhook_url": request.webhook_url,
            "webhook_secret": row['webhook_secret'],   # ✅ actual persisted value
            "webhook_enabled": bool(request.webhook_enabled and request.webhook_url),
            "note": (
                "If webhook_secret was already set previously, this is the existing one. "
                "Use POST /api/admin/webhook/config with rotate_secret=true to change it."
            ),
        }
    }
@app.post("/api/admin/webhook/config")
async def update_webhook_config(
    request: WebhookConfigUpdateRequest,
    api_key: str = Header(..., alias="X-API-Key"),
):
    """Update webhook URL / enable / rotate secret (admin only)."""
    await rate_limit(api_key)
    admin_data = await authenticate(api_key)
    if not admin_data['is_admin']:
        raise HTTPException(403, "Admin only")
    endpoint_name = admin_data['endpoint_name']

    new_secret = None
    if request.rotate_secret:
        new_secret = secrets.token_urlsafe(32)

    await Database.execute(
        """
        UPDATE endpoint_configs
        SET webhook_url = COALESCE($2, webhook_url),
            webhook_enabled = COALESCE($3, webhook_enabled),
            webhook_secret = COALESCE($4, webhook_secret)
        WHERE endpoint_name = $1
        """,
        endpoint_name,
        request.webhook_url,
        request.webhook_enabled,
        new_secret,
    )

    row = await Database.fetchrow(
        """
        SELECT webhook_url, webhook_enabled FROM endpoint_configs
        WHERE endpoint_name = $1
        """,
        endpoint_name,
    )
    return {
        "success": True,
        "endpoint_name": endpoint_name,
        "webhook_url": row['webhook_url'],
        "webhook_enabled": row['webhook_enabled'],
        "new_secret": new_secret,
    }


@app.post("/api/admin/webhook/test")
async def test_webhook(
    api_key: str = Header(..., alias="X-API-Key"),
):
    """Send a test ping event to verify client's endpoint."""
    await rate_limit(api_key)
    admin_data = await authenticate(api_key)
    if not admin_data['is_admin']:
        raise HTTPException(403, "Admin only")
    endpoint_name = admin_data['endpoint_name']

    await fire_webhook(
        endpoint_name=endpoint_name,
        event_type="webhook.test",
        payload={
            "message": "This is a test event from marketplace server",
            "ok": True,
        },
    )
    return {"success": True, "message": "Test webhook queued"}


@app.get("/api/admin/webhook/deliveries")
async def list_webhook_deliveries(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    api_key: str = Header(..., alias="X-API-Key"),
):
    """Delivery log (admin only)."""
    await rate_limit(api_key)
    admin_data = await authenticate(api_key)
    if not admin_data['is_admin']:
        raise HTTPException(403, "Admin only")
    endpoint_name = admin_data['endpoint_name']

    where = "WHERE endpoint_name = $1"
    params: List[Any] = [endpoint_name]
    if status:
        params.append(status)
        where += f" AND status = ${len(params)}"

    rows = await Database.fetch(
        f"""
        SELECT delivery_id, event_type, transaction_id,
               status, attempts, response_code,
               last_error, created_at, delivered_at
        FROM webhook_deliveries
        {where}
        ORDER BY created_at DESC
        LIMIT ${len(params)+1} OFFSET ${len(params)+2}
        """,
        *params, limit, offset,
    )
    return {"success": True, "deliveries": [dict(r) for r in rows]}
    
# ============ Purchase Endpoints ============
@app.post("/api/purchase/initiate")
async def purchase_initiate(
    request: PurchaseInitiateRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """
    🔥 NEW FLOW:
    - User sends their OWN user_api_key (not admin key)
    - user_id / user_type / endpoint_name are derived from the API key
    - Balance check → stock check → DEDUCT immediately → reserve → OTP server
    - NO REFUND, NO CANCEL
    """
    await rate_limit(api_key)

    # ✅ User auth (endpoint auto-derived from the key)
    user_data = await authenticate_user(api_key)

    user_identifier = user_data['user_id']
    user_type       = user_data['user_type']
    endpoint_name   = user_data['endpoint_name']

    # 0. Admin guard (in case admin key leaks here)
    if user_data.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin cannot purchase accounts")

    # 1. Daily retry limit
    daily_retries = await get_daily_retry_count(user_identifier, user_type, endpoint_name)
    if daily_retries >= config.MAX_DAILY_RETRIES:
        raise HTTPException(
            status_code=429,
            detail=f"Daily retry limit reached. Contact {config.ADMIN_CONTACT}"
        )

    # 2. Balance check
    balance = await get_user_balance(user_identifier, user_type, endpoint_name)
    pricing = await get_pricing(request.country_code, request.spam_status, endpoint_name)

    if balance < pricing['price']:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient balance. Required: {pricing['price']}, Available: {balance}"
        )

    # 3. Stock check & reserve
    account = await reserve_account(request.country_code, request.spam_status, endpoint_name)
    if not account:
        raise HTTPException(status_code=404, detail="Stock not found for requested criteria")

    transaction = None

    async def _rollback(reason: str, original_exc: Exception, is_http: bool):
        """
        Rollback handler:
        - Release account ONLY if balance was NOT deducted
        - If balance WAS deducted → mark tx as 'problem' for admin
        - Always re-raise the appropriate exception (never swallow)
        """
        balance_was_deducted = False
        if transaction:
            tx_check = await Database.fetchrow(
                "SELECT balance_deducted FROM transactions WHERE transaction_id = $1",
                transaction['transaction_id']
            )
            balance_was_deducted = bool(tx_check and tx_check['balance_deducted'])

        # Release account only if balance not taken
        if account and not balance_was_deducted:
            await Database.execute(
                "UPDATE accounts SET status='available', reserved_at=NULL WHERE account_id=$1",
                account['account_id']
            )

        # 🆕 If transaction was never created — just re-raise original
        if not transaction:
            if is_http:
                raise original_exc
            raise HTTPException(
                status_code=500,
                detail=f"⚠️ Server error. Contact admin {config.ADMIN_CONTACT}"
            )

        if balance_was_deducted:
            # ⚠️ Balance gone → mark for admin, do NOT auto-refund
            logger.critical(
                "Balance deducted but flow failed | tx=%s | reason=%s | original=%r",
                transaction['transaction_id'], reason, original_exc
            )
            await Database.execute(
                """
                UPDATE transactions
                SET status='problem', lock_reason=$2, locked_at=NOW()
                WHERE transaction_id=$1
                """,
                transaction['transaction_id'], reason
            )
            raise HTTPException(
                status_code=500,
                detail=(
                    f"⚠️ Server error after balance deduction. "
                    f"Contact admin {config.ADMIN_CONTACT} immediately. "
                    f"Transaction ID: {transaction['transaction_id']}"
                )
            )
        else:
            # Balance safe → mark tx failed, re-raise original
            await Database.execute(
                """
                UPDATE transactions
                SET status='failed', lock_reason=$2
                WHERE transaction_id=$1
                """,
                transaction['transaction_id'], reason
            )
            if is_http:
                raise original_exc
            raise HTTPException(
                status_code=500,
                detail=(
                    f"⚠️ Server error. Contact admin {config.ADMIN_CONTACT} "
                    f"with transaction ID: {transaction['transaction_id']}"
                )
            )

    try:
        # 4. Create transaction record FIRST
        purchase_code = uuid.uuid4().hex[:10].upper()
        transaction = await create_transaction(
            user_identifier, user_type, account,
            pricing['price'], purchase_code, endpoint_name
        )

        # 5. DEDUCT balance immediately (atomic)
        await deduct_balance_immediately(
            transaction['transaction_id'],
            user_identifier, user_type, endpoint_name,
            pricing['price']
        )

        # 6. Send to OTP server
        otp_server = await get_available_otp_server()
        await send_to_otp_server(
            otp_server, account,
            transaction['transaction_id'],
            purchase_code,
            user_data['config'],
            user_identifier=user_identifier,
            user_type=user_type
        )

        # 7. Mark last OTP request
        await Database.execute(
            "UPDATE transactions SET last_otp_request_at = NOW() WHERE transaction_id = $1",
            transaction['transaction_id']
        )

        return {
            "success": True,
            "transaction_id": transaction['transaction_id'],
            "purchase_code": purchase_code,
            "phone_number": account['phone_number'],
            "first_name": account.get('first_name'),
            "last_name": account.get('last_name'),
            "username": account.get('username'),
            "account_age_days": account.get('account_age_days'),
            "is_verified": account.get('is_verified', False),
            "is_business": account.get('is_business', False),
            "quality_score": account.get('quality_score'),
            "price": pricing['price'],
            "two_fa_password": account.get('two_fa_password'),
            "otp_timeout": config.OTP_TIMEOUT,
            "endpoint_channel_username": user_data['config'].get('channel_username'),
            "daily_retries_remaining": config.MAX_DAILY_RETRIES - daily_retries,
            "balance_deducted": True,
            "no_refund": True,
            "admin_contact": config.ADMIN_CONTACT,
            "note": "Balance has been deducted. No cancellation or refund available."
        }

    except HTTPException as e:
        await _rollback(
            f"OTP server error after deduction: {e.detail}",
            original_exc=e,
            is_http=True
        )

    except Exception as e:
        await _rollback(
            f"Initiate error: {str(e)}",
            original_exc=e,
            is_http=False
        )

@app.post("/api/purchase/request-otp")
async def request_otp_again(
    request: RetryOTPRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """
    🔥 NEW FLOW:
    - OTP detected-এর আগে: normal retry (cooldown সহ)
    - OTP detected-এর পরে: STRICT retry (2-3 বার max, 30s cooldown)
    - Unauthorized হলেই বন্ধ
    """
    await rate_limit(api_key)
    
    tx = await Database.fetchrow(
        """
        SELECT * FROM transactions 
        WHERE transaction_id = $1 AND purchase_code = $2
        """,
        request.transaction_id, 
        request.purchase_code
    )
    
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    endpoint_name = tx['endpoint_name']

    # ✅ Dual-auth: per-user key vs admin key
    if api_key.startswith("usr_"):
        user_data = await authenticate_user(api_key)
        if user_data['endpoint_name'] != endpoint_name:
            raise HTTPException(403, "API key belongs to a different endpoint")
        if (user_data['user_id'] != tx['user_id']
                or user_data['user_type'] != tx['user_type']):
            raise HTTPException(403, "You can only retry your own transactions")
    else:
        user_data = await authenticate(api_key, endpoint_name)
        if not user_data['is_admin']:
            raise HTTPException(403, "Admin API key required")
    
    # 🔴 Blocked statuses
    if tx['status'] in ('unauthorized', 'cancelled', 'failed', 'problem'):
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot retry. Transaction is {tx['status']}. Contact {config.ADMIN_CONTACT}"
        )
    
    # 🔴 Cooldown check
    await check_otp_cooldown(request.transaction_id)
    
    # 🟡 STRICT MODE: OTP already detected once?
    otp_detected_before = tx['otp_detected_count'] > 0
    
    if otp_detected_before:
        # 🚨 STRICT PATH — scam prevention
        await strict_rate_limit(tx['user_id'], endpoint_name)
        
        # Strict retry limit
        if tx['otp_retry_count'] >= config.MAX_OTP_RETRIES_AFTER_DETECTION:
            # LOCK the transaction permanently
            await Database.execute(
                """
                UPDATE transactions 
                SET status = 'locked',
                    locked_at = NOW(),
                    lock_reason = 'max_retries_after_detection_exceeded'
                WHERE transaction_id = $1
                """,
                request.transaction_id
            )
            raise HTTPException(
                status_code=429,
                detail=(
                    f"🚫 LOCKED: Maximum retries after OTP detection exceeded "
                    f"({config.MAX_OTP_RETRIES_AFTER_DETECTION}). "
                    f"Contact admin {config.ADMIN_CONTACT} if this was a mistake."
                )
            )
    
    # Normal retry limit (before detection)
    if not otp_detected_before and tx['otp_attempts'] >= config.MAX_OTP_ATTEMPTS:
        raise HTTPException(
            status_code=429, 
            detail=f"Max OTP attempts reached. Contact {config.ADMIN_CONTACT}"
        )
    
    # Get or reserve account
    account = await Database.fetchrow(
        "SELECT * FROM accounts WHERE account_id = $1 AND status IN ('available', 'reserved')",
        tx['account_id']
    )
    
    if not account:
        account = await reserve_account(tx['country_code'], tx['spam_status'], endpoint_name)
        if not account:
            raise HTTPException(status_code=404, detail="No stock available")
        
        await Database.execute(
            "UPDATE transactions SET account_id = $1 WHERE transaction_id = $2",
            account['account_id'],
            request.transaction_id
        )
    
    # Update counters
    await Database.execute(
        """
        UPDATE transactions 
        SET otp_attempts = otp_attempts + 1,
            otp_retry_count = otp_retry_count + 1,
            last_otp_request_at = NOW(),
            otp_status = 'none'
        WHERE transaction_id = $1
        """,
        request.transaction_id
    )
    
    # Send to OTP server
    otp_server = await get_available_otp_server()
    try:
        await send_to_otp_server(
            otp_server,
            account,
            request.transaction_id,
            tx['purchase_code'],
            user_data['config'],
            user_identifier=tx['user_id'],
            user_type=tx['user_type']
        )
    except HTTPException as e:
        # Balance already deducted — mark problem
        await Database.execute(
            """
            UPDATE transactions 
            SET status = 'problem',
                lock_reason = $2,
                locked_at = NOW()
            WHERE transaction_id = $1
            """,
            request.transaction_id,
            f"OTP retry failed: {e.detail}"
        )
        raise HTTPException(
            status_code=500,
            detail=(
                f"⚠️ OTP retry failed. Balance already deducted. "
                f"Contact admin {config.ADMIN_CONTACT}. Transaction: {request.transaction_id}"
            )
        )
    
    # Response
    if otp_detected_before:
        remaining = config.MAX_OTP_RETRIES_AFTER_DETECTION - (tx['otp_retry_count'] + 1)
        return {
            "success": True,
            "message": "⚠️ STRICT MODE: OTP request sent (account already accessed before)",
            "strict_mode": True,
            "strict_retries_remaining": max(0, remaining),
            "cooldown_seconds": config.OTP_RETRY_COOLDOWN_SECONDS,
            "warning": "Repeated requests after OTP detection may result in account lock."
        }
    else:
        return {
            "success": True,
            "message": "OTP request sent",
            "strict_mode": False,
            "attempts_remaining": config.MAX_OTP_ATTEMPTS - (tx['otp_attempts'] + 1),
            "cooldown_seconds": config.OTP_RETRY_COOLDOWN_SECONDS,
            "daily_retries_remaining": config.MAX_DAILY_RETRIES - await get_daily_retry_count(
                tx['user_id'], tx['user_type'], endpoint_name
            )
        }

@app.post("/api/purchase/cancel")
async def cancel_reservation(
    request: CancelReservationRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """
    🔒 ADMIN-ONLY cancellation. 
    Users CANNOT cancel — no refund policy.
    """
    await rate_limit(api_key)
    
    transaction = await Database.fetchrow(
        "SELECT * FROM transactions WHERE transaction_id = $1",
        request.transaction_id
    )
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    user_data = await authenticate(api_key, transaction['endpoint_name'])
    
    if not user_data['is_admin']:
        raise HTTPException(
            status_code=403, 
            detail=(
                f"❌ Users cannot cancel. Balance already deducted (no refund). "
                f"Contact admin {config.ADMIN_CONTACT} for issues."
            )
        )
    
    # Admin override — can cancel + optionally refund
    await Database.execute(
        "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1 AND status = 'reserved'",
        transaction['account_id']
    )
    
    await Database.execute(
        """
        UPDATE transactions 
        SET status = 'cancelled_by_admin',
            locked_at = NOW(),
            lock_reason = 'admin_cancelled'
        WHERE transaction_id = $1
        """,
        request.transaction_id
    )
    
    return {
        "success": True,
        "message": "Transaction cancelled by admin. (Balance refund is manual.)"
    }

# ============ Internal Endpoints ============
@app.post("/api/otp/callback")
async def otp_callback(
    callback: OTPServerCallback,
    internal_api_key: str = Header(..., alias="X-Internal-Key")
):
    """
    🔥 NEW LOGIC:
    - detected → otp_detected (increment count, mark account sold)
    - timeout → otp_pending (KEEP trying)
    - unauthorized → unauthorized (FINAL, no refund)
    """
    if internal_api_key != config.INTERNAL_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid internal API key")
    
    if not callback.transaction_id:
        return {"success": False, "message": "Transaction ID required"}
    
    tx = await Database.fetchrow(
        """
        SELECT t.*,
               a.session_string, a.phone_number, a.two_fa_password,
               a.first_name, a.last_name, a.username,
               a.account_age_days, a.quality_score,
               a.is_verified, a.is_business,
               a.country_code AS acc_country, a.country_name
        FROM transactions t
        LEFT JOIN accounts a ON t.account_id = a.account_id
        WHERE t.transaction_id = $1
        """,
        callback.transaction_id,
    )
    
    if not tx:
        return {"success": False, "message": "Transaction not found"}
    
    endpoint_name = tx['endpoint_name']
    
    # ============ OTP DETECTED ============
    if callback.status == "detected":
        async with Database.pool.acquire() as conn:
            async with conn.transaction():
                # Increment detection counter
                await conn.execute(
                    """
                    UPDATE transactions 
                    SET otp_detected_count = otp_detected_count + 1,
                        first_otp_detected_at = COALESCE(first_otp_detected_at, NOW()),
                        status = 'otp_detected',
                        otp_status = 'detected'
                    WHERE transaction_id = $1
                    """,
                    callback.transaction_id
                )
                
                # Mark account sold (permanent)
                await conn.execute(
                    """
                    UPDATE accounts 
                    SET status = 'sold', sold_at = NOW(), reserved_at = NULL
                    WHERE account_id = $1
                    """,
                    tx['account_id']
                )
        
        # Store OTP code
        if callback.otp_code:
            await Database.execute(
                """
                INSERT INTO otp_requests (transaction_id, otp_code, status, expires_at)
                VALUES ($1, $2, 'sent', NOW() + INTERVAL '10 minutes')
                ON CONFLICT (transaction_id) 
                DO UPDATE SET otp_code = $2, status = 'sent', expires_at = NOW() + INTERVAL '10 minutes'
                """,
                callback.transaction_id,
                callback.otp_code
            )
        # 🔔 Fire client webhook (otp.received)
        await fire_webhook(
            endpoint_name=tx['endpoint_name'],
            event_type="otp.received",
            transaction_id=str(tx['transaction_id']),
            payload={
                "purchase_code": tx['purchase_code'],
                "phone_number": tx['phone_number'],
                "otp_code": callback.otp_code,
                "two_fa_password": tx['two_fa_password'],  # None হতে পারে
                "buyer": {
                    "id": tx['user_id'],
                    "type": tx['user_type'],
                },
                "account": {
                    "first_name": tx['first_name'],
                    "last_name": tx['last_name'],
                    "username": tx['username'],
                    "account_age_days": tx['account_age_days'],
                    "quality_score": tx['quality_score'],
                    "is_verified": tx['is_verified'],
                    "is_business": tx['is_business'],
                    "country_code": tx['acc_country'],
                    "country_name": tx['country_name'],
                },
            },
        )
        
        return {
            "success": True,
            "message": "✅ OTP detected — transaction marked. Account is now sold.",
            "otp_detected_count": tx['otp_detected_count'] + 1,
            "no_refund": True
        }
    
    # ============ OTP TIMEOUT (keep pending!) ============
    elif callback.status == "timeout":
        # 🔥 DO NOT EXPIRE — keep as otp_pending for retry
        await Database.execute(
            """
            UPDATE transactions 
            SET otp_status = 'timeout'
            WHERE transaction_id = $1 AND status NOT IN ('unauthorized', 'locked', 'cancelled')
            """,
            callback.transaction_id
        )
        await fire_webhook(
            endpoint_name=tx['endpoint_name'],
            event_type="otp.timeout",
            transaction_id=str(tx['transaction_id']),
            payload={
                "purchase_code": tx['purchase_code'],
                "phone_number": tx['phone_number'],
                "buyer": {"id": tx['user_id'], "type": tx['user_type']},
            },
        )
        # Account remains reserved — user can retry
        return {
            "success": True,
            "message": "⏳ OTP timeout — transaction still pending. You can retry.",
            "can_retry": True,
            "cooldown_seconds": config.OTP_RETRY_COOLDOWN_SECONDS
        }
    
    # ============ UNAUTHORIZED (final) ============
    elif callback.status in ("unauthorized", "session_expired"):
        await Database.execute(
            """
            UPDATE transactions 
            SET status = 'unauthorized',
                otp_status = $2,
                locked_at = NOW(),
                lock_reason = $2
            WHERE transaction_id = $1
            """,
            callback.transaction_id,
            callback.status
        )
        
        # Account marked sold (no reuse)
        await Database.execute(
            """
            UPDATE accounts 
            SET status = 'sold', sold_at = NOW(), reserved_at = NULL
            WHERE account_id = $1
            """,
            tx['account_id']
        )
        await fire_webhook(
            endpoint_name=tx['endpoint_name'],
            event_type="otp.unauthorized",
            transaction_id=str(tx['transaction_id']),
            payload={
                "purchase_code": tx['purchase_code'],
                "phone_number": tx['phone_number'],
                "reason": callback.status,
                "buyer": {"id": tx['user_id'], "type": tx['user_type']},
            },
        )
        return {
            "success": True,
            "message": (
                f"❌ {callback.status} — transaction closed. "
                f"NO REFUND. Contact admin {config.ADMIN_CONTACT} if problem."
            ),
            "final_status": "unauthorized",
            "no_refund": True,
            "admin_contact": config.ADMIN_CONTACT
        }
    
    else:
        return {"success": False, "message": f"Unknown status: {callback.status}"}

# ============ Admin Endpoints (Endpoint-aware) ============
@app.post("/api/admin/accounts")
async def add_single_account(
    account: AccountAddRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Add single account (admin only)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    endpoint_name = user_data['endpoint_name']
    
    if not account.price:
        pricing = await Database.fetchrow(
            "SELECT * FROM country_pricing WHERE country_code = $1 AND endpoint_name = $2",
            account.country_code, endpoint_name
        )
        if pricing:
            account.price = pricing['base_price'] if account.spam_status != 'limited' else pricing['limited_price']
        else:
            raise HTTPException(status_code=400, detail=f"No pricing found for country {account.country_code} in this endpoint")
    
    account_id = str(uuid.uuid4())
    await Database.execute(
        """
        INSERT INTO accounts (account_id, phone_number, country_code, country_name, prefix,
        spam_status, session_string, two_fa_password, price, endpoint_name,
        first_name, last_name, username, account_age_days, profile_pic_url,
        bio, is_verified, is_business, last_active, quality_score
    )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
        ON CONFLICT (phone_number, endpoint_name) 
        DO UPDATE SET 
            country_code = $3,
            country_name = $4,
            prefix = $5,
            spam_status = $6,
            session_string = $7,
            two_fa_password = $8,
            price = $9,
            endpoint_name = $10,
            first_name = $11,
            last_name = $12,
            username = $13,
            account_age_days = $14,
            profile_pic_url = $15,
            bio = $16,
            is_verified = $17,
            is_business = $18,
            last_active = $19,
            quality_score = $20,
            status = 'available',
            reserved_at = NULL,
            sold_at = NULL
        """,
        account_id,
        account.phone_number,
        account.country_code,
        account.country_name,
        account.prefix,
        account.spam_status,
        account.session_string,
        account.two_fa_password,  # <-- None হতে পারে
        float(account.price),
        endpoint_name,
        account.first_name,
        account.last_name,
        account.username,
        account.account_age_days,
        account.profile_pic_url,
        account.bio,
        account.is_verified,
        account.is_business,
        account.last_active,
        account.quality_score
    )
    
    return {"success": True, "account_id": account_id}

@app.post("/api/admin/accounts/bulk")
async def add_bulk_accounts(
    request: BulkAccountsRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Add bulk accounts (admin only)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    endpoint_name = user_data['endpoint_name']
    added_count = 0
    updated_count = 0
    errors = []
    
    pricing_cache = {}
    
    for account in request.accounts:
        try:
            if not account.price:
                if account.country_code not in pricing_cache:
                    pricing = await Database.fetchrow(
                        "SELECT * FROM country_pricing WHERE country_code = $1 AND endpoint_name = $2",
                        account.country_code, endpoint_name
                    )
                    if pricing:
                        pricing_cache[account.country_code] = pricing
                    else:
                        raise ValueError(f"No pricing found for country {account.country_code} in this endpoint")
                
                pricing = pricing_cache[account.country_code]
                account.price = pricing['base_price'] if account.spam_status != 'limited' else pricing['limited_price']
            
            account_id = str(uuid.uuid4())
            result = await Database.execute(
                """
                INSERT INTO accounts (
                account_id, phone_number, country_code, country_name, prefix,
                spam_status, session_string, two_fa_password, price, endpoint_name,
                first_name, last_name, username, account_age_days, profile_pic_url,
                bio, is_verified, is_business, last_active, quality_score
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
                ON CONFLICT (phone_number, endpoint_name) 
                DO UPDATE SET 
                    country_code = $3,
                    country_name = $4,
                    prefix = $5,
                    spam_status = $6,
                    session_string = $7,
                    two_fa_password = $8,
                    price = $9,
                    endpoint_name = $10,
                    first_name = $11,
                    last_name = $12,
                    username = $13,
                    account_age_days = $14,
                    profile_pic_url = $15,
                    bio = $16,
                    is_verified = $17,
                    is_business = $18,
                    last_active = $19,
                    quality_score = $20,
                    status = 'available',
                    reserved_at = NULL,
                    sold_at = NULL
                """,
                account_id,
                account.phone_number,
                account.country_code,
                account.country_name,
                account.prefix,
                account.spam_status,
                account.session_string,
                account.two_fa_password,  # <-- None হতে পারে
                float(account.price),
                endpoint_name,
                account.first_name,
                account.last_name,
                account.username,
                account.account_age_days,
                account.profile_pic_url,
                account.bio,
                account.is_verified,
                account.is_business,
                account.last_active,
                account.quality_score
            )
            
            if "INSERT" in result:
                added_count += 1
            else:
                updated_count += 1
        except Exception as e:
            errors.append({"phone_number": account.phone_number, "error": str(e)})
    
    return {
        "success": True,
        "added_count": added_count,
        "updated_count": updated_count,
        "errors": errors
    }

@app.post("/api/admin/pricing")
async def set_country_pricing(
    pricing: PricingRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Set country pricing (admin only)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    endpoint_name = user_data['endpoint_name']
    
    await Database.execute(
        """
        INSERT INTO country_pricing (country_code, country_name, prefix, base_price, limited_price, endpoint_name)
        VALUES ($1, $2, $3, $4::numeric, $5::numeric, $6)
        ON CONFLICT (country_code, endpoint_name) 
        DO UPDATE SET 
            country_name = $2,
            prefix = $3,
            base_price = $4::numeric,
            limited_price = $5::numeric
        """,
        pricing.country_code,
        pricing.country_name,
        pricing.prefix,
        float(pricing.base_price),
        float(pricing.limited_price),
        endpoint_name
    )
    
    await Database.execute(
        """
        UPDATE accounts 
        SET price = CASE 
            WHEN spam_status = 'limited' THEN $2::numeric
            ELSE $1::numeric
        END
        WHERE country_code = $3 AND endpoint_name = $4
        """,
        float(pricing.base_price),
        float(pricing.limited_price),
        pricing.country_code,
        endpoint_name
    )
    
    return {"success": True, "message": f"Pricing updated for {pricing.country_code} in endpoint {endpoint_name}"}

@app.post("/api/admin/users/register")
async def register_user(
    request: UserRegistrationRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """
    🔑 Admin API key দিয়ে নতুন user register।
    - endpoint_name admin key থেকেই পাওয়া যায়
    - per-user unique API key জেনারেট হয় (usr_ prefix)
    - same identifier দ্বিতীয়বার দিলে একই key ফেরত দেয় (idempotent)
    """
    await rate_limit(api_key)

    admin_data = await authenticate(api_key)
    if not admin_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin API key required")

    endpoint_name = admin_data['endpoint_name']

    # Already registered? Return existing key (idempotent)
    existing = await Database.fetchrow(
        """
        SELECT user_api_key, balance FROM users
        WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $3
        """,
        request.user_identifier, request.user_type, endpoint_name
    )

    if existing:
        existing_key = existing['user_api_key']

        # 🆕 key না থাকলে এই মুহূর্তে generate করে save করি
        if not existing_key:
            existing_key = f"usr_{secrets.token_urlsafe(32)}"
            await Database.execute(
                """UPDATE users SET user_api_key=$1
                   WHERE user_id=$2 AND user_type=$3 AND endpoint_name=$4""",
                existing_key, request.user_identifier,
                request.user_type, endpoint_name
            )

        return {
            "success": True,
            "already_registered": True,
            "message": "User already exists — returning existing API key",
            "user_id": request.user_identifier,
            "user_type": request.user_type,
            "endpoint_name": endpoint_name,
            "user_api_key": existing_key,
            "balance": float(existing['balance']),
        }

    # Generate unique per-user API key
    user_api_key = f"usr_{secrets.token_urlsafe(32)}"

    try:
        await Database.execute(
            """
            INSERT INTO users (user_id, user_type, balance, endpoint_name, user_api_key)
            VALUES ($1, $2, $3, $4, $5)
            """,
            request.user_identifier,
            request.user_type,
            float(request.initial_balance or 0.0),
            endpoint_name,
            user_api_key
        )
    except asyncpg.UniqueViolationError:
        row = await Database.fetchrow(
            """
            SELECT user_api_key, balance FROM users
            WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $3
            """,
            request.user_identifier, request.user_type, endpoint_name
        )
        key = row['user_api_key'] if row else None
        if not key:
            key = f"usr_{secrets.token_urlsafe(32)}"
            await Database.execute(
                """UPDATE users SET user_api_key=$1
                   WHERE user_id=$2 AND user_type=$3 AND endpoint_name=$4""",
                key, request.user_identifier, request.user_type, endpoint_name
            )
        return {
            "success": True,
            "already_registered": True,
            "user_id": request.user_identifier,
            "user_type": request.user_type,
            "endpoint_name": endpoint_name,
            "user_api_key": key,
            "balance": float(row['balance']) if row else 0.0,
        }
    return {
        "success": True,
        "already_registered": False,
        "message": "User registered successfully. Share this user_api_key with the user.",
        "user_id": request.user_identifier,
        "user_type": request.user_type,
        "endpoint_name": endpoint_name,
        "user_api_key": user_api_key,
        "initial_balance": float(request.initial_balance or 0.0),
    }
    
@app.post("/api/admin/users/balance")
async def add_user_balance(
    request: BalanceRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Add user balance (admin only). ইউজার রেজিস্টার্ড থাকতে হবে।"""
    await rate_limit(api_key)

    admin_data = await authenticate(api_key)
    if not admin_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")

    endpoint_name = admin_data['endpoint_name']

    # ✅ STEP 1: user exist করে কিনা চেক
    user_row = await Database.fetchrow(
        """
        SELECT user_api_key, balance FROM users
        WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $3
        """,
        request.user_id, request.user_type, endpoint_name
    )

    if not user_row:
        raise HTTPException(
            status_code=404,
            detail=(
                f"❌ User '{request.user_id}' ({request.user_type}) not registered "
                f"in endpoint '{endpoint_name}'. "
                f"Register first via POST /api/admin/users/register"
            )
        )

    # ✅ STEP 2: balance add
    await Database.execute(
        """
        UPDATE users 
        SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = $2 AND user_type = $3 AND endpoint_name = $4
        """,
        float(request.amount), request.user_id, request.user_type, endpoint_name
    )

    new_balance = await get_user_balance(request.user_id, request.user_type, endpoint_name)
    return {
        "success": True,
        "user_id": request.user_id,
        "user_type": request.user_type,
        "endpoint_name": endpoint_name,
        "amount_added": float(request.amount),
        "new_balance": new_balance,
        "user_api_key": user_row['user_api_key'],
    }

@app.get("/api/admin/accounts/list")
async def list_accounts(
    country_code: Optional[str] = None,
    spam_status: Optional[str] = None,
    has_username: Optional[bool] = None,  # নতুন ফিল্টার
    min_age_days: Optional[int] = None,   # নতুন ফিল্টার
    status: Optional[str] = "available",
    limit: int = 20,
    offset: int = 0,
    api_key: str = Header(..., alias="X-API-Key")
):
    await rate_limit(api_key)
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin only")
    
    endpoint_name = user_data['endpoint_name']
    
    query = "SELECT * FROM accounts WHERE endpoint_name = $1"
    params = [endpoint_name]
    count_query = "SELECT COUNT(*) FROM accounts WHERE endpoint_name = $1"
    count_params = [endpoint_name]
    idx = 2
    
    if status:
        query += f" AND status = ${idx}"
        count_query += f" AND status = ${idx}"
        params.append(status); count_params.append(status); idx += 1
    
    if country_code:
        query += f" AND country_code = ${idx}"
        count_query += f" AND country_code = ${idx}"
        params.append(country_code); count_params.append(country_code); idx += 1
    
    if spam_status:
        query += f" AND spam_status = ${idx}"
        count_query += f" AND spam_status = ${idx}"
        params.append(spam_status); count_params.append(spam_status); idx += 1
    
    if has_username is not None:
        if has_username:
            query += f" AND username IS NOT NULL AND username != ''"
            count_query += f" AND username IS NOT NULL AND username != ''"
        else:
            query += f" AND (username IS NULL OR username = '')"
            count_query += f" AND (username IS NULL OR username = '')"
    
    if min_age_days is not None:
        query += f" AND account_age_days >= ${idx}"
        count_query += f" AND account_age_days >= ${idx}"
        params.append(min_age_days); count_params.append(min_age_days); idx += 1
    
    # পেজিনেশন
    query += f" ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx+1}"
    params.extend([limit, offset])
    
    total = await Database.fetchval(count_query, *count_params)
    rows = await Database.fetch(query, *params)
    accounts = []
    for row in rows:
        account = dict(row)
        accounts.append(account)
    return {
        "success": True,
        "total": total,
        "limit": limit,
        "offset": offset,
        "accounts": accounts
    }
@app.get("/api/admin/stock")
async def view_stock(
    country_code: Optional[str] = None,
    spam_status: Optional[str] = None,
    api_key: str = Header(..., alias="X-API-Key")
):
    """View stock (admin only)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    endpoint_name = user_data['endpoint_name']
    
    query = """
        SELECT country_code, country_name, spam_status, status, COUNT(*) as count
        FROM accounts
        WHERE endpoint_name = $1
    """
    params = [endpoint_name]
    
    if country_code:
        params.append(country_code)
        query += f" AND country_code = ${len(params)}"
    
    if spam_status:
        params.append(spam_status)
        query += f" AND spam_status = ${len(params)}"
    
    query += " GROUP BY country_code, country_name, spam_status, status ORDER BY country_code, spam_status, status"
    
    results = await Database.fetch(query, *params)
    
    stock_summary = {}
    for row in results:
        key = f"{row['country_code']}_{row['spam_status']}"
        if key not in stock_summary:
            stock_summary[key] = {
                "country_code": row['country_code'],
                "country_name": row['country_name'],
                "spam_status": row['spam_status'],
                "available": 0,
                "reserved": 0,
                "sold": 0,
                "pending_takeover": 0,
                "total": 0
            }
        
        status = row['status']
        if status in stock_summary[key]:
            stock_summary[key][status] = row['count']
        stock_summary[key]['total'] += row['count']
    
    return {"success": True, "stock": list(stock_summary.values())}

@app.get("/api/admin/transaction/{transaction_id}")
async def get_transaction_details(
    transaction_id: str,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Get full transaction details including phone number (admin only)"""
    await rate_limit(api_key)
    
    # First get transaction to know endpoint
    tx = await Database.fetchrow(
        "SELECT endpoint_name FROM transactions WHERE transaction_id = $1",
        transaction_id
    )
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    user_data = await authenticate(api_key, tx['endpoint_name'])
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await Database.fetchrow(
        """
        SELECT 
            t.transaction_id,
            t.user_id,
            t.user_type,
            t.amount,
            t.country_code,
            t.spam_status,
            t.purchase_code,
            t.otp_status,
            t.otp_attempts,
            t.status,
            t.created_at,
            t.endpoint_name,
            a.phone_number,
            a.country_name,
            a.prefix
        FROM transactions t
        LEFT JOIN accounts a ON t.account_id = a.account_id
        WHERE t.transaction_id = $1
        """,
        transaction_id
    )
    
    if not result:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    return {
        "success": True,
        "transaction": {
            "transaction_id": result['transaction_id'],
            "user_id": result['user_id'],
            "amount": float(result['amount']),
            "country_code": result['country_code'],
            "country_name": result['country_name'],
            "spam_status": result['spam_status'],
            "purchase_code": result['purchase_code'],
            "otp_status": result['otp_status'],
            "status": result['status'],
            "phone_number": result['phone_number'],
            "prefix": result['prefix'],
            "endpoint_name": result['endpoint_name'],
            "created_at": result['created_at'].isoformat()
        }
    }

@app.get("/api/admin/transactions")
async def view_transactions(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    api_key: str = Header(..., alias="X-API-Key")
):
    """View transactions (admin only)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    endpoint_name = user_data['endpoint_name']
    
    query = "SELECT * FROM transactions WHERE endpoint_name = $1"
    params = [endpoint_name]
    
    if status:
        params.append(status)
        query += f" AND status = ${len(params)}"
    
    query += " ORDER BY created_at DESC LIMIT $" + str(len(params) + 1) + " OFFSET $" + str(len(params) + 2)
    params.extend([limit, offset])
    
    results = await Database.fetch(query, *params)
    
    transactions = []
    for row in results:
        transactions.append({
            "transaction_id": row['transaction_id'],
            "user_id": row['user_id'],
            "user_type": row['user_type'],
            "account_id": str(row['account_id']),
            "amount": float(row['amount']),
            "country_code": row['country_code'],
            "spam_status": row['spam_status'],
            "purchase_code": row['purchase_code'],
            "otp_status": row['otp_status'],
            "otp_attempts": row['otp_attempts'],
            "status": row['status'],
            "endpoint_name": row['endpoint_name'],
            "created_at": row['created_at'].isoformat(),
            "completed_at": row['completed_at'].isoformat() if row['completed_at'] else None
        })
    
    return {"success": True, "transactions": transactions, "count": len(transactions)}

# ============ User Endpoints (Endpoint-aware) ============
@app.post("/api/user/balance")
async def check_user_balance(
    api_key: str = Header(..., alias="X-API-Key")
):
    """নিজের balance চেক — শুধু API key পাঠান।"""
    await rate_limit(api_key)

    user_data = await authenticate_user(api_key)
    balance = await get_user_balance(
        user_data['user_id'], user_data['user_type'], user_data['endpoint_name']
    )

    return {
        "success": True,
        "user_id": user_data['user_id'],
        "user_type": user_data['user_type'],
        "endpoint_name": user_data['endpoint_name'],
        "balance": balance
    }

@app.get("/api/stock")
async def get_available_stock(api_key: str = Header(..., alias="X-API-Key")):
    await rate_limit(api_key)

    user_data = await authenticate_user(api_key)
    endpoint_name = user_data['endpoint_name']

    results = await Database.fetch(
        """
        SELECT a.country_code, a.country_name, a.spam_status,
               cp.base_price, cp.limited_price,
               COUNT(*) as available_count
        FROM accounts a
        LEFT JOIN country_pricing cp 
            ON a.country_code = cp.country_code AND a.endpoint_name = cp.endpoint_name
        WHERE a.status = 'available' AND a.endpoint_name = $1
        GROUP BY a.country_code, a.country_name, a.spam_status,
                 cp.base_price, cp.limited_price
        ORDER BY a.country_code, a.spam_status
        """,
        endpoint_name
    )

    stock = [{
        "country_code": r['country_code'],
        "country_name": r['country_name'],
        "spam_status": r['spam_status'],
        "price": float(r['limited_price'] if r['spam_status'] == 'limited' else r['base_price']),
        "available_count": r['available_count'],
    } for r in results]

    return {"success": True, "stock": stock}

# ============ Database Initialization ============
async def init_database():
    """Initialize database tables with endpoint support"""
    await Database.connect()
    
    # Users table with endpoint_name
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            user_type VARCHAR(50) NOT NULL,
            endpoint_name VARCHAR(255),
            balance DECIMAL(10,2) DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, user_type, endpoint_name)
        )
    """)
    
    # Accounts table with endpoint_name
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            phone_number VARCHAR(20) NOT NULL,
            country_code VARCHAR(2) NOT NULL,
            country_name VARCHAR(100),
            prefix VARCHAR(10),
            spam_status VARCHAR(20) NOT NULL,
            session_string TEXT NOT NULL,
            two_fa_password TEXT,
            price DECIMAL(10,2),
            status VARCHAR(20) DEFAULT 'available',
            reserved_at TIMESTAMP,
            sold_at TIMESTAMP,
            endpoint_name VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(phone_number)
        )
    """)
    
    # Transactions table with endpoint_name
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id VARCHAR(255) NOT NULL,
            user_type VARCHAR(50) NOT NULL,
            account_id UUID REFERENCES accounts(account_id),
            amount DECIMAL(10,2) NOT NULL,
            country_code VARCHAR(2),
            spam_status VARCHAR(20),
            purchase_code VARCHAR(50) UNIQUE,
            otp_status VARCHAR(20) DEFAULT 'none',
            otp_attempts INTEGER DEFAULT 0,
            status VARCHAR(20) DEFAULT 'pending',
            endpoint_name VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)
    
    # Country pricing with endpoint_name, composite unique
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS country_pricing (
            id SERIAL PRIMARY KEY,
            country_code VARCHAR(2) NOT NULL,
            country_name VARCHAR(100) NOT NULL,
            prefix VARCHAR(10) NOT NULL,
            base_price DECIMAL(10,2) NOT NULL,
            limited_price DECIMAL(10,2) NOT NULL,
            endpoint_name VARCHAR(255) NOT NULL,
            UNIQUE(country_code, endpoint_name)
        )
    """)
    
    # Endpoint configs
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_configs (
            id SERIAL PRIMARY KEY,
            endpoint_name VARCHAR(255) UNIQUE NOT NULL,
            admin_api_key VARCHAR(255),
            user_api_key VARCHAR(255),
            bot_token VARCHAR(255),
            admin_telegram_id BIGINT,
            channel_username VARCHAR(255),
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # OTP requests table (unchanged)
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS otp_requests (
            id SERIAL PRIMARY KEY,
            transaction_id UUID REFERENCES transactions(transaction_id),
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            status VARCHAR(20) DEFAULT 'pending',
            otp_code TEXT,
            notification_sent BOOLEAN DEFAULT FALSE
        )
    """)
    
    # 🆕 Migration: Add new columns if they don't exist
    await Database.execute("""
        ALTER TABLE accounts 
        ADD COLUMN IF NOT EXISTS first_name VARCHAR(100),
        ADD COLUMN IF NOT EXISTS last_name VARCHAR(100),
        ADD COLUMN IF NOT EXISTS username VARCHAR(100),
        ADD COLUMN IF NOT EXISTS account_age_days INTEGER,
        ADD COLUMN IF NOT EXISTS profile_pic_url TEXT,
        ADD COLUMN IF NOT EXISTS bio TEXT,
        ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS is_business BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS last_active TIMESTAMP,
        ADD COLUMN IF NOT EXISTS quality_score INTEGER
    """)
    
    # 🆕 Migration: transactions-এ নতুন column
    await Database.execute("""
        ALTER TABLE transactions 
        ADD COLUMN IF NOT EXISTS balance_deducted BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS otp_detected_count INTEGER DEFAULT 0,
        ADD COLUMN IF NOT EXISTS otp_retry_count INTEGER DEFAULT 0,
        ADD COLUMN IF NOT EXISTS first_otp_detected_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS last_otp_request_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS locked_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS lock_reason TEXT
    """)
    
    # 🆕 Endpoint webhook config
    await Database.execute("""
        ALTER TABLE endpoint_configs 
        ADD COLUMN IF NOT EXISTS webhook_url VARCHAR(500),
        ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(255),
        ADD COLUMN IF NOT EXISTS webhook_enabled BOOLEAN DEFAULT FALSE
    """)

    # 🆕 Webhook delivery log (retry queue)
    await Database.execute("""
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id SERIAL PRIMARY KEY,
            delivery_id UUID NOT NULL DEFAULT gen_random_uuid(),
            endpoint_name VARCHAR(255) NOT NULL,
            event_type VARCHAR(50) NOT NULL,
            transaction_id UUID,
            webhook_url VARCHAR(500) NOT NULL,
            payload JSONB NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            attempts INTEGER DEFAULT 0,
            last_attempt_at TIMESTAMP,
            last_error TEXT,
            response_code INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            delivered_at TIMESTAMP
        )
    """)
    await Database.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint 
        ON webhook_deliveries(endpoint_name, created_at DESC)
    """)
    await Database.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status 
        ON webhook_deliveries(status) WHERE status != 'delivered'
    """)
    # 🆕 Migration: users.user_api_key + unique index
    await Database.execute("""
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS user_api_key VARCHAR(255)
    """)
    await Database.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_api_key 
        ON users(user_api_key) 
        WHERE user_api_key IS NOT NULL
    """)
    # Indexes for performance
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_accounts_endpoint_status ON accounts(endpoint_name, status)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_accounts_endpoint_country_status ON accounts(endpoint_name, country_code, spam_status, status)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_transactions_endpoint_status ON transactions(endpoint_name, status)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_transactions_endpoint_created ON transactions(endpoint_name, created_at)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_transactions_purchase_code ON transactions(purchase_code)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_transactions_user_endpoint_date ON transactions(user_id, user_type, endpoint_name, created_at)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_users_endpoint ON users(endpoint_name)")
    await Database.execute("CREATE INDEX IF NOT EXISTS idx_pricing_endpoint ON country_pricing(endpoint_name)")
    
    # Insert default endpoint if not exists
    await Database.execute("""
        INSERT INTO endpoint_configs (endpoint_name, admin_api_key, user_api_key, bot_token, admin_telegram_id, channel_username)
        VALUES ('default', 'admin_key_123', 'user_key_123', NULL, NULL, NULL)
        ON CONFLICT (endpoint_name) DO NOTHING
    """)

    # 🆕 FIX: phone_number শুধু নিজের endpoint-এ unique
    await Database.execute("""
        ALTER TABLE accounts 
        DROP CONSTRAINT IF EXISTS accounts_phone_number_key
    """)
    await Database.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_phone_endpoint 
        ON accounts(phone_number, endpoint_name)
    """)
    
# ============ Startup/Shutdown Events ============
@app.on_event("startup")
async def startup_event():
    await init_database()
    asyncio.create_task(cleanup_expired_transactions())
    asyncio.create_task(retry_stuck_webhooks())
    print("🚀 Main Marketplace Server started successfully with Endpoint System!")
    print(f"📍 Database connected: {config.DATABASE_URL}")
    print(f"🔑 OTP Servers: {len(config.OTP_SERVERS)} configured")
    print(f"⏰ Auto-cleanup: Every {config.CLEANUP_INTERVAL} seconds")
    print(f"🎯 Role: Orchestration + Database + Callbacks")
    print(f"💳 Payment Policy: NO REFUND - Balance deducted on purchase request")
    print(f"🔒 Strict retry: {config.MAX_OTP_RETRIES_AFTER_DETECTION} after OTP detection")
    print(f"📞 Admin contact: {config.ADMIN_CONTACT}")
    print(f"🔄 Daily Retry Limit: {config.MAX_DAILY_RETRIES} per user per endpoint")
    print(f"🏢 Endpoint System: Enabled (each endpoint isolated)")
    print(f"🔐 User Registration: POST /api/admin/users/register")
    print(f"🎫 Per-User API Keys: Enabled (usr_ prefix)")

@app.on_event("shutdown")
async def shutdown_event():
    await Database.disconnect()
    print("👋 Main Marketplace Server shut down gracefully")

# ============ Main Entry Point ============
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )