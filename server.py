import os
import asyncio
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from decimal import Decimal
import random
import json

import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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
    CLEANUP_INTERVAL = int(os.getenv("CLEANUP_INTERVAL", "60"))
    SUPER_ADMIN_KEY = os.getenv("SUPER_ADMIN_KEY", "super_admin_key_123")

config = Config()

# ============ Database Connection ============
class Database:
    pool: asyncpg.Pool = None

    @classmethod
    async def connect(cls):
        if not cls.pool:
            cls.pool = await asyncpg.create_pool(
                config.DATABASE_URL,
                min_size=5,
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

class EndpointConfigCreateRequest(BaseModel):
    endpoint_name: str
    admin_api_key: str
    user_api_key: Optional[str] = None
    bot_token: Optional[str] = None
    admin_telegram_id: Optional[int] = None
    channel_username: Optional[str] = None

class PurchaseInitiateRequest(BaseModel):
    endpoint_name: str  # Endpoint name required for purchase
    user_identifier: str = Field(..., description="User ID or identifier")
    user_type: str = Field(..., pattern="^(telegram|bot|api)$")
    country_code: str = Field(..., min_length=2, max_length=2)
    spam_status: str = Field(..., pattern="^(good|limited|bad)$")

class PurchaseVerifyRequest(BaseModel):
    transaction_id: str
    otp_code: str = Field(..., min_length=4, max_length=10)

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
    user_type: str = Field(..., pattern="^(telegram|bot|api)$")
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
    async with Database.pool.acquire() as conn:
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
    """Auto release account if not sold within timeout"""
    await asyncio.sleep(config.RESERVATION_TIMEOUT)
    
    result = await Database.execute(
        """
        UPDATE accounts 
        SET status = 'available', reserved_at = NULL 
        WHERE account_id = $1 AND status = 'reserved'
        RETURNING account_id
        """,
        account_id
    )
    
    if result:
        await Database.execute(
            """
            UPDATE transactions 
            SET status = 'expired', completed_at = CURRENT_TIMESTAMP
            WHERE account_id = $1 AND status IN ('pending', 'otp_pending')
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
    endpoint_config: Dict[str, Any]
):
    """Send account to OTP server with endpoint configuration"""
    async with httpx.AsyncClient() as client:
        try:
            payload = {
                "phone_number": account['phone_number'],
                "session_string": account['session_string'],
                "two_fa_password": account['two_fa_password'],
                "transaction_id": transaction_id,
                "purchase_code": purchase_code,
                "endpoint_config": {
                    "bot_token": endpoint_config.get('bot_token'),
                    "admin_telegram_id": endpoint_config.get('admin_telegram_id'),
                    "channel_username": endpoint_config.get('channel_username')
                },
                "callback_url": f"{config.MAIN_SERVER_URL}/api/otp/callback"
            }
            
            response = await client.post(
                f"{otp_server}/api/otp/register",
                json=payload,
                headers={
                    "X-Internal-Key": config.INTERNAL_API_KEY
                },
                timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            await Database.execute(
                "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1",
                account['account_id']
            )
            raise HTTPException(status_code=500, detail=f"Failed to register with OTP server: {str(e)}")

async def deduct_balance(user_id: str, user_type: str, endpoint_name: str, amount: float):
    """Deduct user balance for specific endpoint"""
    result = await Database.execute(
        """
        UPDATE users 
        SET balance = balance - $3, updated_at = CURRENT_TIMESTAMP 
        WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $4 AND balance >= $3
        """,
        user_id, user_type, amount, endpoint_name
    )
    
    if "UPDATE 0" in result:
        raise HTTPException(status_code=400, detail="Insufficient balance")

async def mark_account_sold(account_id: str):
    """Mark account as sold"""
    await Database.execute(
        """
        UPDATE accounts 
        SET status = 'sold', sold_at = CURRENT_TIMESTAMP 
        WHERE account_id = $1
        """,
        account_id
    )

async def create_transaction(
    user_identifier: str, 
    user_type: str, 
    account: Dict, 
    amount: float,
    purchase_code: str,
    endpoint_name: str
) -> Dict:
    """Create transaction record with purchase code and endpoint"""
    transaction_id = str(uuid.uuid4())
    await Database.execute(
        """
        INSERT INTO transactions (
            transaction_id, user_id, user_type, account_id, 
            amount, country_code, spam_status, purchase_code, otp_status, endpoint_name
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'none', $9)
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

async def mark_transaction_complete(transaction_id: str, account_id: str, user_id: str, user_type: str, endpoint_name: str, amount: float):
    """Mark transaction as complete and deduct balance - NO REFUND POLICY"""
    async with Database.pool.acquire() as conn:
        async with conn.transaction():
            check = await conn.fetchrow(
                "SELECT status FROM transactions WHERE transaction_id = $1 FOR UPDATE",
                transaction_id
            )
            
            if check['status'] == 'completed':
                return False
            
            result = await conn.execute(
                """
                UPDATE users 
                SET balance = balance - $3, updated_at = CURRENT_TIMESTAMP 
                WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $4 AND balance >= $3
                """,
                user_id, user_type, amount, endpoint_name
            )
            
            if "UPDATE 0" in result:
                await conn.execute(
                    "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1",
                    account_id
                )
                await conn.execute(
                    "UPDATE transactions SET status = 'failed', completed_at = NOW() WHERE transaction_id = $1",
                    transaction_id
                )
                raise HTTPException(status_code=400, detail="Insufficient balance")
            
            await conn.execute(
                """
                UPDATE transactions 
                SET status = 'completed', 
                    otp_status = 'detected',
                    completed_at = NOW() 
                WHERE transaction_id = $1
                """,
                transaction_id
            )
            
            await conn.execute(
                """
                UPDATE accounts 
                SET status = 'sold', 
                    sold_at = NOW(),
                    reserved_at = NULL
                WHERE account_id = $1
                """,
                account_id
            )
            
            return True

async def mark_transaction_expired(transaction_id: str, account_id: str):
    """Mark transaction as expired and release account for retry"""
    await Database.execute(
        """
        UPDATE transactions 
        SET status = 'expired', 
            otp_status = 'expired',
            completed_at = NOW() 
        WHERE transaction_id = $1 AND status NOT IN ('completed', 'cancelled')
        """,
        transaction_id
    )
    
    await Database.execute(
        """
        UPDATE accounts 
        SET status = 'available', 
            reserved_at = NULL 
        WHERE account_id = $1 AND status IN ('reserved', 'pending_takeover')
        """,
        account_id
    )

async def mark_account_takeover_complete(transaction_id: str, account_id: str, user_id: str, user_type: str, endpoint_name: str, amount: float):
    """Mark account takeover as complete (unauthorized/session_expired status)"""
    async with Database.pool.acquire() as conn:
        async with conn.transaction():
            check = await conn.fetchrow(
                "SELECT status FROM transactions WHERE transaction_id = $1 FOR UPDATE",
                transaction_id
            )
            
            if check['status'] == 'completed':
                return False
            
            if check['status'] in ('otp_sent', 'pending', 'otp_pending'):
                result = await conn.execute(
                    """
                    UPDATE users 
                    SET balance = balance - $3, updated_at = CURRENT_TIMESTAMP 
                    WHERE user_id = $1 AND user_type = $2 AND endpoint_name = $4 AND balance >= $3
                    """,
                    user_id, user_type, amount, endpoint_name
                )
                
                if "UPDATE 0" in result:
                    await conn.execute(
                        "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1",
                        account_id
                    )
                    raise HTTPException(status_code=400, detail="Insufficient balance")
            
            await conn.execute(
                """
                UPDATE transactions 
                SET status = 'completed', 
                    otp_status = 'unauthorized',
                    completed_at = NOW() 
                WHERE transaction_id = $1
                """,
                transaction_id
            )
            
            await conn.execute(
                """
                UPDATE accounts 
                SET status = 'sold', 
                    sold_at = NOW(),
                    reserved_at = NULL
                WHERE account_id = $1
                """,
                account_id
            )
            
            return True

async def cleanup_expired_transactions():
    """Background task to cleanup expired transactions"""
    while True:
        try:
            result = await Database.fetch(
                """
                SELECT t.transaction_id, t.account_id
                FROM transactions t
                WHERE t.status IN ('pending', 'otp_pending')
                  AND t.created_at < CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                """
            )
            
            for row in result:
                await Database.execute(
                    "UPDATE transactions SET status = 'expired', completed_at = CURRENT_TIMESTAMP WHERE transaction_id = $1",
                    row['transaction_id']
                )
                
                await Database.execute(
                    "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1 AND status = 'reserved'",
                    row['account_id']
                )
            
        except Exception as e:
            print(f"Error in cleanup task: {str(e)}")
        
        await asyncio.sleep(config.CLEANUP_INTERVAL)

# ============ Rate Limiting ============
rate_limit_cache = {}

async def rate_limit(api_key: str):
    """Simple rate limiting"""
    current_time = datetime.now()
    minute_key = current_time.strftime("%Y%m%d%H%M")
    
    if api_key not in rate_limit_cache:
        rate_limit_cache[api_key] = {}
    
    if minute_key not in rate_limit_cache[api_key]:
        rate_limit_cache[api_key] = {minute_key: 0}
    
    rate_limit_cache[api_key][minute_key] += 1
    
    if rate_limit_cache[api_key][minute_key] > config.RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
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
    """Register new endpoint with auto-generated API keys"""
    if api_key != config.SUPER_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Super admin access required")
    
    # Generate random API keys
    admin_api_key = secrets.token_urlsafe(32)
    user_api_key = secrets.token_urlsafe(32)
    
    await Database.execute(
        """
        INSERT INTO endpoint_configs 
        (endpoint_name, admin_api_key, user_api_key, bot_token, admin_telegram_id, channel_username)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (endpoint_name) 
        DO UPDATE SET 
            admin_api_key = $2,
            user_api_key = $3,
            bot_token = $4,
            admin_telegram_id = $5,
            channel_username = $6,
            is_active = TRUE
        """,
        request.endpoint_name,
        admin_api_key,
        user_api_key,
        request.bot_token,
        request.admin_telegram_id,
        request.channel_username
    )
    
    return {
        "success": True,
        "endpoint": {
            "endpoint_name": request.endpoint_name,
            "admin_api_key": admin_api_key,
            "user_api_key": user_api_key,
            "admin_telegram_id": request.admin_telegram_id,
            "bot_token": request.bot_token,
            "channel_username": request.channel_username
        }
    }

# ============ Purchase Endpoints ============
@app.post("/api/purchase/initiate")
async def purchase_initiate(
    request: PurchaseInitiateRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Initiate purchase flow (endpoint-aware)"""
    await rate_limit(api_key)
    
    # Authenticate with endpoint
    user_data = await authenticate(api_key, request.endpoint_name)
    
    if user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin cannot purchase accounts")
    
    endpoint_name = user_data['endpoint_name']
    
    daily_retries = await get_daily_retry_count(request.user_identifier, request.user_type, endpoint_name)
    if daily_retries >= config.MAX_DAILY_RETRIES:
        raise HTTPException(
            status_code=429, 
            detail=f"Daily retry limit reached ({config.MAX_DAILY_RETRIES}). Please try again tomorrow."
        )
    
    balance = await get_user_balance(request.user_identifier, request.user_type, endpoint_name)
    pricing = await get_pricing(request.country_code, request.spam_status, endpoint_name)
    
    if balance < pricing['price']:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    account = await reserve_account(request.country_code, request.spam_status, endpoint_name)
    
    if not account:
        raise HTTPException(status_code=404, detail="Stock not found for requested criteria")
    
    try:
        purchase_code = uuid.uuid4().hex[:10].upper()
        
        transaction = await create_transaction(
            request.user_identifier,
            request.user_type,
            account,
            pricing['price'],
            purchase_code,
            endpoint_name
        )
        
        otp_server = await get_available_otp_server()
        
        await send_to_otp_server(
            otp_server, 
            account, 
            transaction['transaction_id'],
            purchase_code,
            user_data['config']
        )
        
        return {
            "success": True,
            "transaction_id": transaction['transaction_id'],
            "purchase_code": purchase_code,
            "phone_number": account['phone_number'],
            "price": pricing['price'],
            "otp_timeout": config.OTP_TIMEOUT,
            "reservation_timeout": config.RESERVATION_TIMEOUT,
            "daily_retries_remaining": config.MAX_DAILY_RETRIES - daily_retries
        }
    except Exception as e:
        await Database.execute(
            "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1",
            account['account_id']
        )
        await Database.execute(
            "UPDATE transactions SET status = 'failed' WHERE transaction_id = $1",
            transaction['transaction_id']
        )
        raise e

@app.post("/api/purchase/request-otp")
async def request_otp_again(
    request: RetryOTPRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Request OTP again (endpoint-aware)"""
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
    
    # Determine endpoint from transaction
    endpoint_name = tx['endpoint_name']
    
    # Authenticate with endpoint
    user_data = await authenticate(api_key, endpoint_name)
    
    daily_retries = await get_daily_retry_count(tx['user_id'], tx['user_type'], endpoint_name)
    if daily_retries >= config.MAX_DAILY_RETRIES:
        raise HTTPException(
            status_code=429, 
            detail=f"Daily retry limit reached ({config.MAX_DAILY_RETRIES}). Please try again tomorrow."
        )
    
    if tx['status'] not in ('expired', 'otp_pending'):
        raise HTTPException(status_code=400, detail="Cannot request OTP at this stage")
    
    if tx['otp_attempts'] >= config.MAX_OTP_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Max OTP attempts reached for this transaction")
    
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
    
    await Database.execute(
        """
        UPDATE transactions 
        SET otp_attempts = otp_attempts + 1, 
            status = 'otp_pending', 
            otp_status = 'none'
        WHERE transaction_id = $1
        """,
        request.transaction_id
    )
    
    otp_server = await get_available_otp_server()
    await send_to_otp_server(
        otp_server,
        account,
        request.transaction_id,
        tx['purchase_code'],
        user_data['config']
    )
    
    return {
        "success": True,
        "message": "OTP request sent successfully",
        "attempts_remaining": config.MAX_OTP_ATTEMPTS - (tx['otp_attempts'] + 1),
        "daily_retries_remaining": config.MAX_DAILY_RETRIES - daily_retries
    }

@app.post("/api/purchase/cancel")
async def cancel_reservation(
    request: CancelReservationRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Cancel reservation (endpoint-aware)"""
    await rate_limit(api_key)
    
    transaction = await Database.fetchrow(
        "SELECT * FROM transactions WHERE transaction_id = $1 AND status IN ('pending', 'otp_pending')",
        request.transaction_id
    )
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found or not pending")
    
    user_data = await authenticate(api_key, transaction['endpoint_name'])
    
    if request.user_identifier and not user_data['is_admin']:
        if transaction['user_id'] != request.user_identifier:
            raise HTTPException(status_code=403, detail="Not authorized to cancel this transaction")
    
    await Database.execute(
        "UPDATE accounts SET status = 'available', reserved_at = NULL WHERE account_id = $1",
        transaction['account_id']
    )
    
    await Database.execute(
        "UPDATE transactions SET status = 'cancelled' WHERE transaction_id = $1",
        request.transaction_id
    )
    
    return {"success": True, "message": "Reservation cancelled successfully"}

# ============ Internal Endpoints ============
@app.post("/api/otp/callback")
async def otp_callback(
    callback: OTPServerCallback,
    internal_api_key: str = Header(..., alias="X-Internal-Key")
):
    """OTP server callback endpoint (endpoint-aware)"""
    if internal_api_key != config.INTERNAL_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid internal API key")
    
    if not callback.transaction_id:
        return {"success": False, "message": "Transaction ID required"}
    
    tx = await Database.fetchrow(
        """
        SELECT t.*, a.session_string 
        FROM transactions t
        LEFT JOIN accounts a ON t.account_id = a.account_id
        WHERE t.transaction_id = $1
        """,
        callback.transaction_id
    )
    
    if not tx:
        return {"success": False, "message": "Transaction not found"}
    
    endpoint_name = tx['endpoint_name']
    
    if callback.status == "detected":
        try:
            completed = await mark_transaction_complete(
                callback.transaction_id,
                tx['account_id'],
                tx['user_id'],
                tx['user_type'],
                endpoint_name,
                float(tx['amount'])
            )
            
            if not completed:
                return {"success": False, "message": "Transaction already completed"}
            
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
            
            return {
                "success": True, 
                "message": "OTP detected - transaction completed and balance deducted",
                "completed": True,
                "no_refund": True
            }
        except HTTPException as e:
            return {"success": False, "message": str(e.detail)}
        except Exception as e:
            return {"success": False, "message": f"Error completing transaction: {str(e)}"}
    
    elif callback.status == "timeout":
        await mark_transaction_expired(callback.transaction_id, tx['account_id'])
        return {
            "success": True, 
            "message": "OTP timeout - transaction expired",
            "can_retry": True,
            "retry_limit": config.MAX_DAILY_RETRIES
        }
    
    elif callback.status in ("unauthorized", "session_expired"):
        try:
            completed = await mark_account_takeover_complete(
                callback.transaction_id,
                tx['account_id'],
                tx['user_id'],
                tx['user_type'],
                endpoint_name,
                float(tx['amount'])
            )
            
            if not completed:
                return {"success": False, "message": "Transaction already completed"}
            
            return {
                "success": True, 
                "message": f"{callback.status.replace('_', ' ').title()} - takeover confirmed and balance deducted",
                "completed": True,
                "no_refund": True
            }
        except HTTPException as e:
            return {"success": False, "message": str(e.detail)}
        except Exception as e:
            return {"success": False, "message": f"Error completing takeover: {str(e)}"}
    
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
        INSERT INTO accounts (account_id, phone_number, country_code, country_name, prefix, spam_status, session_string, two_fa_password, price, endpoint_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (phone_number) 
        DO UPDATE SET 
            country_code = $3,
            country_name = $4,
            prefix = $5,
            spam_status = $6,
            session_string = $7,
            two_fa_password = $8,
            price = $9,
            endpoint_name = $10,
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
        account.two_fa_password,
        float(account.price),
        endpoint_name
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
                INSERT INTO accounts (account_id, phone_number, country_code, country_name, prefix, spam_status, session_string, two_fa_password, price, endpoint_name)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (phone_number) 
                DO UPDATE SET 
                    country_code = $3,
                    country_name = $4,
                    prefix = $5,
                    spam_status = $6,
                    session_string = $7,
                    two_fa_password = $8,
                    price = $9,
                    endpoint_name = $10,
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
                account.two_fa_password,
                account.price,
                endpoint_name
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

@app.post("/api/admin/users/balance")
async def add_user_balance(
    request: BalanceRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Add user balance (admin only)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    if not user_data['is_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    endpoint_name = user_data['endpoint_name']
    
    await Database.execute(
        """
        INSERT INTO users (user_id, user_type, balance, endpoint_name)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, user_type, endpoint_name) 
        DO UPDATE SET 
            balance = users.balance + $3,
            updated_at = CURRENT_TIMESTAMP
        """,
        request.user_id,
        request.user_type,
        request.amount,
        endpoint_name
    )
    
    balance = await get_user_balance(request.user_id, request.user_type, endpoint_name)
    return {"success": True, "user_id": request.user_id, "new_balance": balance}

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
    request: UserBalanceRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    """Check user balance (user or admin)"""
    await rate_limit(api_key)
    
    # Need endpoint; we can infer from API key if user, but if admin, we also need endpoint.
    # We'll attempt to authenticate without explicit endpoint; if it's admin, we might need to specify endpoint in request? 
    # Better: require endpoint in request? But user might not know endpoint name. 
    # For simplicity, we keep as is: authenticate and use the endpoint from the key.
    # However, if a user key is used, it belongs to exactly one endpoint, so we can derive it.
    # If an admin key is used, we also derive one endpoint; that's fine for admin checking their own users.
    user_data = await authenticate(api_key)
    endpoint_name = user_data['endpoint_name']
    
    balance = await get_user_balance(request.user_id, request.user_type, endpoint_name)
    return {
        "success": True,
        "user_id": request.user_id,
        "user_type": request.user_type,
        "endpoint_name": endpoint_name,
        "balance": balance
    }

@app.get("/api/stock")
async def get_available_stock(
    api_key: str = Header(..., alias="X-API-Key")
):
    """Get available stock (public for any authenticated user)"""
    await rate_limit(api_key)
    
    user_data = await authenticate(api_key)
    endpoint_name = user_data['endpoint_name']
    
    results = await Database.fetch(
        """
        SELECT 
            a.country_code,
            a.country_name,
            a.spam_status,
            cp.base_price,
            cp.limited_price,
            COUNT(*) as available_count
        FROM accounts a
        LEFT JOIN country_pricing cp ON a.country_code = cp.country_code AND a.endpoint_name = cp.endpoint_name
        WHERE a.status = 'available' AND a.endpoint_name = $1
        GROUP BY a.country_code, a.country_name, a.spam_status, cp.base_price, cp.limited_price
        ORDER BY a.country_code, a.spam_status
        """,
        endpoint_name
    )
    
    stock = []
    for row in results:
        stock.append({
            "country_code": row['country_code'],
            "country_name": row['country_name'],
            "spam_status": row['spam_status'],
            "price": float(row['limited_price'] if row['spam_status'] == 'limited' else row['base_price']),
            "available_count": row['available_count']
        })
    
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
    
    # Insert default user for default endpoint
    await Database.execute("""
        INSERT INTO users (user_id, user_type, balance, endpoint_name)
        VALUES ('test_user', 'api', 100.00, 'default')
        ON CONFLICT (user_id, user_type, endpoint_name) DO NOTHING
    """)

# ============ Startup/Shutdown Events ============
@app.on_event("startup")
async def startup_event():
    await init_database()
    asyncio.create_task(cleanup_expired_transactions())
    print("🚀 Main Marketplace Server started successfully with Endpoint System!")
    print(f"📍 Database connected: {config.DATABASE_URL}")
    print(f"🔑 OTP Servers: {len(config.OTP_SERVERS)} configured")
    print(f"⏰ Auto-cleanup: Every {config.CLEANUP_INTERVAL} seconds")
    print(f"🎯 Role: Orchestration + Database + Callbacks")
    print(f"💳 Payment Policy: NO REFUND - Balance deducted on OTP detection")
    print(f"🔄 Daily Retry Limit: {config.MAX_DAILY_RETRIES} per user per endpoint")
    print(f"🏢 Endpoint System: Enabled (each endpoint isolated)")

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
