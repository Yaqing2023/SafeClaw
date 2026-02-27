# Feishu Bridge Architecture Documentation

## Overview

The Feishu Bridge is a Flask-based middleware service that connects Feishu (Lark) messaging platform to Clawdbot AI. It handles message routing, user authentication, role-based access control, and document processing.

## System Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Feishu    │◄────►│  Feishu Bridge   │◄────►│  Clawdbot   │
│  Platform   │      │  (Flask :5001)   │      │  (:18789)   │
└─────────────┘      └──────────────────┘      └─────────────┘
      │                      │
      │                      ▼
      │              ┌──────────────────┐
      │              │   Config Files   │
      │              │ - whitelist.json │
      │              │ - permissions.json│
      │              │ - pending.json   │
      │              └──────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Message Flow                              │
│  1. User sends message in Feishu (private or group chat)    │
│  2. Feishu webhook → /webhook endpoint                       │
│  3. Bridge checks whitelist & permissions                    │
│  4. Routes to appropriate Clawdbot agent based on role       │
│  5. Response sent back to Feishu chat                        │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Webhook Handler (`/webhook`)

The main entry point for all Feishu events.

**Message Deduplication:**
- Uses `MessageDeduplicator` class with LRU cache
- Prevents duplicate processing when Feishu retries webhooks
- TTL: 300 seconds, max cache size: 1000 events

**Event Processing Flow:**
```
Incoming Event
     │
     ▼
Token Verification (FEISHU_VERIFICATION_TOKEN)
     │
     ▼
Event Dedup Check (by event_id)
     │
     ▼
User Whitelist Check
     │
     ├── Not in whitelist → Permission Request Flow
     │
     └── In whitelist → Permission Check → Route to Agent
```

### 2. Card Callback Handler (`/card_callback`)

Handles interactive button clicks from approval cards.

**Actions:**
- `approve` - Approves user with selected role
- `reject` - Rejects the application

### 3. Notification Endpoints

- `POST /notify` - Send text message (supports chat_id or open_id)
- `POST /send_file` - Upload and send file to chat

---

## Role-Based Access Control (RBAC)

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    RBAC System                               │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Whitelist   │───►│  Permissions │───►│ Agent Router │   │
│  │ (Gate Check) │    │ (Role Lookup)│    │ (Capability) │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Layer 1: Whitelist (`whitelist_feishu.json`)

**Purpose:** First-layer access control - determines who can interact with the bot at all.

**Structure:**
```json
{
  "enabled": true,
  "users": ["ou_xxx", "ou_yyy", "ou_zzz"],
  "note": "User1 / User2 / User3"
}
```

**Behavior:**
- `enabled: false` → All users allowed (whitelist disabled)
- `enabled: true` + empty users → All users allowed
- `enabled: true` + users list → Only listed users allowed
- Accepts: `user_id`, `open_id`, or `union_id`

**Hot Reload:**
- File modification time checked on each request
- Cache invalidated when file changes
- No service restart required

### Layer 2: Permissions (`permissions.json`)

**Purpose:** Fine-grained permission control - determines what each user can do.

**Structure:**
```json
{
  "roles": {
    "admin": {
      "description": "Full access",
      "features": ["*"]
    },
    "ecommerce_ops": {
      "description": "E-commerce operations",
      "features": ["chat", "search", "read", "exec"]
    },
    "power_user": {
      "description": "Can read/write files",
      "features": ["chat", "search", "read", "write"]
    },
    "user": {
      "description": "Can search and read",
      "features": ["chat", "search", "read"]
    },
    "viewer": {
      "description": "Chat and search only",
      "features": ["chat", "search"]
    }
  },
  "features": {
    "chat": "Talk to the bot",
    "search": "Web search",
    "read": "Read files",
    "write": "Write files",
    "exec": "Execute commands"
  },
  "users": {
    "ou_xxx": {
      "name": "Username",
      "role": "admin",
      "chat_id": "oc_xxx"
    }
  }
}
```

**Role Hierarchy:**
| Role | Features | Clawdbot Agent |
|------|----------|----------------|
| admin | * (all) | clawdbot:main |
| ecommerce_ops | chat, search, read, exec | clawdbot:main |
| power_user | chat, search, read, write | clawdbot:power-user |
| user | chat, search, read | clawdbot:user |
| viewer | chat, search | clawdbot:viewer |

**Wildcard Support:**
- `"features": ["*"]` grants all defined features

### Layer 3: Agent Routing

Based on user role, messages are routed to different Clawdbot agents with varying capabilities:

```python
ROLE_TO_AGENT = {
    "admin": "clawdbot:main",         # Full tool access
    "ecommerce_ops": "clawdbot:main", # E-commerce operations
    "power_user": "clawdbot:power-user",  # No exec
    "user": "clawdbot:user",          # Read-only
    "viewer": "clawdbot:viewer"       # Chat/search only
}
```

### Message Context Injection

When forwarding messages to Clawdbot, the bridge injects metadata into the message:

```
[飞书消息 | 用户: 王亚卿 | 角色: admin | chat_id: oc_xxx]

原始消息内容...
```

This allows Clawdbot to:
- Know the user's name and role
- **Know the chat_id to send files/media back to the correct chat**

**Why chat_id matters:**
When the bot needs to send files (e.g., AI-generated videos), it must know which chat to send them to. The `chat_id` in the context enables this.

### Permission Request Flow

```
New User Message
      │
      ▼
┌─────────────────┐
│ Whitelist Check │
│   (FAIL)        │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Is "申请权限" / "申请" / "/request"? │
└────────────────┬────────────────────┘
                 │
         ┌───────┴───────┐
         │               │
         ▼               ▼
     Group Chat      Private Chat
         │               │
         ▼               ▼
    Send hint:       Start role
    "私聊我申请"     selection flow
                         │
                         ▼
              ┌──────────────────┐
              │ User selects     │
              │ 1=viewer         │
              │ 2=user           │
              │ 3=power_user     │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Save to pending  │
              │ requests.json    │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Send approval    │
              │ card to admins   │
              └────────┬─────────┘
                       │
         ┌─────────────┴─────────────┐
         │                           │
         ▼                           ▼
    Admin clicks              Admin clicks
    "✅ [role]"               "❌ 拒绝"
         │                           │
         ▼                           ▼
┌──────────────────┐      ┌──────────────────┐
│ Add to whitelist │      │ Remove from      │
│ Add to permissions│      │ pending list     │
│ Notify user      │      │ Notify user      │
└──────────────────┘      └──────────────────┘
```

**Session State Management:**
- `user_sessions` dict tracks users in role selection flow
- State: `selecting_role` with timestamp
- Cleared after successful submission

---

## Document Processing

### Supported File Types (Reading)

| Type | Extensions | Parser | Max Limit |
|------|------------|--------|-----------|
| Excel | .xls, .xlsx | pandas | 100 rows |
| PDF | .pdf | PyMuPDF (fitz) | 50,000 chars |
| Word | .doc, .docx | python-docx | 50,000 chars |
| PPT | .ppt, .pptx | python-pptx | 50,000 chars |
| Markdown | .md | Native read | 50,000 chars |
| Text | .txt, .json, .yaml, etc. | Native read | 50,000 chars |

### Supported File Types (Sending)

| Type | Extensions | file_type | msg_type |
|------|------------|-----------|----------|
| Video | .mp4, .mov, .avi, .mkv | mp4 | media |
| Audio | .mp3, .wav, .ogg, .m4a | opus | media |
| Excel | .xls, .xlsx | xls | file |
| PDF | .pdf | pdf | file |
| Word | .doc, .docx | doc | file |
| PPT | .ppt, .pptx | ppt | file |
| Other | * | stream | file |

**Note:** Video and audio files use `msg_type: "media"`, while documents use `msg_type: "file"`.

### File Processing Flow

```
File Message Received
        │
        ▼
┌─────────────────┐
│ Check file type │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Download file   │
│ (via Feishu API)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Parse to text   │
│ (type-specific) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Build prompt    │
│ with content    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Send to Clawdbot│
│ for analysis    │
└─────────────────┘
```

### Recent File Lookup

For group chats, users can say "读文件" / "看文件" to analyze the most recently sent file:

```python
def find_recent_file(chat_id, max_messages=20):
    # Fetches recent messages via Feishu API
    # Returns first file message found
```

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/webhook` | POST | Feishu event callback |
| `/card_callback` | POST | Card button interactions |
| `/notify` | POST | Send notification message |
| `/send_file` | POST | Upload and send file |
| `/health` | GET | Health check |

### Notify API

```bash
# Send to group chat
curl -X POST http://localhost:5001/notify \
  -H "Content-Type: application/json" \
  -d '{"chat_id": "oc_xxx", "message": "Hello"}'

# Send private message
curl -X POST http://localhost:5001/notify \
  -H "Content-Type: application/json" \
  -d '{"open_id": "ou_xxx", "message": "Hello"}'
```

### Send File API

```bash
curl -X POST http://localhost:5001/send_file \
  -H "Content-Type: application/json" \
  -d '{
    "chat_id": "oc_xxx",
    "file_path": "/path/to/file.xlsx",
    "file_name": "report.xlsx",
    "caption": "Here is the report"
  }'
```

---

## Configuration

### Environment Variables (in server.py)

```python
FEISHU_APP_ID = "cli_xxx"
FEISHU_APP_SECRET = "xxx"
FEISHU_VERIFICATION_TOKEN = "xxx"
CLAWDBOT_URL = "http://127.0.0.1:18789"
CLAWDBOT_TOKEN = "xxx"
```

### Feishu Platform Setup

1. **Required Permissions:**
   - `im:message:send_as_bot` - Send messages
   - `im:message:receive` - Receive messages
   - `im:chat:readonly` - Read chat info
   - `contact:user.base:readonly` - Read user info

2. **Event Subscriptions:**
   - `im.message.receive_v1` - Message receive event

3. **Card Callback URL:**
   - For approval cards: `http://SERVER:5001/card_callback`

---

## Hot Reload Support

Both configuration files support hot reload:

```python
# Whitelist cache with mtime check
whitelist_cache = {"data": None, "mtime": 0}

def load_whitelist():
    mtime = os.path.getmtime(WHITELIST_FILE)
    if whitelist_cache["mtime"] != mtime:
        # Reload from disk
        whitelist_cache["data"] = json.load(f)
        whitelist_cache["mtime"] = mtime
```

**To update permissions without restart:**
1. Edit `whitelist_feishu.json` or `permissions.json`
2. Save the file
3. Next request will pick up changes automatically

---

## Error Handling

### Rate Limiting
- Detects 429 responses and returns friendly message
- Timeout handling with user-friendly feedback

### Graceful Degradation
- If Clawdbot unavailable, returns "服务暂时不可用"
- Empty responses filtered (won't send "No response from Clawdbot.")

---

## Service Management

```bash
# Systemd service
sudo systemctl start feishu-bridge
sudo systemctl stop feishu-bridge
sudo systemctl restart feishu-bridge
sudo systemctl status feishu-bridge

# View logs
sudo journalctl -u feishu-bridge -f
sudo journalctl -u feishu-bridge --since "10 minutes ago"
```
