# 飞书 → Clawdbot 桥接服务

将飞书机器人消息转发到 Clawdbot，实现飞书内与 AI 对话。

## 功能特性

### ✅ 已实现功能

1. **消息转发**
   - 私聊消息直接转发到 Clawdbot
   - 群聊 @机器人 消息转发到 Clawdbot
   - 支持文本消息
   - **消息带 chat_id 上下文**（Clawdbot 可以发文件回原群）

2. **白名单 & 权限系统**
   - `whitelist_feishu.json` - 控制谁可以使用机器人
   - `permissions.json` - 细粒度权限控制
   - 支持热更新（修改文件即生效，无需重启）

3. **权限角色**
   | 角色 | 权限 | 说明 |
   |------|------|------|
   | admin | * | 全部权限（含 exec） |
   | ecommerce_ops | chat, search, read, exec | 电商运营管理员 |
   | power_user | chat, search, read, write | 可读写文件 |
   | user | chat, search, read | 可搜索和读取 |
   | viewer | chat, search | 只能聊天和搜索 |

4. **文件发送**
   - 支持发送视频: mp4, mov, avi, mkv
   - 支持发送音频: mp3, wav, ogg, m4a
   - 支持发送文档: pdf, doc, xls, ppt 等
   - 视频/音频用 `media` 消息类型，文档用 `file` 类型

4. **权限申请流程**（卡片审批）
   - 新用户 @机器人 → 提示申请权限
   - 群聊申请 → 私聊处理（保护隐私）
   - 用户选择角色 (1/2/3)
   - 管理员收到审批卡片（批准/拒绝按钮）
   - 批准后自动添加白名单和权限

5. **多 Agent 路由**
   - 根据用户角色路由到不同 Clawdbot Agent
   - admin → clawdbot:main
   - power_user → clawdbot:power-user
   - user → clawdbot:user
   - viewer → clawdbot:viewer

## 配置文件

### whitelist_feishu.json
```json
{
  "enabled": true,
  "users": ["ou_xxx", "ou_yyy"],
  "note": "用户备注"
}
```

### permissions.json
```json
{
  "roles": { ... },
  "features": { ... },
  "users": {
    "ou_xxx": {
      "name": "用户名",
      "role": "admin",
      "chat_id": "oc_xxx"
    }
  }
}
```

## 安装

```bash
cd ~/clawd/feishu-bridge
pip install -r requirements.txt
```

## 配置

编辑 `server.py` 顶部配置：

```python
FEISHU_APP_ID = "cli_xxxxx"
FEISHU_APP_SECRET = "xxxxx"
FEISHU_VERIFICATION_TOKEN = "xxxxx"

CLAWDBOT_URL = "http://127.0.0.1:18789"
CLAWDBOT_TOKEN = "your-token"
```

## 飞书开放平台配置

1. **创建应用**: https://open.feishu.cn/ → 企业自建应用

2. **获取凭证**:
   - App ID / App Secret: 「凭证与基础信息」
   - Verification Token: 「事件订阅」

3. **开启机器人**: 应用能力 → 添加「机器人」

4. **事件订阅**:
   - 请求地址: `http://YOUR_SERVER:5001/webhook`
   - 添加事件: `im.message.receive_v1`

5. **权限配置**:
   - `im:message:send_as_bot` - 发送消息
   - `im:message:receive` - 接收消息
   - `im:chat:readonly` - 读取群信息
   - `contact:user.base:readonly` - 读取用户基本信息

6. **卡片回调**（权限审批用）:
   - 消息卡片请求网址: `http://YOUR_SERVER:5001/card_callback`

7. **发布应用**: 版本管理 → 创建版本 → 申请发布

## 运行

```bash
# 开发模式
python server.py

# systemd 服务 (推荐)
sudo cp feishu-bridge.service /etc/systemd/system/
sudo systemctl enable feishu-bridge
sudo systemctl start feishu-bridge

# 查看日志
sudo journalctl -u feishu-bridge -f
```

## 当前用户

查看 `permissions.json` 中的 users 部分。

## API 端点

- `GET /health` - 健康检查
- `POST /webhook` - 飞书事件回调
- `POST /card_callback` - 卡片交互回调

## 故障排查

```bash
# 查看服务状态
sudo systemctl status feishu-bridge

# 查看日志
sudo journalctl -u feishu-bridge --since "10 minutes ago"

# 重启服务
sudo systemctl restart feishu-bridge
```
