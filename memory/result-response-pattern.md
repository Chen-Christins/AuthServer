---
name: result-response-pattern
description: 所有 JSON 响应必须通过 Result 结构体处理，不写裸 JSON
metadata:
  type: project
---

**All JSON responses must use the `Result` struct**, not raw JSON strings or `JsonUtil::ToString` directly.

Pattern:
- `result->setResult(code, msg)` for status
- `result->set(key, value)` for data fields  
- `result->append(key, value)` for arrays
- `response->setBody(result->toJsonString())` at the end

**Why:** The `AuthServlet` base class provides `Result::ptr` to every handler. It standardizes the response envelope `{code, message, used, data}` and automatically tracks timing via `used_`.

**How to apply:** Never write `response->setBody("{\"error\":...}")`. Always populate the `result` parameter and call `result->toJsonString()`.
