---
name: cpp-code-style
description: C++ 代码规范 — 本项目的 C++ 编码风格、命名约定、注释规范等详细说明。编写或修改任何 C++ 代码时遵循此规范。
type: project
---

# C++ 代码规范

本规范基于 `chen` 项目的实际编码实践总结而来，适用于项目中所有 C++ 源代码（`.h` / `.cc` / `.cpp`）的编写和修改。

---

## 1. 文件组织

### 1.1 文件头注释

每个头文件和源文件必须以 Doxygen 风格的文件头注释开始：

```cpp
/**
 * @file filename.h
 * @brief 模块简要说明
 * @author Christins
 * @date YYYY-MM-DD
 * @copyright Apache 2.0
 */
```

### 1.2 Include Guard

使用 `#pragma once`：

```cpp
#pragma once

// ... 文件内容 ...
```

> **迁移计划：** 现有代码使用 `#ifndef` / `#define` / `#endif` 宏守卫，后续将全部替换为 `#pragma once`。
> **新文件必须使用 `#pragma once`。**

### 1.3 Include 顺序

遵循以下顺序，各组之间用空行分隔：

1. 对应的头文件（源文件 `#include "xxx.h"` 始终在第一行）
2. 本项目其他头文件（使用引号 `""`）
3. 第三方库头文件（使用尖括号 `<>`）
4. 标准库头文件（使用尖括号 `<>`）

每个组内按字母顺序排列。

```cpp
#include "application.h"

#include "config/config.h"
#include "daemon.h"
#include "env.h"
#include "module.h"

#include <yaml-cpp/yaml.h>

#include <memory>
#include <mutex>
#include <string>
```

---

## 2. 缩进与排版

### 2.1 基本设置

| 规则 | 值 |
|------|-----|
| 缩进宽度 | 4 个空格（不使用 Tab） |
| Tab 宽度 | 4 个空格 |
| 行宽限制 | 135 字符 |
| 最大连续空行 | 1 行 |
| 文件结尾 | 必须有且仅有一个换行符 |

### 2.2 访问修饰符

`public:` / `protected:` / `private:` 不缩进（对齐到 class 关键字）：

```cpp
class Foo {
public:
    void doSomething();

private:
    int m_value;
};
```

### 2.3 尾随空格

不允许行尾有空格。

### 2.4 空行规范

- 函数之间空一行
- 不同逻辑块之间可以空一行
- 最多连续空一行
- namespace `{` 前空一行（如果上方有 `#include` 或注释）

---

## 3. 大括号规范

### 3.1 类/结构体/枚举/命名空间 — 左大括号与声明同行

```cpp
class Foo {
public:
    // ...
};

struct Node {
    char* ptr;
    Node* next;
};

enum Level {
    DEBUG = 1,
    INFO = 2,
};

namespace chen {
// ...
}
```

### 3.2 函数/方法 — 左大括号另起一行

```cpp
void Foo::doSomething(int arg) {
    if (arg > 0) {
        // ...
    }
}
```

```cpp
bool Application::init(int argc, char** argv) {
    m_argc = argc;
    m_argv = argv;
    // ...
    return true;
}
```

### 3.3 if / else if / else — 左大括号与条件同行

```cpp
if (condition) {
    // ...
} else if (other_condition) {
    // ...
} else {
    // ...
}
```

**规则：** `if`、`for`、`while`、`switch` 等控制语句的大括号始终不省略，即使只有一行语句：

```cpp
// 正确
if (ptr) {
    return ptr->getValue();
}

// 错误
if (ptr)
    return ptr->getValue();
```

### 3.4 for / while / do-while — 左大括号与关键字同行

```cpp
for (auto& i : modules) {
    i->onServerReady();
}

for (size_t i = 0; i < node.size(); ++i) {
    // ...
}

while (condition) {
    // ...
}
```

### 3.5 switch-case — 左大括号同行，case 与 switch 同缩进

```cpp
switch (level) {
case LogLevel::DEBUG:
    color = "\033[1;34m";
    break;
case LogLevel::INFO:
    color = "\033[1;32m";
    break;
default:
    break;
}
```

case 不额外缩进，与 switch 关键字对齐。

### 3.6 namespace — 左大括号同行

```cpp
namespace chen {

// ... 内容不缩进（项目实际风格）

} // namespace chen
```

namespace 结尾注释格式：`} // namespace chen` 或 `} // namespace chen::http`

namespace 内部代码不缩进。

### 3.7 匿名 namespace — 左大括号同行

```cpp
namespace {
// ...
} // namespace
```

---

## 4. 命名规范

### 4.1 类/结构体 — PascalCase（首字母大写的驼峰）

```cpp
class Application;
class TcpServer;
class LogEvent;
class ConfigVarBase;
class FileLogAppender;
struct MySQLTime;
struct LogAppenderDefine;
```

### 4.2 成员变量 — m_ 前缀 + snake_case

```cpp
std::string m_name;
int m_argc;
bool m_isKeepAlive;
uint64_t m_lastTime;
SpinLock m_mutex;
```

布尔类型成员变量使用 `m_is` / `m_has` / `m_can` 等前缀：

```cpp
bool m_hasFormatter = false;   // 是否有
bool m_isKeepAlive;             // 是否
bool m_hasError;                // 存在
bool m_isFinished;              // 已完成
bool m_recurring = false;       // 循环
bool m_tickled = false;         // 已触发
```

### 4.3 静态成员变量 — g_ 前缀 + snake_case

```cpp
static ConfigVarMap g_datas;
static std::shared_mutex g_mutex;
static uint64_t g_fun_id;
```

### 4.4 线程局部变量 — t_ 前缀 + snake_case

```cpp
static thread_local Thread* t_thread = nullptr;
static thread_local std::string t_thread_name = "UNKNOW";
```

### 4.5 局部变量和函数参数 — snake_case

```cpp
std::string conf_path = EnvMgr::GetInstance()->getConfigPath();
bool is_print_help = false;
int run_type = 0;
uint64_t now = event->getTime();
```

函数参数：

```cpp
void setName(const std::string& name);
bool init(int argc, char** argv);
Timer::ptr addTimer(uint64_t ms, std::function<void()> cb, bool recurring = false);
```

### 4.6 成员函数 — camelCase（首字母小写的驼峰）

```cpp
int getErrno() const;
std::string getContent() const;
void addAppender(LogAppender::ptr appender);
void delAppender(LogAppender::ptr appender);
bool shouldRotate(uint64_t timestamp);
```

Getter 使用 `get` 前缀（如 `getValue()`、`getName()`），Setter 使用 `set` 前缀（如 `setValue()`、`setName()`）。

布尔型成员函数命名：**不强制** `is` 前缀，根据语义自行判断：

```cpp
bool isNeedCheck();
bool isNegotiateH2() const;
bool hasTimer();
bool cancel();
```

### 4.7 静态/自由函数 — PascalCase

```cpp
static T* GetInstance();
static void SetThis(Fiber* f);
static uint64_t TotalFibers();
static ConfigVar<T>::ptr Lookup(const std::string& name, ...);
static void LoadFromConfDir(const std::string& path, bool force = false);
static void RegisterBuiltInServers();
```

### 4.8 宏 — 全大写 + 下划线

```cpp
#define ASSERT(x)       ...
#define ASSERT2(x, w)   ...
#define LICKLY(x)       ...
#define UNLICKLY(x)     ...
#define LOG_ROOT()      ...
#define LOG_NAME(name)  ...
```

### 4.9 枚举值 — 全大写 + 下划线 或 PascalCase 混用

优先全大写：

```cpp
enum Level {
    UNKNOW = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

enum State {
    INIT,
    HOLD,
    EXEC,
    TERM,
    READY,
    EXCEPT
};

enum TimeRotateType {
    NONE = 0,
    MINUTE_30 = 1,
    HOUR = 2,
    HOUR_12 = 3,
    DAY = 4,
    WEEK = 5,
    MONTH = 6
};
```

### 4.10 类型别名（typedef）— 类内第一个 public 成员

```cpp
class Logger {
public:
    typedef std::shared_ptr<Logger> ptr;
    typedef SpinLock MutexType;
    // ...
};
```

智能指针别名一律命名为 `ptr`，锁类型别名命名为 `MutexType`。

---

## 5. 空格规范

### 5.1 控制语句关键字后加空格

```cpp
if (condition) { ... }
for (auto& i : vec) { ... }
while (condition) { ... }
switch (expr) { ... }
```

### 5.2 函数名与括号之间不加空格

```cpp
foo();
bar(arg1, arg2);
obj.method();
```

### 5.3 逗号后加空格，逗号前不加空格

```cpp
void foo(int a, int b, const std::string& c);
```

### 5.4 赋值运算符前后加空格

```cpp
int a = 1;
bool ok = false;
```

### 5.5 二元运算符前后加空格

```cpp
if (a == b) { ... }
int c = a + b;
```

### 5.6 指针和引用 — 左对齐

```cpp
int* ptr;
const std::string& name;
char** argv;
```

（`.clang-format` 配置 `PointerAlignment: Left`）

### 5.7 模板尖括号前后不加空格

```cpp
std::vector<TcpServer::ptr>
std::shared_ptr<Logger>
std::function<void()>
```

---

## 6. 类内部组织顺序

1. `public:` 区域
   - typedef / using 声明
   - 构造函数
   - 析构函数
   - 成员函数
2. `protected:` 区域
   - 成员函数
   - 成员变量
3. `private:` 区域
   - 成员函数
   - 成员变量

同一访问区域内的成员变量集中放在该区域的最后，并用 `///` 注释说明用途。

---

## 7. 注释规范

### 7.1 Doxygen 文档注释

所有 public 接口必须使用 Doxygen 风格注释：

```cpp
/**
 * @brief 简要说明
 * @param name 参数说明
 * @param[out] result 输出参数说明
 * @return 返回值说明
 * @details 详细说明（可选）
 * @pre 前置条件（可选）
 * @post 后置条件（可选）
 * @tparam T 模板参数说明（可选）
 * @exception 可能抛出的异常（可选）
 */
```

### 7.2 成员变量注释 — 使用 `///`

```cpp
/// 日志名称
std::string m_name;
/// 日志级别
LogLevel::Level m_level;
/// 日志目标集合
std::list<std::shared_ptr<LogAppender>> m_appenders;
```

### 7.3 枚举值注释 — 使用 `///`

```cpp
enum State {
    /// 初始化状态
    INIT,
    /// 暂停状态
    HOLD,
    /// 执行态
    EXEC,
};
```

### 7.4 行内注释

使用 `//` 注释，位于代码上方或同行：

```cpp
// 启动协程
m_mainIOManager.reset(new IOManager(1, true, "main"));
m_mainIOManager->schedule(std::bind(&Application::run_fiber, this));
```

被注释掉的代码保留（用于将来参考），直接 `//` 注释掉即可。

---

## 8. 模板规范

### 8.1 模板声明始终换行

```cpp
template <class T, class X = void, int N = 0>
class Singleton { ... };

template <class T>
static typename ConfigVar<T>::ptr Lookup(const std::string& name);
```

（`.clang-format` 配置 `AlwaysBreakTemplateDeclarations: true`）

### 8.2 模板类型使用 class 或 typename

简短的模板参数优先使用 `class`，较长的参数列表中可以混用：

```cpp
template <class T>                      // 单参数用 class
template <class F, class T>             // 多参数用 class
template <class T, class FromStr = ..., class ToStr = ...>   // 带默认值
template <typename... Args>             // 可变参数模板用 typename
template <typename T>                   // 也接受 typename
```

---

## 9. 其他约定

### 9.1 使用 nullptr

不使用 `NULL` 或 `0` 表示空指针，始终使用 `nullptr`：

```cpp
char** m_argv = nullptr;
static Application* m_instance = nullptr;
```

### 9.2 自动类型推导

迭代器和复杂类型优先使用 `auto`：

```cpp
for (auto& i : modules) { ... }
auto it = m_servers.find(name);
auto server = std::make_shared<http::HttpServer>(...);
```

### 9.3 const 正确性

- 不修改的成员函数必须标记为 `const`
- 不修改的参数尽量使用 `const` 引用
- 返回值可以返回 `const` 引用以避免拷贝

```cpp
const std::string& getName() const { return m_name; }
pid_t getId() const { return m_id; }
void setName(const std::string& v) { m_name = v; }
```

### 9.4 禁用拷贝 — 继承 Noncopyable

需要禁用拷贝/赋值的类，继承 `Noncopyable`：

```cpp
class Mutex : public Noncopyable { ... };
class Thread : Noncopyable { ... };
```

### 9.5 智能指针

- 使用 `std::shared_ptr` 管理对象生命周期
- 每个类定义 `ptr` 别名
- 创建对象使用 `std::make_shared` 或 `new`

```cpp
Logger::ptr logger(new Logger(name));
auto server = std::make_shared<http::HttpServer>(keepalive, worker, io_worker, accept_worker);
```

### 9.6 line break in function parameters

函数参数过多时，将后续参数放在新行，缩进对齐：

```cpp
LogEvent(Logger::ptr logger, LogLevel::Level level
    ,const char* file, int32_t line, uint32_t elapse
    ,uint32_t threadId, uint32_t fiberId, uint64_t time
    ,const std::string& threadName);
```

注意：逗号放在新行的开头（前置逗号风格）。

### 9.7 构造函数初始化列表

初始化列表另起一行，使用逗号前置风格：

```cpp
LogEvent::LogEvent(Logger::ptr logger, LogLevel::Level level
        ,const char* file, int32_t line, uint32_t elapse
        ,uint32_t threadId, uint32_t fiberId, uint64_t time
        ,const std::string& threadName)
    :m_logger(logger)
    ,m_level(level)
    ,m_file(file)
    ,m_line(line)
    ,m_elapse(elapse)
    ,m_threadId(threadId)
    ,m_fiberId(fiberId)
    ,m_time(time)
    ,m_threadName(threadName) {
}
```

初始化列表中的 `:` 之前另起一行（紧随参数列表后），每个成员初始化以 `,` 开头。

### 9.8 命名空间

所有代码放在命名空间中，子模块可以使用嵌套命名空间：

```cpp
namespace chen {
// 大部分代码
}

// 或 C++17 嵌套命名空间
namespace chen::http {
// http 子模块
}
```

### 9.9 using namespace

禁止在头文件的全局作用域中使用 `using namespace`。`.cc` 文件中不限制，但也尽量避免。

### 9.10 RAII 锁管理

使用 RAII 封装管理锁的生命周期：

```cpp
MutexType::Lock lock(m_mutex);  // 构造函数加锁，析构函数解锁
```

### 9.11 override 关键字

重写虚函数时，使用 `override` 关键字（不用 `virtual`）：

```cpp
void log(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) override;
int getErrno() const override;
```

### 9.12 静态工厂方法

优先使用静态方法 `Create` 作为工厂：

```cpp
static MySQLStmt::ptr Create(MySQL::ptr db, const std::string& stmt);
static IPAddress::ptr Create(const char* address, uint16_t port = 0);
```

---

## 10. .clang-format 配置

项目使用 `.clang-format` 文件自动格式化，关键配置：

```yaml
BasedOnStyle: LLVM
ColumnLimit: 135
IndentWidth: 4
TabWidth: 4
PointerAlignment: Left
AccessModifierOffset: -4
AlwaysBreakTemplateDeclarations: true
SpaceBeforeParens: ControlStatements
MaxEmptyLinesToKeep: 1
AllowShortEnumsOnASingleLine: false
AlignConsecutiveMacros: AcrossEmptyLinesAndComments
BinPackParameters: true
```

---

## 11. 速查表

| 元素 | 约定 | 示例 |
|------|------|------|
| 类/结构体名 | PascalCase | `TcpServer`, `LogEvent` |
| 成员变量 | `m_` + snake_case | `m_name`, `m_isKeepAlive` |
| 静态成员 | `g_` + snake_case | `g_datas`, `g_fun_id` |
| 线程局部变量 | `t_` + snake_case | `t_thread`, `t_thread_name` |
| 局部变量/参数 | snake_case | `conf_path`, `run_type` |
| 成员函数 | camelCase | `getValue()`, `setName()` |
| 静态/自由函数 | PascalCase | `GetInstance()`, `Lookup()` |
| 宏 | 全大写 | `ASSERT(x)`, `LOG_ROOT()` |
| 枚举值 | 全大写 | `DEBUG`, `INFO`, `NONE` |
| 智能指针 typedef | `Type::ptr` | `std::shared_ptr<Logger>` |
| 锁 typedef | `MutexType` | `SpinLock` 的别名 |
| 布尔成员 | `m_is` / `m_has` | `m_isKeepAlive`, `m_hasError` |
| Getter/Setter | `get` / `set` 前缀 | `getName()`, `setName()` |
| 工厂方法 | `Create()` | `MySQLStmt::Create(...)` |
| Include Guard | `#pragma once` | `#pragma once` |
| 文件头 | Doxygen 注释块 | `@file`, `@brief`, `@author` |
| 成员变量注释 | `///` | `/// 日志名称` |
