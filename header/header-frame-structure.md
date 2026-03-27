## Header Frame Structure

一个基于固定前缀 + 可变长度头部的帧解码器。解码器首先读取固定的 8 字节头部前缀，
然后通过 `HeaderSize` 字段确定完整头部长度，最后解析头部中的 Payload 来确定
Body 的结构和长度。

该协议采用两阶段解码策略：第一阶段读取 8 字节固定前缀，获取帧的头部边界；
第二阶段根据 `Magic` 和 `Version` 解析 Payload 的内部结构，从而确定 Body
的长度和布局。

### 头部布局

```
+-------+----------+------------+---------------------------+
| Magic | Version  | HeaderSize |         Payload           |
| (4)   |   (2)    |    (2)     |    (HeaderSize - 8)       |
+-------+----------+------------+---------------------------+
|<---      固定前缀 (8 字节)     --->|
|<---              HeaderSize 字节                       --->|
```

### 完整帧布局

```
+-----------------------------------------------------+-------------------+
|                       Header                         |       Body        |
| Magic(4) + Version(2) + HeaderSize(2) + Payload(N)  |    (变长)          |
+-----------------------------------------------------+-------------------+
|<---            HeaderSize 字节                  ---->|<-- 由 Payload  --->|
                                                          中的字段决定
```

### 字段说明

| 字段       | 偏移量 | 长度    | 说明                                                                    |
|------------|--------|---------|-------------------------------------------------------------------------|
| Magic      | 0      | 4 字节  | 协议魔数，用于协议识别和校验。                                             |
| Version    | 4      | 2 字节  | 协议版本号，决定 Payload 和 Body 的解析逻辑。                              |
| HeaderSize | 6      | 2 字节  | 整个 Header 的总长度（包含 Magic、Version、HeaderSize 自身以及 Payload）。最小值为 `8`。 |
| Payload    | 8      | HeaderSize - 8 字节 | 可变长度的头部载荷。其内部结构由 `Magic` 和 `Version` 共同决定，包含确定 Body 结构和长度所需的元数据。 |

### 解码示例

#### 示例 1：最小头部，无 Payload，HeaderSize = 8

最简单的情况，头部仅包含固定前缀，没有额外的 Payload。
Body 的结构完全由 `Magic` 和 `Version` 决定。

```
HeaderSize = 8
Payload    = (空, 0 字节)

HEADER (8 字节)
+------------+---------+------------+
|   Magic    | Version | HeaderSize |
| 0xCAFEBEEF |  0x0001 |   0x0008   |
+------------+---------+------------+
```

#### 示例 2：带 12 字节 Payload 的头部，HeaderSize = 20

典型场景，Payload 中携带消息类型、序列号、Body 长度等元数据。

```
HeaderSize = 20
Payload    = 20 - 8 = 12 字节

HEADER (20 字节)
+------------+---------+------------+-----------------------------+
|   Magic    | Version | HeaderSize |          Payload            |
| 0xCAFEBEEF |  0x0001 |   0x0014   |     (12 字节元数据)          |
+------------+---------+------------+-----------------------------+
```

#### 示例 3：包含 Header 和 Body 的完整帧

假设 Payload 起始处包含一个 4 字节的 `BodyLength` 字段，后跟 8 字节的其他
头部元数据，Body 内容为 "HELLO, WORLD"（12 字节）：

```
HeaderSize  = 20 (8 固定前缀 + 12 Payload)
Payload     = BodyLength(4) + OtherMeta(8)
BodyLength  = 12

完整帧 (32 字节)
+------------+---------+------------+------------+-----------+----------------+
|   Magic    | Version | HeaderSize | BodyLength | OtherMeta | Actual Content |
| 0xCAFEBEEF |  0x0001 |   0x0014   | 0x0000000C | (8 字节)  | "HELLO, WORLD" |
+------------+---------+------------+------------+-----------+----------------+
|<---                 Header (20 字节)                  ---->|<-- Body (12) ->|
```

### 解码流程

```
1. 读取 8 字节（固定前缀）
         |
         v
2. 校验 Magic
         |
         v
3. 提取 Version 和 HeaderSize
         |
         v
4. 读取剩余 (HeaderSize - 8) 字节作为 Payload
         |
         v
5. 根据 Magic + Version 解析 Payload，
   确定 Body 的长度和结构
         |
         v
6. 读取 Body
```

### 注意事项

- `HeaderSize` 为无符号 16 位整数，因此头部最大长度为 `65535` 字节。
- `HeaderSize` 必须 >= `8`。任何小于 `8` 的值应视为帧损坏异常
  （`CorruptedFrameException`）。
- 读取固定前缀后应立即校验 `Magic` 字段。无法识别的魔数表示数据流损坏
  或协议不兼容，应关闭连接。
- Payload 和 Body 的解析逻辑依赖于版本号。不同的 `Version` 值可能定义
  完全不同的 Payload 布局和 Body 结构。
