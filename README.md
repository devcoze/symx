### 二进制文件格式设计

```text

[ 32byte 统一固定文件头 ]
  +-------------------------------------------------------------------------+
  | Magic(4) | Type(1) | Version(1) | HeaderExtLen(2) | PayloadLen(8) | BuildID(16) |
  +-------------------------------------------------------------------------+

[ TLV 变长头部 ]
  区间: [FixedSize, FixedSize + HeaderExtLen)
  元数据 (文件名，字符串池，基址...)

[ 二进制有序索引数据 ]
  区间: [FixedSize + HeaderExtLen, FixedSize + HeaderExtLen + PayloadLen)
  由元数据中的字段决定结构和长度
  
  JS位置数组 / PG符号数组 / DWARF地址区间

```