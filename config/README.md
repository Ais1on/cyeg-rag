# 配置说明

本文档描述了威胁情报RAG系统的各种配置选项。

## 环境变量配置

复制 `.env.example` 文件为 `.env` 并根据你的环境进行配置：

### OpenAI配置
```bash
# OpenAI API密钥
OPENAI_API_KEY=your_openai_api_key_here

# OpenAI API基础URL（可选，用于使用代理或其他兼容API）
OPENAI_BASE_URL=https://api.openai.com/v1
```

### Milvus向量数据库配置
```bash
# Milvus服务器地址
MILVUS_HOST=localhost
MILVUS_PORT=19530

# Milvus认证（可选）
MILVUS_USERNAME=
MILVUS_PASSWORD=
```

### Neo4j知识图谱数据库配置
```bash
# Neo4j连接URI
NEO4J_URI=bolt://localhost:7687

# Neo4j认证
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password123
```

### 文档处理配置
```bash
# 文档分块大小
CHUNK_SIZE=512

# 分块重叠大小
CHUNK_OVERLAP=50

# 嵌入模型名称
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

# 日志级别
LOG_LEVEL=INFO
```

## 系统配置

### 支持的嵌入模型

#### Sentence Transformers模型
- `sentence-transformers/all-MiniLM-L6-v2` (384维, 推荐)
- `sentence-transformers/all-mpnet-base-v2` (768维, 高质量)
- `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` (384维, 多语言)

#### OpenAI嵌入模型
- `text-embedding-ada-002` (1536维, 需要API密钥)
- `text-embedding-3-small` (1536维, 较新版本)
- `text-embedding-3-large` (3072维, 高质量)

### 文档分块策略

#### 1. FIXED_SIZE
固定大小分块，适合大多数场景
```python
chunk_strategy = ChunkStrategy.FIXED_SIZE
chunk_size = 512
chunk_overlap = 50
```

#### 2. SENTENCE
按句子分块，保持语义完整性
```python
chunk_strategy = ChunkStrategy.SENTENCE
chunk_size = 1000  # 最大字符数
```

#### 3. PARAGRAPH
按段落分块，适合结构化文档
```python
chunk_strategy = ChunkStrategy.PARAGRAPH
chunk_size = 1500
```

#### 4. SEMANTIC
语义分块，基于主题变化
```python
chunk_strategy = ChunkStrategy.SEMANTIC
chunk_size = 800
```

#### 5. THREAT_INTEL
威胁情报专用分块，基于威胁实体
```python
chunk_strategy = ChunkStrategy.THREAT_INTEL
chunk_size = 600
```

### Milvus索引配置

#### IVF_FLAT（推荐）
```python
index_type = "IVF_FLAT"
metric_type = "COSINE"  # 或 "L2", "IP"
index_params = {"nlist": 128}
```

#### IVF_SQ8（内存优化）
```python
index_type = "IVF_SQ8"
metric_type = "COSINE"
index_params = {"nlist": 128}
```

#### HNSW（高性能）
```python
index_type = "HNSW"
metric_type = "COSINE"
index_params = {"M": 16, "efConstruction": 200}
```

## 实验配置

### 不同分块策略对比实验

```python
from src.document_processor.chunker import ChunkStrategy

strategies = [
    ChunkStrategy.FIXED_SIZE,
    ChunkStrategy.SENTENCE,
    ChunkStrategy.PARAGRAPH,
    ChunkStrategy.SEMANTIC,
    ChunkStrategy.THREAT_INTEL
]

for strategy in strategies:
    processor = ThreatIntelProcessor(
        chunk_strategy=strategy,
        chunk_size=512
    )
    # 运行实验...
```

### 多种嵌入模型对比实验

```python
models = [
    ("sentence-transformers/all-MiniLM-L6-v2", "sentence_transformer"),
    ("sentence-transformers/all-mpnet-base-v2", "sentence_transformer"),
    ("text-embedding-ada-002", "openai")
]

for model_name, model_type in models:
    processor = ThreatIntelProcessor(
        embedding_model=model_name,
        embedding_model_type=model_type
    )
    # 运行实验...
```

### 混合嵌入实验

```python
from src.vector_store.embedder import HybridEmbeddingGenerator

# 创建混合嵌入生成器
generators = [
    EmbeddingGenerator("sentence-transformers/all-MiniLM-L6-v2"),
    EmbeddingGenerator("sentence-transformers/all-mpnet-base-v2")
]
weights = [0.6, 0.4]

hybrid_embedder = HybridEmbeddingGenerator(generators, weights)
```

## 性能调优

### 批处理大小调优
```python
# CPU环境
batch_size = 8

# GPU环境
batch_size = 32

# 大内存环境
batch_size = 64
```

### Milvus性能配置
```python
# 搜索参数调优
search_params = {
    "metric_type": "COSINE",
    "params": {"nprobe": 10}  # 增加nprobe提高召回率
}

# 索引参数调优
index_params = {
    "index_type": "IVF_FLAT",
    "metric_type": "COSINE",
    "params": {"nlist": 256}  # 增加nlist提高性能
}
```

### 内存使用优化
```python
# 不保留中间结果
processor.process_documents(
    source="data/",
    return_chunks=False  # 不返回分块，节省内存
)

# 分批处理大型数据集
def process_large_dataset(file_list, batch_size=10):
    for i in range(0, len(file_list), batch_size):
        batch_files = file_list[i:i+batch_size]
        # 处理批次...
```

## 安全配置

### API密钥管理
```bash
# 生产环境建议使用密钥管理服务
export OPENAI_API_KEY=$(aws ssm get-parameter --name "/app/openai-key" --with-decryption --query Parameter.Value --output text)
```

### 网络安全
```bash
# 限制Milvus和Neo4j访问
# 在防火墙中只允许应用服务器访问数据库端口
```

### 数据加密
```python
# 敏感数据加密存储
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

# 加密存储敏感元数据
encrypted_metadata = cipher_suite.encrypt(metadata_json.encode())
```

## 监控配置

### 日志配置
```python
from loguru import logger

# 详细日志配置
logger.add(
    "logs/threat_intel_{time}.log",
    rotation="1 day",
    retention="30 days",
    level="INFO",
    format="{time} | {level} | {module}:{function}:{line} | {message}"
)
```

### 性能监控
```python
import time
from functools import wraps

def monitor_performance(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logger.info(f"{func.__name__} 执行时间: {end_time - start_time:.2f}秒")
        return result
    return wrapper
```

## 故障排除

### 常见问题

1. **Milvus连接失败**
   ```bash
   # 检查Milvus是否运行
   docker ps | grep milvus
   
   # 检查端口是否开放
   telnet localhost 19530
   ```

2. **Neo4j连接失败**
   ```bash
   # 检查Neo4j状态
   docker exec neo4j-db cypher-shell -u neo4j -p password123 "RETURN 1"
   ```

3. **内存不足**
   ```python
   # 减少批处理大小
   batch_size = 8
   
   # 使用更小的嵌入模型
   embedding_model = "sentence-transformers/all-MiniLM-L6-v2"
   ```

4. **嵌入模型下载慢**
   ```bash
   # 设置Hugging Face镜像
   export HF_ENDPOINT=https://hf-mirror.com
   ``` 