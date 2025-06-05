# 威胁情报RAG检索系统

一个专为威胁情报分析设计的高级RAG（检索增强生成）系统，集成了**知识图谱**、**混合检索**和**大语言模型**，支持DeepSeek-Chat和ZhipuAI Embedding-3。

## 🆕 最新功能

### 🧠 知识图谱引擎
- **自动实体提取**: 使用LLM从威胁情报文档中提取IoC、APT组织、恶意软件、CVE等实体
- **智能关系构建**: 基于语义分析自动建立实体间的复杂关系
- **图谱查询**: 支持Cypher查询和自然语言查询
- **威胁态势分析**: 全局威胁态势可视化和趋势分析

### 🔍 混合检索系统
- **向量检索**: 基于语义相似度的高精度文档检索
- **图谱检索**: 基于实体关系的结构化信息检索
- **混合融合**: 智能融合多种检索结果，提升查准率和查全率
- **动态扩展**: 使用知识图谱动态扩展检索上下文

### 🤖 大模型集成
- **DeepSeek-Chat**: 专业的威胁情报分析和报告生成
- **ZhipuAI Embedding-3**: 高质量中文威胁情报向量化
- **多模态分析**: 支持威胁分析、IoC调查、APT追踪等多种分析模式

## ⚡ 快速开始

### 1. 一键设置
```bash
# 克隆项目
git clone <repository_url>
cd cyeg-rag

# 运行自动设置脚本
python scripts/setup_rag_system.py
```

### 2. 配置API密钥
编辑 `.env` 文件：
```env
# DeepSeek API配置
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# ZhipuAI API配置
ZHIPUAI_API_KEY=your_zhipuai_api_key_here

# 嵌入模型配置
EMBEDDING_MODEL=zhipuai-embedding-3
```

### 3. 启动服务
```bash
# 启动Milvus和Neo4j
docker-compose up -d

# 验证服务状态
docker-compose ps
```

## 📖 使用示例

### 基础RAG查询
```python
from src.rag_engine.rag_engine import ThreatIntelRAGEngine

# 初始化RAG引擎
rag_engine = ThreatIntelRAGEngine()

# 摄取威胁情报文档
result = rag_engine.ingest_documents(
    source="path/to/threat_intel_docs",
    build_knowledge_graph=True
)

# 执行查询
answer = rag_engine.query(
    question="APT29使用了哪些攻击技术？",
    retrieval_method="hybrid",  # vector/graph/hybrid
    response_type="comprehensive"
)

print(f"回答: {answer['response']}")
print(f"置信度: {answer['metadata']['confidence_score']}")
```

### 威胁分析
```python
# 深度威胁分析
threat_analysis = rag_engine.analyze_threat(
    query="分析DarkSide勒索软件的攻击链和影响",
    include_graph_analysis=True
)

print(f"风险等级: {threat_analysis['risk_level']}")
print(f"威胁指标: {threat_analysis['threat_indicators']}")
print(f"防护建议: {threat_analysis['recommendations']}")
```

### IoC调查
```python
# IoC深度调查
ioc_report = rag_engine.analyze_ioc(
    ioc_value="192.168.100.5",
    ioc_type="ip"
)

print(f"威胁等级: {ioc_report['threat_level']}")
print(f"关联恶意软件: {ioc_report['associated_malware']}")
print(f"关联APT组织: {ioc_report['apt_groups']}")
```

### 知识图谱查询
```python
# 自然语言图谱查询
result = rag_engine.natural_language_query(
    "有哪些APT组织使用了CVE-2021-34527漏洞？"
)
print(result)

# 威胁态势分析
landscape = rag_engine.get_threat_landscape()
print(f"当前威胁统计: {landscape['statistics']}")
print(f"活跃威胁: {landscape['top_threats']}")
```

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    威胁情报RAG系统                          │
├─────────────────────────────────────────────────────────────┤
│  🎯 RAG引擎 (rag_engine/)                                   │
│  ├── ThreatIntelRAGEngine     # 核心引擎                    │
│  ├── HybridRetriever          # 混合检索器                  │
│  └── ResponseGenerator        # 响应生成器                  │
├─────────────────────────────────────────────────────────────┤
│  🧠 知识图谱 (knowledge_graph/)                             │
│  ├── Neo4jClient              # Neo4j客户端                │
│  ├── ThreatIntelGraphBuilder  # 图谱构建器                  │
│  └── GraphQueryEngine         # 图谱查询引擎                │
├─────────────────────────────────────────────────────────────┤
│  🤖 LLM接口 (llm/)                                          │
│  ├── LLMClient                # LLM基类                     │
│  └── DeepSeekClient           # DeepSeek客户端              │
├─────────────────────────────────────────────────────────────┤
│  🗃️ 向量存储 (vector_store/)                               │
│  ├── MilvusVectorStore        # Milvus向量数据库            │
│  └── EmbeddingGenerator       # 嵌入生成器(支持ZhipuAI)     │
├─────────────────────────────────────────────────────────────┤
│  📄 文档处理 (document_processor/)                          │
│  ├── ThreatIntelProcessor     # 威胁情报处理器              │
│  ├── DocumentLoader           # 文档加载器                  │
│  └── ThreatIntelChunker       # 威胁情报分块器              │
└─────────────────────────────────────────────────────────────┘
```

## 📁 项目结构
```
cyeg-rag/
├── src/                         # 源代码目录
│   ├── rag_engine/              # 🎯 RAG引擎
│   │   ├── rag_engine.py        # 核心RAG引擎
│   │   ├── retriever.py         # 混合检索器
│   │   └── generator.py         # 响应生成器
│   ├── knowledge_graph/         # 🧠 知识图谱
│   │   ├── neo4j_client.py      # Neo4j客户端
│   │   ├── graph_builder.py     # 图谱构建器
│   │   └── graph_query.py       # 图谱查询引擎
│   ├── llm/                     # 🤖 LLM接口
│   │   ├── llm_client.py        # LLM基类
│   │   └── deepseek_client.py   # DeepSeek客户端
│   ├── vector_store/            # 🗃️ 向量存储
│   │   ├── milvus_store.py      # Milvus向量存储
│   │   └── embedder.py          # 嵌入生成器
│   ├── document_processor/      # 📄 文档处理
│   │   ├── processor.py         # 威胁情报处理器
│   │   ├── loader.py            # 文档加载器
│   │   └── chunker.py           # 智能分块器
│   └── utils/                   # 🔧 工具函数
│       └── config.py            # 配置管理
├── examples/                    # 📚 使用示例
│   ├── complete_rag_example.py  # 完整功能示例
│   └── basic_rag_example.py     # 基础示例
├── scripts/                     # 🚀 脚本工具
│   └── setup_rag_system.py     # 快速设置脚本
├── config/                      # ⚙️ 配置文档
├── docker-compose.yml           # 🐳 Docker服务编排
├── requirements.txt             # 📦 Python依赖
├── env.example                  # 🔧 环境变量模板
└── README.md                    # 📖 项目文档
```

## 🔧 核心特性

### 📊 文档处理
- **多格式支持**: PDF、DOCX、TXT、HTML、JSON、STIX
- **智能分块**: 5种分块策略，针对威胁情报优化
- **实体感知**: 基于威胁实体边界的智能分块
- **批量处理**: 高效的并行文档处理

### 🧮 向量存储
- **Milvus集成**: 高性能向量数据库
- **多模型支持**: ZhipuAI Embedding-3、OpenAI、Sentence Transformers
- **混合搜索**: 向量相似度 + 关键词过滤
- **动态索引**: 支持实时数据更新

### 🕸️ 知识图谱
- **Neo4j图数据库**: 高性能图存储和查询
- **威胁本体**: 专门的威胁情报实体和关系模型
- **自动构建**: LLM驱动的实体提取和关系推理
- **图查询**: Cypher查询和自然语言查询

### 🎯 检索引擎
- **混合检索**: 向量检索 + 图谱检索 + 关键词检索
- **智能融合**: 多源结果的智能排序和去重
- **上下文扩展**: 基于图谱的动态上下文扩展
- **过滤和重排**: 支持复杂过滤条件和重排序

### 💬 响应生成
- **多模式生成**: 简洁、详细、分析三种响应模式
- **威胁分析**: 专门的威胁分析报告生成
- **IoC调查**: 自动化的IoC调查和关联分析
- **置信度评估**: 基于检索质量的置信度计算

## 🛠️ 技术栈

### 🗄️ 数据存储
- **Milvus**: 向量数据库 (v2.3.4+)
- **Neo4j**: 图数据库 (v5.x)

### 🤖 AI模型
- **DeepSeek-Chat**: 大语言模型 (推理和分析)
- **ZhipuAI Embedding-3**: 嵌入模型 (中文优化)
- **备选模型**: OpenAI GPT、Sentence Transformers

### 🐍 Python依赖
- **LangChain**: RAG框架和文档处理
- **PyMilvus**: Milvus Python客户端
- **Neo4j Driver**: Neo4j Python驱动
- **loguru**: 日志管理
- **pydantic**: 配置管理

## 🚀 高级功能

### 🔍 多模式检索对比
```python
# 对比不同检索方法的效果
query = "APT29的攻击技术分析"

# 纯向量检索
vector_result = rag_engine.query(query, retrieval_method="vector")

# 纯图谱检索  
graph_result = rag_engine.query(query, retrieval_method="graph")

# 混合检索
hybrid_result = rag_engine.query(query, retrieval_method="hybrid")

# 性能对比
print(f"向量检索置信度: {vector_result['metadata']['confidence_score']}")
print(f"图谱检索置信度: {graph_result['metadata']['confidence_score']}")
print(f"混合检索置信度: {hybrid_result['metadata']['confidence_score']}")
```

### 📊 威胁态势仪表板
```python
# 获取全局威胁态势
landscape = rag_engine.get_threat_landscape()

# 威胁统计
stats = landscape['statistics']
print(f"IoC指标: {stats['ioc_count']}")
print(f"APT组织: {stats['apt_count']}")
print(f"恶意软件: {stats['malware_count']}")

# 活跃威胁
for threat in landscape['top_threats']:
    print(f"威胁组织: {threat['apt_name']}, 活跃度: {threat['activity_score']}")

# 新兴技术
for technique in landscape['top_techniques']:
    print(f"技术: {technique['technique_name']}, 使用频率: {technique['usage_count']}")
```

### 🔗 关联分析
```python
# 深度关联分析
associations = rag_engine.graph_query.find_ioc_associations("malicious-c2.example.com")

print(f"关联恶意软件: {len(associations['malware_families'])}")
print(f"关联APT组织: {len(associations['apt_groups'])}")
print(f"相关文档: {len(associations['documents'])}")

# 攻击链分析
attack_patterns = rag_engine.graph_query.find_attack_patterns(
    apt_group="APT29"
)

for pattern in attack_patterns:
    print(f"APT: {pattern['apt']['name']}")
    print(f"恶意软件: {pattern['malware']['name']}")
    print(f"技术: {pattern['technique']['name']}")
```

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

感谢以下开源项目和技术：
- [LangChain](https://langchain.com/) - RAG框架
- [Milvus](https://milvus.io/) - 向量数据库
- [Neo4j](https://neo4j.com/) - 图数据库
- [DeepSeek](https://deepseek.com/) - 大语言模型
- [ZhipuAI](https://zhipuai.cn/) - 嵌入模型

---

**🔥 立即开始您的威胁情报分析之旅！**

```bash
python scripts/setup_rag_system.py
``` 