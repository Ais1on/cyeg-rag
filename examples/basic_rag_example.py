"""
基本RAG使用示例
演示如何使用威胁情报RAG系统进行文档处理、向量存储和检索
"""
import os
import sys

# 添加项目根目录到路径
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.document_processor import DocumentLoader, DocumentChunker, ChunkStrategy
from src.vector_store import EmbeddingGenerator, MilvusVectorStore
from src.utils import get_settings
from loguru import logger


def main():
    """主函数"""
    logger.info("开始威胁情报RAG示例")
    
    # 1. 加载配置
    settings = get_settings()
    logger.info(f"使用嵌入模型: {settings.embedding_model}")
    
    # 2. 创建示例威胁情报文档
    create_sample_documents()
    
    # 3. 加载文档
    logger.info("=== 步骤1: 加载文档 ===")
    loader = DocumentLoader()
    
    try:
        # 从示例数据目录加载文档
        documents = loader.load_directory("data/sample_threat_intel")
        logger.info(f"成功加载 {len(documents)} 个文档")
        
        for i, doc in enumerate(documents[:3]):  # 显示前3个文档
            logger.info(f"文档 {i+1}: {doc.metadata.get('source', 'Unknown')} - {len(doc.content)} 字符")
    
    except Exception as e:
        logger.error(f"加载文档失败: {str(e)}")
        return
    
    # 4. 文档分块
    logger.info("=== 步骤2: 文档分块 ===")
    chunker = DocumentChunker(
        chunk_size=settings.chunk_size,
        chunk_overlap=settings.chunk_overlap,
        strategy=ChunkStrategy.THREAT_INTEL  # 使用威胁情报专用分块策略
    )
    
    chunks = chunker.chunk_documents(documents)
    logger.info(f"生成 {len(chunks)} 个文档分块")
    
    # 显示一些分块示例
    for i, chunk in enumerate(chunks[:3]):
        logger.info(f"分块 {i+1} (ID: {chunk.chunk_id}): {chunk.content[:100]}...")
        if 'threat_entities' in chunk.metadata:
            entities = chunk.metadata['threat_entities']
            logger.info(f"  -> 检测到威胁实体: {len(entities)} 个")
    
    # 5. 生成嵌入向量
    logger.info("=== 步骤3: 生成嵌入向量 ===")
    embedder = EmbeddingGenerator(
        model_name=settings.embedding_model,
        model_type="sentence_transformer"
    )
    
    chunks_with_embeddings = embedder.embed_chunks(chunks, batch_size=16)
    logger.info(f"为 {len(chunks_with_embeddings)} 个分块生成了嵌入向量")
    logger.info(f"嵌入维度: {embedder.get_embedding_dim()}")
    
    # 6. 存储到Milvus向量数据库
    logger.info("=== 步骤4: 存储到向量数据库 ===")
    try:
        vector_store = MilvusVectorStore(
            collection_name="threat_intel_demo",
            embedding_dim=embedder.get_embedding_dim(),
            auto_create=True
        )
        
        # 插入向量
        inserted_ids = vector_store.insert_chunks(chunks_with_embeddings)
        logger.info(f"成功插入 {len(inserted_ids)} 个向量到Milvus")
        
        # 获取存储统计信息
        stats = vector_store.get_stats()
        logger.info(f"向量数据库统计: {stats}")
        
    except Exception as e:
        logger.error(f"向量存储失败: {str(e)}")
        logger.warning("跳过向量存储步骤（可能是Milvus未启动）")
        return
    
    # 7. 演示检索功能
    logger.info("=== 步骤5: 检索演示 ===")
    
    # 示例查询
    queries = [
        "APT攻击组织使用的恶意软件",
        "网络钓鱼邮件检测方法",
        "勒索软件防护策略",
        "CVE漏洞利用技术"
    ]
    
    for query in queries:
        logger.info(f"\n查询: '{query}'")
        
        try:
            # 生成查询向量
            query_embedding = embedder.generate_embeddings(query)
            
            # 执行向量搜索
            search_results = vector_store.search(
                query_embedding=query_embedding,
                top_k=3
            )
            
            logger.info(f"找到 {len(search_results)} 个相关结果:")
            for i, result in enumerate(search_results):
                logger.info(f"  结果 {i+1} (相似度: {result['score']:.3f}):")
                logger.info(f"    内容: {result['content'][:100]}...")
                logger.info(f"    来源: {result['source']}")
            
            # 演示混合搜索
            if "APT" in query:
                hybrid_results = vector_store.hybrid_search(
                    query_embedding=query_embedding,
                    keywords=["APT", "攻击", "恶意软件"],
                    top_k=3
                )
                logger.info(f"混合搜索结果数量: {len(hybrid_results)}")
                
        except Exception as e:
            logger.error(f"检索失败: {str(e)}")
    
    logger.info("=== RAG示例完成 ===")


def create_sample_documents():
    """创建示例威胁情报文档"""
    os.makedirs("data/sample_threat_intel", exist_ok=True)
    
    # 示例1: APT攻击报告
    apt_report = """
    # APT29攻击组织分析报告
    
    ## 概述
    APT29（又称Cozy Bear）是一个高度复杂的网络间谍组织，被认为与俄罗斯政府有关。
    该组织主要针对政府机构、外交组织和智库进行长期潜伏攻击。
    
    ## 攻击技术
    - 鱼叉式钓鱼邮件 (T1566.001)
    - PowerShell恶意脚本 (T1059.001)
    - WMI持久化 (T1047)
    - 域管理员账户劫持 (T1078.002)
    
    ## IoC指标
    - 恶意域名: cozybeardomain[.]com
    - IP地址: 185.86.151.11
    - 文件哈希: 7c8b8e8d5f7e4b3a2c1d9e8f6a5b4c3d2e1f8g7h6i5j4k3l2m1n9o8p7q6r5s4t3u2v1w
    
    ## 防护建议
    1. 加强邮件安全过滤
    2. 限制PowerShell执行权限
    3. 监控WMI活动
    4. 实施零信任架构
    """
    
    # 示例2: 勒索软件分析
    ransomware_report = """
    # WannaCry勒索软件技术分析
    
    ## 基本信息
    WannaCry是2017年5月爆发的大规模勒索软件攻击，利用NSA泄露的EternalBlue漏洞。
    CVE编号: CVE-2017-0144
    
    ## 传播机制
    - 利用SMB协议漏洞 (MS17-010)
    - 蠕虫式自动传播
    - 无需用户交互
    
    ## 技术特征
    - 加密算法: AES-128 + RSA-2048
    - 目标文件类型: .doc, .xls, .pdf, .jpg, .png等
    - 赎金要求: 300-600美元比特币
    
    ## 防护措施
    1. 及时安装MS17-010补丁
    2. 关闭不必要的SMB服务
    3. 实施网络分段
    4. 定期备份重要数据
    """
    
    # 示例3: 网络钓鱼检测
    phishing_guide = """
    # 网络钓鱼邮件检测指南
    
    ## 常见特征
    1. 发件人地址伪造
    2. 紧急性语言诱导
    3. 可疑链接和附件
    4. 语法和拼写错误
    
    ## 技术检测方法
    - SPF记录验证
    - DKIM签名检查
    - DMARC策略执行
    - 邮件头分析
    
    ## 机器学习检测
    - 自然语言处理分析
    - 行为模式识别
    - 异常流量检测
    
    ## 响应流程
    1. 立即隔离可疑邮件
    2. 分析邮件头和内容
    3. 提取IoC指标
    4. 更新防护规则
    5. 用户安全培训
    """
    
    # 保存文档
    documents = [
        ("apt29_analysis.txt", apt_report),
        ("wannacry_technical_analysis.txt", ransomware_report),
        ("phishing_detection_guide.txt", phishing_guide)
    ]
    
    for filename, content in documents:
        filepath = os.path.join("data/sample_threat_intel", filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    logger.info("已创建示例威胁情报文档")


if __name__ == "__main__":
    main() 