#!/usr/bin/env python3
"""
完整的威胁情报RAG系统使用示例
展示知识图谱和混合检索功能
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.rag_engine.rag_engine import ThreatIntelRAGEngine
from src.utils.config import get_settings
from loguru import logger
import json
import time


def create_sample_threat_docs():
    """创建示例威胁情报文档"""
    sample_docs = {
        "apt29_lazarus_analysis.txt": """
APT29 (Cozy Bear) 威胁分析报告

概述：
APT29，也被称为Cozy Bear，是一个高级持续性威胁组织，被认为与俄罗斯政府有关。该组织在2024年频繁活跃，主要针对政府机构和企业进行网络间谍活动。

攻击技术：
- 使用T1566.001鱼叉式钓鱼邮件作为初始访问方式
- 利用T1055进程注入技术绕过安全检测
- 使用T1071.001通过HTTP/HTTPS进行C2通信

IoC指标：
- IP地址: 192.168.100.5, 10.0.0.15
- 域名: malicious-c2.example.com
- 文件哈希: a1b2c3d4e5f6789012345678901234567890abcd

关联恶意软件：
- CozyDuke木马
- MiniDuke后门

时间线：
2024-01-15: 首次发现攻击活动
2024-02-20: 确认与APT29关联
2024-03-10: 发现新的C2服务器
""",
        
        "ransomware_darkside_ioc.txt": """
DarkSide勒索软件IoC报告

威胁名称：DarkSide勒索软件
威胁类型：勒索软件
严重程度：高

技术特征：
- 使用AES-256和RSA-1024加密算法
- 针对Windows和Linux系统
- 利用CVE-2021-34527(PrintNightmare)漏洞进行权限提升

IoC指标：
- 文件哈希: 
  - SHA256: 7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c
  - MD5: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
- 注册表键: HKLM\SOFTWARE\DarkSideKey
- 文件路径: C:\ProgramData\darkside.exe
- 网络通信: 185.220.101.45:8080

关联组织：DarkSide犯罪集团

影响范围：
- 能源行业
- 制造业
- 金融服务

防护建议：
1. 及时安装安全补丁
2. 实施网络分段
3. 备份关键数据
4. 部署端点检测和响应(EDR)解决方案
""",

        "mitre_attack_techniques.txt": """
MITRE ATT&CK技术分析

T1566.001 - 鱼叉式钓鱼邮件附件
战术：初始访问
描述：攻击者通过包含恶意附件的电子邮件获得初始访问权限
检测方法：
- 邮件附件沙箱分析
- 文件类型过滤
- 用户行为分析

T1055 - 进程注入
战术：防御绕过，权限升级
描述：将代码注入到合法进程中以逃避检测
检测方法：
- 进程监控
- API调用监控
- 内存分析

T1071.001 - 应用层协议：Web协议
战术：命令与控制
描述：使用HTTP/HTTPS进行C2通信
检测方法：
- 网络流量分析
- SSL/TLS证书检查
- 域名信誉检查

T1027 - 混淆文件或信息
战术：防御绕过
描述：使用编码、加密或其他技术隐藏恶意代码
检测方法：
- 静态分析
- 熵值分析
- 字符串分析

常见组合攻击链：
T1566.001 → T1055 → T1071.001 → T1027
""",

        "cve_vulnerabilities.txt": """
高危漏洞情报报告

CVE-2021-34527 (PrintNightmare)
CVSS评分：8.8 (高危)
影响组件：Windows Print Spooler
漏洞类型：权限提升/远程代码执行
发布日期：2021-07-06
修复状态：已修复

漏洞描述：
Windows Print Spooler服务中的权限提升漏洞，可能允许攻击者以系统权限执行任意代码。

利用场景：
- 本地权限提升
- 横向移动
- 持久化

相关APT组织：
- APT29使用此漏洞进行权限提升
- Lazarus Group在勒索软件攻击中利用此漏洞

防护措施：
1. 立即安装KB5004945补丁
2. 禁用Print Spooler服务（如不需要）
3. 限制网络打印机访问
4. 监控异常打印机驱动程序安装

CVE-2023-23397 (Outlook权限提升)
CVSS评分：9.8 (严重)
影响组件：Microsoft Outlook
漏洞类型：权限提升
发布日期：2023-03-14

攻击向量：恶意邮件中的Calendar对象
被利用组织：多个APT组织在野利用
"""
    }
    
    # 创建示例文档目录
    docs_dir = project_root / "sample_threat_docs"
    docs_dir.mkdir(exist_ok=True)
    
    for filename, content in sample_docs.items():
        doc_path = docs_dir / filename
        with open(doc_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    logger.info(f"已创建 {len(sample_docs)} 个示例威胁情报文档")
    return str(docs_dir)


def main():
    """主函数"""
    logger.info("=== 威胁情报RAG系统完整示例 ===")
    
    # 检查配置
    settings = get_settings()
    if not settings.deepseek_api_key:
        logger.warning("未配置DeepSeek API密钥，某些功能可能无法使用")
    if not settings.zhipuai_api_key:
        logger.warning("未配置ZhipuAI API密钥，将使用默认嵌入模型")
    
    try:
        # 1. 创建示例文档
        logger.info("1. 创建示例威胁情报文档")
        docs_dir = create_sample_threat_docs()
        
        # 2. 初始化RAG引擎
        logger.info("2. 初始化威胁情报RAG引擎")
        with ThreatIntelRAGEngine(auto_init=True) as rag_engine:
            
            # 3. 摄取文档并构建知识图谱
            logger.info("3. 摄取文档并构建知识图谱")
            ingest_result = rag_engine.ingest_documents(
                source=docs_dir,
                source_type="directory",
                build_knowledge_graph=True,
                return_stats=True
            )
            
            print(f"\n📊 文档摄取统计:")
            print(f"- 处理文档数: {ingest_result.get('stats', {}).get('processed_files', 0)}")
            print(f"- 生成分块数: {ingest_result.get('stats', {}).get('total_chunks', 0)}")
            print(f"- 向量存储: {ingest_result.get('stats', {}).get('stored_vectors', 0)}")
            if 'graph_stats' in ingest_result:
                graph_stats = ingest_result['graph_stats']
                print(f"- 创建节点数: {graph_stats.get('created_nodes', 0)}")
                print(f"- 创建关系数: {graph_stats.get('created_relationships', 0)}")
            
            # 等待一下让数据完全索引
            time.sleep(2)
            
            # 4. 基础RAG查询测试
            logger.info("4. 测试基础RAG查询")
            
            test_queries = [
                "APT29使用了哪些攻击技术？",
                "DarkSide勒索软件有什么特征？",
                "CVE-2021-34527漏洞的影响是什么？",
                "192.168.100.5这个IP地址有什么威胁信息？"
            ]
            
            for query in test_queries:
                print(f"\n🔍 查询: {query}")
                
                # 混合检索查询
                result = rag_engine.query(
                    question=query,
                    retrieval_method="hybrid",
                    response_type="comprehensive",
                    top_k=5
                )
                
                print(f"💬 回答: {result['response'][:300]}...")
                print(f"📈 置信度: {result['metadata']['confidence_score']}")
                print(f"📚 使用来源: {result['metadata']['sources_used']}")
                print("-" * 50)
            
            # 5. 威胁分析功能测试
            logger.info("5. 测试威胁分析功能")
            
            threat_analysis = rag_engine.analyze_threat(
                query="分析APT29的最新攻击活动和使用的技术",
                include_graph_analysis=True
            )
            
            print(f"\n🎯 威胁分析报告:")
            print(f"风险等级: {threat_analysis.get('risk_level', '未知')}")
            print(f"威胁指标数量: {len(threat_analysis.get('threat_indicators', {}).get('iocs', []))}")
            print(f"防护建议: {len(threat_analysis.get('recommendations', []))}")
            
            # 6. IoC分析功能测试
            logger.info("6. 测试IoC分析功能")
            
            ioc_analysis = rag_engine.analyze_ioc(
                ioc_value="192.168.100.5",
                ioc_type="ip"
            )
            
            print(f"\n🔍 IoC分析结果:")
            print(f"威胁等级: {ioc_analysis.get('threat_level', '未知')}")
            print(f"关联恶意软件: {ioc_analysis.get('associated_malware', [])}")
            print(f"关联APT组织: {ioc_analysis.get('apt_groups', [])}")
            
            # 7. 相似威胁搜索
            logger.info("7. 测试相似威胁搜索")
            
            similar_threats = rag_engine.search_similar_threats(
                reference_threat="勒索软件攻击使用鱼叉式钓鱼邮件",
                similarity_threshold=0.3,
                max_results=5
            )
            
            print(f"\n🔗 找到 {len(similar_threats)} 个相似威胁")
            for i, threat in enumerate(similar_threats[:3], 1):
                print(f"{i}. 相似度: {threat['retrieval_score']:.2f}")
                print(f"   内容: {threat['content'][:100]}...")
            
            # 8. 威胁态势分析
            logger.info("8. 测试威胁态势分析")
            
            landscape = rag_engine.get_threat_landscape()
            
            print(f"\n🌍 威胁态势概览:")
            stats = landscape.get('statistics', {})
            print(f"- IoC数量: {stats.get('ioc_count', 0)}")
            print(f"- 恶意软件数量: {stats.get('malware_count', 0)}")
            print(f"- APT组织数量: {stats.get('apt_count', 0)}")
            print(f"- 漏洞数量: {stats.get('vuln_count', 0)}")
            
            # 9. 自然语言图谱查询
            logger.info("9. 测试自然语言图谱查询")
            
            nl_queries = [
                "有哪些APT组织使用了鱼叉式钓鱼攻击？",
                "DarkSide勒索软件与哪些IoC相关？",
                "CVE-2021-34527被哪些威胁组织利用？"
            ]
            
            for nl_query in nl_queries:
                print(f"\n❓ 图谱查询: {nl_query}")
                nl_result = rag_engine.natural_language_query(nl_query)
                print(f"📋 结果: {nl_result[:200]}...")
            
            # 10. 系统状态检查
            logger.info("10. 检查系统状态")
            
            status = rag_engine.get_system_status()
            
            print(f"\n⚙️ 系统状态:")
            print(f"向量存储: {status.get('vector_store', {}).get('collection_name', '未知')}")
            print(f"嵌入模型: {status.get('embedder', {}).get('model', '未知')}")
            print(f"LLM模型: {status.get('llm', {}).get('model', '未知')}")
            
            # 11. 演示不同检索方法的对比
            logger.info("11. 对比不同检索方法")
            
            comparison_query = "APT29的攻击特征和使用的恶意软件"
            
            methods = ["vector", "graph", "hybrid"]
            for method in methods:
                result = rag_engine.query(
                    question=comparison_query,
                    retrieval_method=method,
                    response_type="brief",
                    top_k=3
                )
                
                print(f"\n🔄 {method.upper()}检索:")
                print(f"置信度: {result['metadata']['confidence_score']}")
                print(f"回答: {result['response'][:150]}...")
            
            logger.info("✅ 所有测试完成！")
            
    except Exception as e:
        logger.error(f"示例运行失败: {str(e)}")
        raise


if __name__ == "__main__":
    main() 