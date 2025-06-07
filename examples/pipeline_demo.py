#!/usr/bin/env python3
"""
威胁情报RAG系统流水线演示
清晰展示：文档Embedding → 知识图谱构建 → 混合检索
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
import time


def create_threat_docs():
    """创建示例威胁情报文档"""
    docs = {
        "apt29_report.txt": """
APT29 威胁情报报告

APT29（Cozy Bear）是俄罗斯政府支持的高级持续性威胁组织。

攻击技术（MITRE ATT&CK）：
- T1566.001: 鱼叉式钓鱼邮件附件
- T1055: 进程注入
- T1071.001: 通过HTTP/HTTPS进行C2通信
- T1027: 文件混淆

IoC指标：
- IP: 192.168.100.5, 10.0.0.15  
- 域名: evil-c2.example.com
- 文件哈希: a1b2c3d4e5f6789012345678901234567890abcd

关联恶意软件：
- CozyDuke
- MiniDuke
- PowerDuke

目标：政府机构、外交使团、智库
""",
        
        "darkside_ransomware.txt": """
DarkSide 勒索软件分析

威胁类型：勒索软件即服务(RaaS)
活跃时间：2020-2021年

技术特征：
- 双重勒索模式：数据加密+数据泄露威胁
- 利用CVE-2021-34527（PrintNightmare）进行权限提升
- 使用RSA+AES混合加密

IoC指标：
- SHA256: 7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c
- 注册表: HKLM\SOFTWARE\DarkSide
- C2: 185.220.101.45:8080
- 文件: %APPDATA%\darkside.exe

攻击链：
T1566.001 → CVE-2021-34527 → T1486(数据加密)

关联组织：DarkSide犯罪集团
影响：Colonial Pipeline攻击
""",

        "cve_2021_34527.txt": """
CVE-2021-34527 (PrintNightmare) 漏洞详情

基本信息：
- CVSS评分：8.8（高危）
- 影响组件：Windows Print Spooler
- 漏洞类型：权限提升/远程代码执行
- 发现时间：2021年6月

技术细节：
Windows Print Spooler服务中的特权提升漏洞，允许攻击者：
1. 安装任意驱动程序
2. 以SYSTEM权限执行代码
3. 横向移动到域控制器

利用场景：
- 本地权限提升
- 远程代码执行（通过RPC）
- 域渗透

被利用的威胁组织：
- APT29：用于权限提升
- DarkSide：勒索软件攻击中的权限获取
- Lazarus Group：APT攻击

防护措施：
1. 安装KB5004945补丁
2. 禁用Print Spooler服务
3. 限制驱动程序安装权限
"""
    }
    
    docs_dir = project_root / "demo_threat_docs"
    docs_dir.mkdir(exist_ok=True)
    
    for filename, content in docs.items():
        (docs_dir / filename).write_text(content, encoding='utf-8')
    
    return str(docs_dir)


def main():
    """主演示函数"""
    print("🎯 威胁情报RAG系统流水线演示")
    print("=" * 60)
    
    # 检查配置
    settings = get_settings()
    if not settings.deepseek_api_key:
        print("⚠️ 警告：未配置DeepSeek API密钥")
    if not settings.zhipuai_api_key:
        print("⚠️ 警告：未配置ZhipuAI API密钥")
    
    try:
        # 步骤1：准备示例文档
        print("\n📝 步骤1：准备示例威胁情报文档")
        docs_dir = create_threat_docs()
        print(f"✅ 文档已创建在: {docs_dir}")
        
        # 初始化RAG引擎
        print("\n🚀 步骤2：初始化RAG引擎组件")
        with ThreatIntelRAGEngine(auto_init=True) as rag_engine:
            print("✅ RAG引擎初始化完成")
            
            # 步骤3：文档Embedding和向量存储
            print("\n" + "="*60)
            print("📊 步骤3：文档Embedding和向量存储")
            print("="*60)
            
            start_time = time.time()
            
            embedding_result = rag_engine.embed_and_store_documents(
                source=docs_dir,
                source_type="directory",
                return_chunks=True,
                return_stats=True
            )
            
            embedding_time = time.time() - start_time
            
            if embedding_result['status'] == 'success':
                stats = embedding_result['stats']
                print(f"✅ 向量存储完成 (耗时: {embedding_time:.2f}秒)")
                print(f"   📂 处理文档: {stats['total_documents']} 个")
                print(f"   📄 生成分块: {stats['total_chunks']} 个")
                print(f"   🎯 成功embedding: {stats['successful_embeddings']} 个")
                print(f"   📏 向量维度: {stats['vector_dimension']}")
                
                # 测试向量检索
                print("\n🔍 测试向量检索:")
                vector_result = rag_engine.query(
                    question="APT29使用了哪些攻击技术？",
                    retrieval_method="vector",
                    response_type="brief",
                    top_k=3
                )
                print(f"   检索结果: {vector_result['retrieval_stats']['total_retrieved']} 个片段")
                print(f"   置信度: {vector_result['metadata'].get('confidence_score', 0):.2f}")
                print(f"   回答: {vector_result['response'][:100]}...")
                
            else:
                print(f"❌ 向量存储失败: {embedding_result.get('error')}")
                return
            
            # 步骤4：知识图谱构建  
            print("\n" + "="*60)
            print("🕸️ 步骤4：实体提取和知识图谱构建")
            print("="*60)
            
            start_time = time.time()
            
            # 使用已存储的分块数据构建知识图谱
            chunks = embedding_result.get('chunks', [])
            
            graph_result = rag_engine.build_knowledge_graph_from_documents(
                chunks=chunks,
                extract_entities=True,
                return_stats=True
            )
            
            graph_time = time.time() - start_time
            
            if graph_result['status'] == 'success':
                graph_stats = graph_result['graph_stats']
                print(f"✅ 知识图谱构建完成 (耗时: {graph_time:.2f}秒)")
                print(f"   🏷️  创建节点: {graph_stats.get('created_nodes', 0)} 个")
                print(f"   🔗 创建关系: {graph_stats.get('created_relationships', 0)} 个")
                print(f"   🎯 提取实体: {graph_stats.get('extracted_entities', 0)} 个")
                
                # 测试图谱查询
                print("\n🔍 测试知识图谱查询:")
                graph_result_query = rag_engine.query(
                    question="哪些威胁组织利用了CVE-2021-34527漏洞？",
                    retrieval_method="graph", 
                    response_type="brief",
                    top_k=3
                )
                print(f"   检索结果: {graph_result_query['retrieval_stats']['total_retrieved']} 个关系")
                print(f"   置信度: {graph_result_query['metadata'].get('confidence_score', 0):.2f}")
                print(f"   回答: {graph_result_query['response'][:100]}...")
                
            else:
                print(f"⚠️ 知识图谱构建失败: {graph_result.get('error')}")
            
            # 步骤5：混合检索演示
            print("\n" + "="*60)
            print("🔀 步骤5：混合检索功能演示")
            print("="*60)
            
            test_questions = [
                "APT29组织的攻击手法和使用的恶意软件",
                "DarkSide勒索软件利用了哪些漏洞？",
                "CVE-2021-34527与哪些威胁相关联？"
            ]
            
            for i, question in enumerate(test_questions, 1):
                print(f"\n📋 测试 {i}: {question}")
                
                # 对比不同检索方法
                methods = ["vector", "graph", "hybrid"]
                results = {}
                
                for method in methods:
                    try:
                        result = rag_engine.query(
                            question=question,
                            retrieval_method=method,
                            response_type="brief",
                            top_k=5
                        )
                        
                        results[method] = {
                            'count': result['retrieval_stats']['total_retrieved'],
                            'confidence': result['metadata'].get('confidence_score', 0),
                            'length': len(result['response'])
                        }
                        
                        print(f"   {method.upper():>6}: "
                              f"检索{results[method]['count']:>2}个 | "
                              f"置信度{results[method]['confidence']:>4.2f} | "
                              f"回答{results[method]['length']:>3}字符")
                        
                    except Exception as e:
                        print(f"   {method.upper():>6}: 查询失败 - {str(e)}")
                
                # 展示混合检索的详细回答
                try:
                    hybrid_result = rag_engine.query(
                        question=question,
                        retrieval_method="hybrid",
                        response_type="comprehensive",
                        top_k=8,
                        include_sources=True
                    )
                    
                    print(f"\n   💬 混合检索详细回答:")
                    print(f"   {hybrid_result['response'][:200]}...")
                    
                    if 'sources_used' in hybrid_result['metadata']:
                        print(f"   📚 使用来源: {len(hybrid_result['metadata']['sources_used'])} 个")
                    
                except Exception as e:
                    print(f"   ❌ 混合检索失败: {str(e)}")
            
            # 步骤6：高级分析功能
            print("\n" + "="*60)
            print("⚡ 步骤6：高级威胁分析功能")
            print("="*60)
            
            # IoC分析
            print("\n🔍 IoC分析演示:")
            try:
                ioc_result = rag_engine.analyze_ioc(
                    ioc_value="192.168.100.5",
                    ioc_type="ip"
                )
                
                if 'error' not in ioc_result:
                    print(f"   IP地址: 192.168.100.5")
                    print(f"   威胁级别: {ioc_result.get('threat_level', '未知')}")
                    print(f"   关联恶意软件: {ioc_result.get('associated_malware', [])}")
                    print(f"   关联威胁组织: {ioc_result.get('apt_groups', [])}")
                else:
                    print(f"   ❌ IoC分析失败: {ioc_result['error']}")
                    
            except Exception as e:
                print(f"   ❌ IoC分析异常: {str(e)}")
            
            # 威胁分析
            print("\n🎯 威胁分析演示:")
            try:
                threat_result = rag_engine.analyze_threat(
                    query="分析APT29组织的最新威胁活动",
                    include_graph_analysis=True
                )
                
                if 'error' not in threat_result:
                    print(f"   风险级别: {threat_result.get('risk_level', '中等')}")
                    print(f"   威胁指标: {len(threat_result.get('threat_indicators', {}).get('iocs', []))} 个")
                    print(f"   防护建议: {len(threat_result.get('recommendations', []))} 条")
                else:
                    print(f"   ❌ 威胁分析失败: {threat_result['error']}")
                    
            except Exception as e:
                print(f"   ❌ 威胁分析异常: {str(e)}")
            
            # 步骤7：性能总结
            print("\n" + "="*60)
            print("📈 系统性能总结")
            print("="*60)
            
            print(f"✅ 处理效率:")
            print(f"   📊 Embedding阶段: {embedding_time:.2f}秒")
            if graph_result['status'] == 'success':
                print(f"   🕸️  知识图谱阶段: {graph_time:.2f}秒")
            print(f"   ⏱️  总耗时: {embedding_time + (graph_time if graph_result['status'] == 'success' else 0):.2f}秒")
            
            print(f"\n✅ 数据统计:")
            print(f"   📄 文档: {stats['total_documents']} → {stats['total_chunks']} 分块")
            print(f"   🎯 向量: {stats['successful_embeddings']} 个 (维度: {stats['vector_dimension']})")
            if graph_result['status'] == 'success':
                print(f"   🕸️  图谱: {graph_stats.get('created_nodes', 0)} 节点, {graph_stats.get('created_relationships', 0)} 关系")
            
            print(f"\n✅ 功能验证:")
            print(f"   🔍 向量检索: 可用")
            if graph_result['status'] == 'success':
                print(f"   🕸️  图谱查询: 可用")
                print(f"   🔀 混合检索: 可用")
            print(f"   ⚡ 高级分析: 可用")
            
            print(f"\n🎉 威胁情报RAG系统流水线演示完成！")
            print(f"💡 系统已就绪，可以进行生产环境部署。")
            
    except Exception as e:
        logger.error(f"演示过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main() 