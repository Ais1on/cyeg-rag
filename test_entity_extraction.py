#!/usr/bin/env python3
"""
测试实体提取功能
"""
import sys
import os
import traceback

# 添加项目根目录到路径
sys.path.append(os.path.dirname(__file__))

from src.knowledge_graph.graph_builder import ThreatIntelGraphBuilder
from src.knowledge_graph.neo4j_client import Neo4jClient
from src.llm.deepseek_client import DeepSeekClient
from src.document_processor.chunker import DocumentChunk
from src.utils.config import get_settings
from loguru import logger

def test_neo4j_connection():
    """测试Neo4j连接"""
    try:
        neo4j = Neo4jClient()
        result = neo4j.run_query("RETURN 'Hello Neo4j' as message")
        print(f"✅ Neo4j连接成功: {result}")
        neo4j.close()
        return True
    except Exception as e:
        print(f"❌ Neo4j连接失败: {str(e)}")
        return False

def test_llm_connection():
    """测试LLM连接"""
    try:
        settings = get_settings()
        llm = DeepSeekClient(
            api_key=settings.deepseek_api_key,
            base_url=settings.deepseek_base_url
        )
        
        # 简单测试
        response = llm.generate_text("请说'Hello'", max_tokens=10)
        print(f"✅ LLM连接成功: {response}")
        return True
    except Exception as e:
        print(f"❌ LLM连接失败: {str(e)}")
        return False

def test_entity_extraction():
    """测试实体提取"""
    try:
        # 初始化组件
        builder = ThreatIntelGraphBuilder()
        print("✅ 图构建器初始化成功")
        
        # 测试文本
        test_text = """
APT29组织（也称为Cozy Bear）是俄罗斯政府支持的高级持续性威胁组织。
该组织使用恶意软件CozyDuke和MiniDuke进行攻击。
攻击中利用了CVE-2023-1234漏洞，IP地址192.168.1.100和域名evil-c2.example.com被发现用于C2通信。
攻击使用了MITRE ATT&CK技术T1566.001（鱼叉式钓鱼邮件附件）。
"""
        
        print(f"测试文本: {test_text[:100]}...")
        
        # 测试LLM实体提取
        print("\n🔍 测试LLM实体提取...")
        entities = builder._extract_entities_with_llm(test_text)
        print(f"提取结果: {entities}")
        
        if entities:
            print("✅ LLM实体提取成功")
            for entity_type, entity_list in entities.items():
                print(f"  {entity_type}: {len(entity_list)} 个实体")
        else:
            print("❌ LLM实体提取返回空结果")
            
        # 测试创建测试chunk
        chunk = DocumentChunk(
            content=test_text,
            metadata={'source': 'test.txt', 'chunk_index': 0},
            chunk_id='test_chunk_1'
        )
        
        # 测试处理实体
        print("\n🔍 测试实体节点创建...")
        entity_nodes = builder._process_entities(entities, chunk)
        print(f"创建的实体节点: {len(entity_nodes)} 个")
        
        for node in entity_nodes:
            print(f"  节点: {node.get('label', 'Unknown')} - {node}")
            
        return entities, entity_nodes
        
    except Exception as e:
        print(f"❌ 实体提取测试失败: {str(e)}")
        traceback.print_exc()
        return None, None

def test_graph_building():
    """测试知识图谱构建"""
    try:
        builder = ThreatIntelGraphBuilder()
        
        # 创建测试chunk
        test_chunk = DocumentChunk(
            content="APT29使用CozyDuke恶意软件攻击目标，利用CVE-2023-1234漏洞。",
            metadata={'source': 'test.txt', 'file_type': 'txt'},
            chunk_id='test_chunk_for_graph'
        )
        
        print("🔍 测试知识图谱构建...")
        stats = builder.build_graph_from_documents([test_chunk], extract_entities=True)
        print(f"构建统计: {stats}")
        
        if stats['created_nodes'] > 0:
            print("✅ 知识图谱构建成功")
        else:
            print("❌ 知识图谱构建失败：没有创建任何节点")
            
        return stats
        
    except Exception as e:
        print(f"❌ 知识图谱构建测试失败: {str(e)}")
        traceback.print_exc()
        return None

def main():
    """主测试函数"""
    print("🚀 开始诊断实体提取问题\n")
    
    # 1. 测试Neo4j连接
    print("1️⃣ 测试Neo4j连接")
    neo4j_ok = test_neo4j_connection()
    print()
    
    # 2. 测试LLM连接
    print("2️⃣ 测试LLM连接")
    llm_ok = test_llm_connection()
    print()
    
    # 3. 测试实体提取
    print("3️⃣ 测试实体提取")
    entities, entity_nodes = test_entity_extraction()
    print()
    
    # 4. 测试知识图谱构建
    if neo4j_ok and entities:
        print("4️⃣ 测试知识图谱构建")
        graph_stats = test_graph_building()
        print()
    
    # 总结
    print("📋 诊断总结:")
    print(f"  Neo4j连接: {'✅' if neo4j_ok else '❌'}")
    print(f"  LLM连接: {'✅' if llm_ok else '❌'}")
    print(f"  实体提取: {'✅' if entities else '❌'}")
    print(f"  实体节点: {'✅' if entity_nodes else '❌'}")
    
    if not neo4j_ok:
        print("\n🔧 建议: 检查Neo4j服务是否启动，配置是否正确")
    if not llm_ok:
        print("\n🔧 建议: 检查DeepSeek API密钥和网络连接")
    if not entities:
        print("\n🔧 建议: 检查LLM提示词和响应解析")

if __name__ == "__main__":
    main() 