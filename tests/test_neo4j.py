import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.knowledge_graph.neo4j_client import Neo4jClient
from src.utils.config import get_settings

def test_neo4j_connection():
    settings = get_settings()
    print(f"配置信息:")
    print(f"  URI: {settings.neo4j_uri}")
    print(f"  用户名: {settings.neo4j_username}")
    print(f"  密码: {settings.neo4j_password}")
    
    try:
        print("\n尝试连接Neo4j...")
        client = Neo4jClient()
        print("✅ Neo4j连接成功!")
        
        # 测试基本查询
        result = client.run_query("RETURN 'Hello, Neo4j!' as message")
        print(f"测试查询结果: {result}")
        
        client.close()
        
    except Exception as e:
        print(f"❌ Neo4j连接失败: {str(e)}")
        print(f"错误类型: {type(e).__name__}")

if __name__ == "__main__":
    test_neo4j_connection() 