#!/usr/bin/env python3
"""
威胁情报RAG系统快速设置脚本
支持 deepseek-chat + zhipuAI embedding-3
"""

import os
import sys
import subprocess
from pathlib import Path
import shutil
from loguru import logger

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent


def check_python_version():
    """检查Python版本"""
    if sys.version_info < (3, 8):
        logger.error("需要Python 3.8或更高版本")
        sys.exit(1)
    logger.info(f"Python版本: {sys.version}")


def install_dependencies():
    """安装依赖"""
    logger.info("安装项目依赖...")
    
    try:
        # 安装requirements.txt中的依赖
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", 
            str(PROJECT_ROOT / "requirements.txt")
        ], check=True)
        
        logger.info("✅ 依赖安装完成")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"依赖安装失败: {e}")
        sys.exit(1)


def setup_environment():
    """设置环境变量"""
    logger.info("设置环境变量...")
    
    env_file = PROJECT_ROOT / ".env"
    env_example = PROJECT_ROOT / "env.example"
    
    if not env_file.exists():
        if env_example.exists():
            shutil.copy(env_example, env_file)
            logger.info(f"已复制环境变量模板到 {env_file}")
        else:
            # 创建基本的.env文件
            env_content = """# OpenAI API配置
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_BASE_URL=https://api.openai.com/v1

# DeepSeek API配置
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1

# ZhipuAI API配置
ZHIPUAI_API_KEY=your_zhipuai_api_key_here

# Milvus配置
MILVUS_HOST=localhost
MILVUS_PORT=19530
MILVUS_USERNAME=
MILVUS_PASSWORD=

# Neo4j配置
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password123

# 其他配置
LOG_LEVEL=INFO
CHUNK_SIZE=512
CHUNK_OVERLAP=50
EMBEDDING_MODEL=zhipuai-embedding-3
"""
            with open(env_file, 'w', encoding='utf-8') as f:
                f.write(env_content)
            logger.info(f"已创建环境变量文件 {env_file}")
    
    logger.warning("⚠️  请编辑 .env 文件，填入您的API密钥")


def check_docker():
    """检查Docker是否可用"""
    try:
        result = subprocess.run(["docker", "--version"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"✅ Docker可用: {result.stdout.strip()}")
            return True
        else:
            logger.warning("⚠️  Docker不可用")
            return False
    except FileNotFoundError:
        logger.warning("⚠️  Docker未安装")
        return False


def start_services():
    """启动Milvus和Neo4j服务"""
    logger.info("启动依赖服务...")
    
    if not check_docker():
        logger.warning("Docker不可用，请手动启动Milvus和Neo4j")
        return
    
    docker_compose_file = PROJECT_ROOT / "docker-compose.yml"
    
    if not docker_compose_file.exists():
        logger.warning(f"未找到 {docker_compose_file}")
        return
    
    try:
        # 启动服务
        subprocess.run([
            "docker-compose", "-f", str(docker_compose_file), 
            "up", "-d"
        ], check=True, cwd=PROJECT_ROOT)
        
        logger.info("✅ 服务启动成功")
        logger.info("- Milvus: http://localhost:19530")
        logger.info("- Neo4j: http://localhost:7474 (neo4j/password123)")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"服务启动失败: {e}")
        logger.info("请手动启动Milvus和Neo4j服务")


def verify_setup():
    """验证设置"""
    logger.info("验证系统设置...")
    
    try:
        # 添加项目根目录到Python路径
        sys.path.insert(0, str(PROJECT_ROOT))
        
        from src.utils.config import get_settings
        
        settings = get_settings()
        
        # 检查配置
        checks = {
            "嵌入模型配置": settings.embedding_model == "zhipuai-embedding-3",
            "DeepSeek API配置": bool(settings.deepseek_api_key and settings.deepseek_api_key != "your_deepseek_api_key_here"),
            "ZhipuAI API配置": bool(settings.zhipuai_api_key and settings.zhipuai_api_key != "your_zhipuai_api_key_here"),
            "Milvus配置": bool(settings.milvus_host),
            "Neo4j配置": bool(settings.neo4j_uri)
        }
        
        for check_name, passed in checks.items():
            status = "✅" if passed else "❌"
            logger.info(f"{status} {check_name}")
        
        return all(checks.values())
        
    except Exception as e:
        logger.error(f"验证失败: {e}")
        return False


def run_example():
    """运行示例"""
    logger.info("运行完整示例...")
    
    try:
        example_script = PROJECT_ROOT / "examples" / "complete_rag_example.py"
        
        if not example_script.exists():
            logger.warning(f"示例脚本不存在: {example_script}")
            return
        
        # 运行示例
        subprocess.run([sys.executable, str(example_script)], 
                      cwd=PROJECT_ROOT, check=True)
        
        logger.info("✅ 示例运行完成")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"示例运行失败: {e}")
    except KeyboardInterrupt:
        logger.info("示例运行被用户中断")


def main():
    """主函数"""
    print("🚀 威胁情报RAG系统快速设置")
    print("=" * 50)
    
    # 1. 检查Python版本
    check_python_version()
    
    # 2. 安装依赖
    install_dependencies()
    
    # 3. 设置环境变量
    setup_environment()
    
    # 4. 启动服务
    start_services()
    
    # 等待服务启动
    import time
    logger.info("等待服务完全启动...")
    time.sleep(10)
    
    # 5. 验证设置
    setup_ok = verify_setup()
    
    if not setup_ok:
        logger.warning("⚠️  设置不完整，请检查配置文件")
        logger.info("手动步骤:")
        logger.info("1. 编辑 .env 文件，填入API密钥")
        logger.info("2. 确保Milvus和Neo4j服务正在运行")
        logger.info("3. 运行: python examples/complete_rag_example.py")
        return
    
    # 6. 询问是否运行示例
    try:
        run_demo = input("\n✅ 设置完成！是否运行完整示例？(y/N): ").lower().strip()
        if run_demo in ['y', 'yes', '是']:
            run_example()
        else:
            logger.info("您可以稍后运行: python examples/complete_rag_example.py")
    except KeyboardInterrupt:
        logger.info("\n设置完成！")
    
    print("\n🎉 威胁情报RAG系统设置完成！")
    print("\n快速开始:")
    print("```python")
    print("from src.rag_engine.rag_engine import ThreatIntelRAGEngine")
    print("")
    print("# 初始化RAG引擎")
    print("rag_engine = ThreatIntelRAGEngine()")
    print("")
    print("# 摄取文档")
    print("result = rag_engine.ingest_documents('path/to/docs')")
    print("")
    print("# 查询")
    print("answer = rag_engine.query('APT29使用了哪些攻击技术？')")
    print("print(answer['response'])")
    print("```")


if __name__ == "__main__":
    main() 