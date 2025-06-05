#!/usr/bin/env python3
"""
快速设置脚本 - 自动配置威胁情报RAG系统
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path


def check_python_version():
    """检查Python版本"""
    if sys.version_info < (3, 8):
        print("❌ 错误: 需要Python 3.8或更高版本")
        print(f"当前版本: {sys.version}")
        sys.exit(1)
    print(f"✅ Python版本检查通过: {sys.version.split()[0]}")


def check_docker():
    """检查Docker是否安装"""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Docker已安装: {result.stdout.strip()}")
            return True
        else:
            print("❌ Docker未正确安装")
            return False
    except FileNotFoundError:
        print("❌ Docker未安装")
        return False


def check_docker_compose():
    """检查Docker Compose是否安装"""
    try:
        result = subprocess.run(['docker-compose', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Docker Compose已安装: {result.stdout.strip()}")
            return True
        else:
            # 尝试新版本的命令
            result = subprocess.run(['docker', 'compose', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Docker Compose已安装: {result.stdout.strip()}")
                return True
            print("❌ Docker Compose未正确安装")
            return False
    except FileNotFoundError:
        print("❌ Docker Compose未安装")
        return False


def create_env_file():
    """创建.env文件"""
    env_example = Path("env.example")
    env_file = Path(".env")
    
    if env_file.exists():
        print("⚠️  .env文件已存在，跳过创建")
        return
    
    if env_example.exists():
        shutil.copy(env_example, env_file)
        print("✅ 已创建.env文件（从env.example复制）")
        print("📝 请编辑.env文件，填入必要的配置信息")
    else:
        print("❌ env.example文件不存在")


def install_dependencies():
    """安装Python依赖"""
    print("📦 正在安装Python依赖...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True)
        print("✅ Python依赖安装完成")
    except subprocess.CalledProcessError:
        print("❌ Python依赖安装失败")
        sys.exit(1)


def start_services():
    """启动Docker服务"""
    print("🚀 正在启动Docker服务...")
    
    try:
        # 检查docker-compose.yml是否存在
        if not Path("docker-compose.yml").exists():
            print("❌ docker-compose.yml文件不存在")
            return False
        
        # 启动服务
        subprocess.run(['docker-compose', 'up', '-d'], check=True)
        print("✅ Docker服务启动成功")
        
        # 等待服务启动
        print("⏳ 等待服务启动...")
        import time
        time.sleep(10)
        
        return True
    except subprocess.CalledProcessError:
        try:
            # 尝试新版本命令
            subprocess.run(['docker', 'compose', 'up', '-d'], check=True)
            print("✅ Docker服务启动成功")
            
            print("⏳ 等待服务启动...")
            import time
            time.sleep(10)
            
            return True
        except subprocess.CalledProcessError:
            print("❌ Docker服务启动失败")
            return False


def check_services():
    """检查服务状态"""
    print("🔍 检查服务状态...")
    
    # 检查Milvus
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 19530))
        sock.close()
        
        if result == 0:
            print("✅ Milvus服务正在运行 (端口19530)")
        else:
            print("❌ Milvus服务未运行")
    except Exception as e:
        print(f"❌ 检查Milvus服务失败: {e}")
    
    # 检查Neo4j
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 7687))
        sock.close()
        
        if result == 0:
            print("✅ Neo4j服务正在运行 (端口7687)")
        else:
            print("❌ Neo4j服务未运行")
    except Exception as e:
        print(f"❌ 检查Neo4j服务失败: {e}")


def create_directories():
    """创建必要的目录"""
    directories = ['data', 'logs', 'data/sample_threat_intel']
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("✅ 创建必要目录完成")


def run_example():
    """运行示例"""
    print("🏃 运行基本示例...")
    
    try:
        subprocess.run([sys.executable, 'examples/basic_rag_example.py'], check=True)
        print("✅ 示例运行成功")
    except subprocess.CalledProcessError:
        print("❌ 示例运行失败，可能是服务未完全启动")
        print("💡 建议: 等待几分钟后手动运行 'python examples/basic_rag_example.py'")


def main():
    """主函数"""
    print("🎯 威胁情报RAG系统设置向导")
    print("=" * 50)
    
    # 1. 检查Python版本
    check_python_version()
    
    # 2. 检查Docker
    docker_ok = check_docker()
    docker_compose_ok = check_docker_compose()
    
    if not (docker_ok and docker_compose_ok):
        print("\n❌ Docker或Docker Compose未安装")
        print("请先安装Docker和Docker Compose:")
        print("- Docker: https://docs.docker.com/get-docker/")
        print("- Docker Compose: https://docs.docker.com/compose/install/")
        sys.exit(1)
    
    # 3. 创建环境文件
    create_env_file()
    
    # 4. 创建目录
    create_directories()
    
    # 5. 安装依赖
    install_dependencies()
    
    # 6. 询问是否启动服务
    response = input("\n🤔 是否启动Docker服务? (y/N): ").lower().strip()
    
    if response in ['y', 'yes']:
        if start_services():
            check_services()
            
            # 询问是否运行示例
            response = input("\n🤔 是否运行基本示例? (y/N): ").lower().strip()
            if response in ['y', 'yes']:
                run_example()
        else:
            print("\n❌ 服务启动失败，请检查Docker配置")
    
    print("\n🎉 设置完成!")
    print("\n📋 下一步:")
    print("1. 编辑 .env 文件，配置必要的API密钥")
    print("2. 启动服务: docker-compose up -d")
    print("3. 运行示例: python examples/basic_rag_example.py")
    print("4. 查看文档: README.md 和 config/README.md")


if __name__ == "__main__":
    main() 