"""
配置管理模块
"""
import os
from typing import Optional
from pydantic import BaseSettings
from loguru import logger


class Settings(BaseSettings):
    """系统配置"""
    
    # OpenAI配置
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    
    # DeepSeek配置
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com/v1"
    
    # ZhipuAI配置
    zhipuai_api_key: str = ""
    
    # Milvus配置
    milvus_host: str = "localhost"
    milvus_port: int = 19530
    milvus_username: str = ""
    milvus_password: str = ""
    
    # Neo4j配置
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "password123"
    
    # 文档处理配置
    chunk_size: int = 512
    chunk_overlap: int = 50
    embedding_model: str = "zhipuai-embedding-3"
    
    # LLM配置
    llm_model: str = "deepseek-chat"
    max_tokens: int = 2048
    temperature: float = 0.1
    
    # 日志配置
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# 全局配置实例
settings = Settings()


def get_settings() -> Settings:
    """获取配置实例"""
    return settings


def setup_logging():
    """设置日志配置"""
    logger.remove()
    logger.add(
        "logs/app.log",
        rotation="1 day",
        retention="30 days",
        level=settings.log_level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}"
    )
    logger.add(
        lambda msg: print(msg, end=""),
        level=settings.log_level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | <cyan>{name}:{function}:{line}</cyan> | {message}"
    )


# 确保logs目录存在
os.makedirs("logs", exist_ok=True)
setup_logging() 