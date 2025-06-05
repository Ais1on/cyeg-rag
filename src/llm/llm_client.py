"""
LLM客户端基类
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from loguru import logger


class LLMClient(ABC):
    """LLM客户端基类"""
    
    def __init__(self, model_name: str, api_key: str, base_url: str = None):
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url
    
    @abstractmethod
    def generate_text(
        self,
        prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.1,
        **kwargs
    ) -> str:
        """生成文本"""
        pass
    
    @abstractmethod
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 2048,
        temperature: float = 0.1,
        **kwargs
    ) -> str:
        """聊天对话"""
        pass
    
    def extract_entities(
        self,
        text: str,
        entity_types: List[str] = None
    ) -> Dict[str, List[str]]:
        """提取命名实体"""
        if entity_types is None:
            entity_types = ["PERSON", "ORG", "GPE", "CVE", "MALWARE", "IOC"]
        
        prompt = f"""
请从以下文本中提取指定类型的实体：

实体类型：{', '.join(entity_types)}

文本：
{text}

请以JSON格式返回结果，例如：
{{
    "PERSON": ["张三", "李四"],
    "ORG": ["公司A", "组织B"],
    "CVE": ["CVE-2023-1234"],
    "MALWARE": ["病毒名称"],
    "IOC": ["IP地址", "域名", "哈希值"]
}}
"""
        
        try:
            response = self.generate_text(prompt, max_tokens=1024, temperature=0.1)
            # 简单的JSON解析，实际应用中需要更健壮的处理
            import json
            return json.loads(response)
        except Exception as e:
            logger.error(f"实体提取失败: {str(e)}")
            return {}
    
    def generate_summary(
        self,
        text: str,
        max_length: int = 200
    ) -> str:
        """生成文本摘要"""
        prompt = f"""
请为以下文本生成一个简洁的摘要，不超过{max_length}字：

{text}

摘要：
"""
        
        try:
            return self.generate_text(prompt, max_tokens=max_length * 2, temperature=0.1)
        except Exception as e:
            logger.error(f"摘要生成失败: {str(e)}")
            return ""
    
    def analyze_threat_intelligence(
        self,
        text: str
    ) -> Dict[str, Any]:
        """分析威胁情报"""
        prompt = f"""
请分析以下威胁情报文本，提取关键信息：

文本：
{text}

请从以下方面进行分析：
1. 威胁类型
2. 攻击者/组织
3. 攻击目标
4. 攻击技术和战术
5. IoC指标
6. 影响范围
7. 防护建议

请以结构化的JSON格式返回分析结果。
"""
        
        try:
            response = self.generate_text(prompt, max_tokens=2048, temperature=0.1)
            import json
            return json.loads(response)
        except Exception as e:
            logger.error(f"威胁情报分析失败: {str(e)}")
            return {}
    
    def answer_question(
        self,
        question: str,
        context: str,
        max_tokens: int = 1024
    ) -> str:
        """基于上下文回答问题"""
        messages = [
            {
                "role": "system",
                "content": "你是一个威胁情报分析专家。请基于提供的上下文信息回答问题，如果上下文中没有相关信息，请明确说明。"
            },
            {
                "role": "user",
                "content": f"上下文：\n{context}\n\n问题：{question}"
            }
        ]
        
        try:
            return self.chat_completion(messages, max_tokens=max_tokens, temperature=0.1)
        except Exception as e:
            logger.error(f"问答失败: {str(e)}")
            return "抱歉，无法回答此问题。" 