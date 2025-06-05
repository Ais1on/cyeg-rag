"""
DeepSeek LLM客户端
"""
import httpx
from typing import List, Dict, Any
from loguru import logger
from .llm_client import LLMClient


class DeepSeekClient(LLMClient):
    """DeepSeek LLM客户端"""
    
    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com/v1"):
        super().__init__("deepseek-chat", api_key, base_url)
        self.client = httpx.Client(timeout=60.0)
    
    def generate_text(
        self,
        prompt: str,
        max_tokens: int = 2048,
        temperature: float = 0.1,
        **kwargs
    ) -> str:
        """生成文本"""
        messages = [{"role": "user", "content": prompt}]
        return self.chat_completion(messages, max_tokens, temperature, **kwargs)
    
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 2048,
        temperature: float = 0.1,
        **kwargs
    ) -> str:
        """聊天对话"""
        try:
            payload = {
                "model": self.model_name,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False
            }
            
            # 添加其他参数
            payload.update(kwargs)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            response = self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers
            )
            
            response.raise_for_status()
            result = response.json()
            
            return result["choices"][0]["message"]["content"]
            
        except Exception as e:
            logger.error(f"DeepSeek API调用失败: {str(e)}")
            raise
    
    def stream_chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 2048,
        temperature: float = 0.1,
        **kwargs
    ):
        """流式聊天"""
        try:
            payload = {
                "model": self.model_name,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": True
            }
            
            payload.update(kwargs)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            with self.client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers
            ) as response:
                response.raise_for_status()
                
                for line in response.iter_lines():
                    if line:
                        line = line.strip()
                        if line.startswith(b"data: "):
                            data = line[6:]  # 移除 "data: " 前缀
                            if data == b"[DONE]":
                                break
                            
                            try:
                                import json
                                chunk = json.loads(data.decode('utf-8'))
                                if "choices" in chunk:
                                    delta = chunk["choices"][0].get("delta", {})
                                    if "content" in delta:
                                        yield delta["content"]
                            except json.JSONDecodeError:
                                continue
                                
        except Exception as e:
            logger.error(f"DeepSeek流式API调用失败: {str(e)}")
            raise
    
    def extract_threat_entities_advanced(
        self,
        text: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """高级威胁实体提取"""
        prompt = f"""
作为威胁情报分析专家，请从以下文本中提取威胁情报相关的实体，并为每个实体提供详细信息：

文本：
{text}

请提取以下类型的实体，并为每个实体提供坐标位置、置信度和相关上下文：

1. IoC指标（IP地址、域名、文件哈希、URL）
2. CVE漏洞编号
3. 恶意软件名称
4. APT组织名称
5. 攻击技术和战术（MITRE ATT&CK）
6. 文件类型和路径
7. 地理位置
8. 时间信息

返回JSON格式，例如：
{{
    "ioc": [
        {{
            "value": "192.168.1.1",
            "type": "ip",
            "context": "发现恶意IP地址",
            "confidence": 0.95
        }}
    ],
    "cve": [
        {{
            "value": "CVE-2023-1234",
            "severity": "high",
            "context": "利用该漏洞进行攻击"
        }}
    ],
    "malware": [...],
    "apt_groups": [...],
    "techniques": [...],
    "files": [...],
    "locations": [...],
    "timestamps": [...]
}}
"""
        
        try:
            response = self.generate_text(prompt, max_tokens=2048, temperature=0.1)
            import json
            return json.loads(response)
        except Exception as e:
            logger.error(f"高级威胁实体提取失败: {str(e)}")
            return {}
    
    def generate_threat_report(
        self,
        findings: Dict[str, Any],
        title: str = "威胁情报分析报告"
    ) -> str:
        """生成威胁情报报告"""
        prompt = f"""
基于以下威胁情报发现，生成一份专业的威胁分析报告：

标题：{title}

发现的威胁信息：
{findings}

请生成一份结构化的威胁情报报告，包含以下部分：

1. 执行摘要
2. 威胁概述
3. 技术分析
4. IoC指标汇总
5. 影响评估
6. 防护建议
7. 结论

报告应该专业、准确、易于理解，适合向技术和管理人员汇报。
"""
        
        try:
            return self.generate_text(prompt, max_tokens=4096, temperature=0.1)
        except Exception as e:
            logger.error(f"威胁报告生成失败: {str(e)}")
            return ""
    
    def __del__(self):
        """清理资源"""
        if hasattr(self, 'client'):
            self.client.close() 