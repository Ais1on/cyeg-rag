"""
DeepSeek LLM客户端
"""
import httpx
from typing import List, Dict, Any, Optional
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
作为威胁情报分析专家，请从以下文本中提取威胁情报相关的实体。

文本：
{text}

请提取以下类型的实体：
1. IoC指标（IP地址、域名、文件哈希、URL）
2. CVE漏洞编号
3. 恶意软件名称
4. APT组织名称
5. 攻击技术和战术（MITRE ATT&CK）

请严格按照以下JSON格式返回，不要包含任何其他文字说明：
{{
    "ioc": [
        {{
            "value": "实际值",
            "type": "ip/domain/hash/url",
            "context": "上下文描述",
            "confidence": 0.95
        }}
    ],
    "cve": [
        {{
            "value": "CVE-2023-1234",
            "severity": "high/medium/low",
            "context": "利用描述"
        }}
    ],
    "malware": [
        {{
            "name": "恶意软件名称",
            "family": "家族",
            "type": "类型",
            "description": "描述"
        }}
    ],
    "apt_groups": [
        {{
            "name": "APT组织名称",
            "aliases": ["别名1", "别名2"],
            "origin": "国家/地区"
        }}
    ],
    "techniques": [
        {{
            "id": "T1566.001",
            "name": "技术名称",
            "tactic": "战术"
        }}
    ]
}}
"""
        
        try:
            response = self.generate_text(prompt, max_tokens=2048, temperature=0.1)
            logger.debug(f"LLM原始响应: {response}")
            
            # 清理响应 - 移除可能的markdown代码块标记
            cleaned_response = response.strip()
            if cleaned_response.startswith("```json"):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.startswith("```"):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith("```"):
                cleaned_response = cleaned_response[:-3]
            
            cleaned_response = cleaned_response.strip()
            
            # 如果响应为空，返回空字典
            if not cleaned_response:
                logger.warning("LLM返回空响应")
                return {}
            
            # 尝试解析JSON
            import json
            try:
                result = json.loads(cleaned_response)
                logger.info(f"成功解析实体: {len(result)} 个类型")
                return result
            except json.JSONDecodeError as json_error:
                logger.error(f"JSON解析失败: {json_error}")
                logger.error(f"清理后的响应: {cleaned_response[:200]}...")
                
                # 尝试修复常见的JSON问题
                fixed_response = self._fix_json_response(cleaned_response)
                if fixed_response:
                    try:
                        result = json.loads(fixed_response)
                        logger.info("JSON修复成功")
                        return result
                    except json.JSONDecodeError:
                        logger.error("JSON修复失败")
                
                # 如果JSON解析完全失败，尝试正则表达式提取
                return self._fallback_entity_extraction(text)
                
        except Exception as e:
            logger.error(f"高级威胁实体提取失败: {str(e)}")
            # 降级到正则表达式提取
            return self._fallback_entity_extraction(text)
    
    def _fix_json_response(self, response: str) -> Optional[str]:
        """尝试修复常见的JSON格式问题"""
        try:
            # 尝试找到JSON对象的开始和结束
            start_idx = response.find('{')
            end_idx = response.rfind('}')
            
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_part = response[start_idx:end_idx + 1]
                
                # 修复常见问题
                json_part = json_part.replace("'", '"')  # 单引号改双引号
                json_part = json_part.replace('，', ',')  # 中文逗号改英文
                json_part = json_part.replace('：', ':')  # 中文冒号改英文
                
                return json_part
            
            return None
            
        except Exception as e:
            logger.error(f"JSON修复过程出错: {str(e)}")
            return None
    
    def _fallback_entity_extraction(self, text: str) -> Dict[str, List[Dict[str, Any]]]:
        """降级的正则表达式实体提取"""
        import re
        
        entities = {
            "ioc": [],
            "cve": [],
            "malware": [],
            "apt_groups": [],
            "techniques": []
        }
        
        try:
            # IP地址
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for match in re.finditer(ip_pattern, text):
                entities["ioc"].append({
                    "value": match.group(),
                    "type": "ip",
                    "context": f"在位置{match.start()}-{match.end()}发现",
                    "confidence": 0.8
                })
            
            # 域名
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            for match in re.finditer(domain_pattern, text):
                domain = match.group()
                if '.' in domain and not domain.replace('.', '').isdigit():
                    entities["ioc"].append({
                        "value": domain,
                        "type": "domain",
                        "context": f"在位置{match.start()}-{match.end()}发现",
                        "confidence": 0.7
                    })
            
            # CVE
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            for match in re.finditer(cve_pattern, text, re.IGNORECASE):
                entities["cve"].append({
                    "value": match.group(),
                    "severity": "unknown",
                    "context": f"在位置{match.start()}-{match.end()}发现"
                })
            
            # APT组织
            apt_pattern = r'\b(?:APT|apt)[\s-]?\d+\b'
            for match in re.finditer(apt_pattern, text, re.IGNORECASE):
                entities["apt_groups"].append({
                    "name": match.group(),
                    "aliases": [],
                    "origin": "unknown"
                })
            
            # MITRE技术
            technique_pattern = r'T\d{4}(?:\.\d{3})?'
            for match in re.finditer(technique_pattern, text):
                entities["techniques"].append({
                    "id": match.group(),
                    "name": "unknown",
                    "tactic": "unknown"
                })
            
            # 恶意软件关键词
            malware_keywords = ['malware', 'trojan', 'virus', 'ransomware', 'backdoor', 'rootkit']
            for keyword in malware_keywords:
                if keyword.lower() in text.lower():
                    entities["malware"].append({
                        "name": keyword,
                        "family": "unknown",
                        "type": keyword,
                        "description": f"检测到关键词: {keyword}"
                    })
            
            logger.info(f"正则表达式提取完成: {sum(len(v) for v in entities.values())} 个实体")
            return entities
            
        except Exception as e:
            logger.error(f"正则表达式提取失败: {str(e)}")
            return entities
    
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